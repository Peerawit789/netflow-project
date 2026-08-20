import os
import sys
import time
import requests
import json
from datetime import datetime
from fastapi import FastAPI, HTTPException, Request, Header, Depends, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

class ManualActionRequest(BaseModel):
    action: str
    src_ip: str
    ttl: int = 120

from fastapi.middleware.cors import CORSMiddleware
import paramiko

app = FastAPI(title="Policy Engine Decision Maker")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def check_switch_connection():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(
            hostname="192.168.42.254",
            port=22,
            username="root",
            password="1",
            timeout=2
        )
        ssh.close()
        return True
    except Exception:
        return False

# Configs
PROMETHEUS_URL = os.environ.get("PROMETHEUS_URL", "http://prometheus:9090")
LLM_MIDDLEWARE_URL = os.environ.get("LLM_MIDDLEWARE_URL", "http://llm-middleware:8003")
AUTO_RESPONSE_URL = os.environ.get("AUTO_RESPONSE_URL", "http://auto-response:8004")
AUTO_RESPONSE_KEY = os.environ.get("AUTO_RESPONSE_KEY", "super-secret-key-12345")
AUDIT_LOG_PATH = os.environ.get("AUDIT_LOG_PATH", "/logs/audit.log")

# Critical Whitelist
WHITELIST = {
    "192.168.42.1",    # Gateway
    "192.168.42.254",  # NetFlow Exporter
    "192.168.42.20",   # NetFlow Collector / Docker host
    "192.168.1.1",     # Router
    "8.8.8.8",         # DNS
    "1.1.1.1",         # DNS
    "127.0.0.1",       # Localhost
    "other",           # Other bucket
}

# Rate Limiter state: timestamps of blocks in the last 5 minutes
block_timestamps = []

def is_rate_limited():
    global block_timestamps
    now = time.time()
    block_timestamps = [t for t in block_timestamps if now - t < 300]
    return len(block_timestamps) >= 3

def record_block():
    global block_timestamps
    now = time.time()
    block_timestamps.append(now)


def check_rule_agreement(src_ip, dst_ip):
    # Query Prometheus for packets over a 5m window to handle timing differences
    url = f"{PROMETHEUS_URL}/api/v1/query"
    query = f'max_over_time(netflow_packets{{src="{src_ip}",dst="{dst_ip}"}}[5m])'
    try:
        r = requests.get(url, params={"query": query}, timeout=3)
        if r.status_code == 200:
            res = r.json().get("data", {}).get("result", [])
            if res:
                packets = float(res[0]["value"][1])
                print(f"[*] Rule check for {src_ip}->{dst_ip}: packets={packets} (max in 5m)")
                # Threshold check: requires at least 50 packets per window
                return packets >= 50
    except Exception as e:
        print(f"[!] Error checking Prometheus rule agreement: {e}")
    return False

def get_flow_context(src_ip, dst_ip):
    # Get max bytes and packets in 5m for explanation context
    url = f"{PROMETHEUS_URL}/api/v1/query"
    context = {"bytes": 0, "packets": 0}
    try:
        r = requests.get(url, params={"query": f'max_over_time(netflow_bytes{{src="{src_ip}",dst="{dst_ip}"}}[5m])'}, timeout=2)
        if r.status_code == 200:
            res = r.json().get("data", {}).get("result", [])
            if res:
                context["bytes"] = int(float(res[0]["value"][1]))
        r = requests.get(url, params={"query": f'max_over_time(netflow_packets{{src="{src_ip}",dst="{dst_ip}"}}[5m])'}, timeout=2)
        if r.status_code == 200:
            res = r.json().get("data", {}).get("result", [])
            if res:
                context["packets"] = int(float(res[0]["value"][1]))
    except Exception as e:
        print(f"[!] Error fetching context: {e}")
    return context

def log_audit(entry):
    os.makedirs(os.path.dirname(AUDIT_LOG_PATH), exist_ok=True)
    try:
        with open(AUDIT_LOG_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        print(f"[!] Failed to write audit log: {e}")

@app.post("/alert")
async def handle_alert(request: Request):
    payload = await request.json()
    print(f"[*] Received Alertmanager payload: {json.dumps(payload)}")
    
    alerts = payload.get("alerts", [])
    decisions = []
    
    for alert in alerts:
        # We only process firing alerts
        if alert.get("status") != "firing":
            continue
            
        labels = alert.get("labels", {})
        src_ip = labels.get("src")
        dst_ip = labels.get("dst")
        pattern = labels.get("pattern", "unknown")
        
        if not src_ip or not dst_ip:
            continue
            
        print(f"[*] Processing alert for flow {src_ip} -> {dst_ip} ({pattern})")
        
        decision = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "pattern": pattern,
            "ml_score": 0.0,
            "decision": "allow",
            "reason": "",
            "ttl": 0,
            "llm_explanation": None
        }
        
        # Get ML Score from description annotations or range metric query
        try:
            url = f"{PROMETHEUS_URL}/api/v1/query"
            r = requests.get(url, params={"query": f'max_over_time(netflow_anomaly_score{{src="{src_ip}",dst="{dst_ip}"}}[5m])'}, timeout=2)
            if r.status_code == 200:
                res = r.json().get("data", {}).get("result", [])
                if res:
                    decision["ml_score"] = float(res[0]["value"][1])
        except Exception:
            pass
            
        # 1. Hard Rule: Whitelist Validation
        if src_ip in WHITELIST:
            decision["decision"] = "allow"
            decision["reason"] = "IP is whitelisted (critical infrastructure / safe zone)"
            print(f"[SAFE-ZONE] Allow decision: {src_ip} is in whitelist.")
            
        else:
            # 2. Hard Rule: Rule-based Signal Agreement
            rule_agreed = check_rule_agreement(src_ip, dst_ip)
            if not rule_agreed:
                decision["decision"] = "allow"
                decision["reason"] = "Rule-based signal agreement failed (threshold packets < 50)"
                print(f"[POLICY] Allow decision: Rule agreement failed for {src_ip}.")
                
            else:
                # 3. Hard Rule: Rate Limiting
                if is_rate_limited():
                    decision["decision"] = "escalate_to_human"
                    decision["reason"] = "Rate limit exceeded (max 3 blocks per 5m)"
                    print(f"[RATE-LIMIT] Escalate decision: Block limit reached.")
                    
                else:
                    # Whitelist passed, rule agreement met, rate limit ok -> check ML score confidence
                    if decision["ml_score"] < 0.8:
                        decision["decision"] = "escalate_to_human"
                        decision["reason"] = f"Borderline ML confidence score ({decision['ml_score']:.3f}) requires human override"
                        print(f"[POLICY ESCALATE] Escalate decision: Borderline ML score {decision['ml_score']:.3f} on {src_ip}.")
                    else:
                        # "if can connect dont auto down": check switch connectivity
                        if check_switch_connection():
                            decision["decision"] = "escalate_to_human"
                            decision["reason"] = f"Reachable switch 192.168.42.254 detected; automatic down/blocking disabled. Manual approval required."
                            print(f"[POLICY ESCALATE] Escalate decision: Switch is reachable, automatic down disabled for {src_ip}.")
                        else:
                            decision["decision"] = "block"
                            decision["reason"] = f"ML score ({decision['ml_score']:.3f}) and rule threshold (>50 packets) both firing"
                            decision["ttl"] = 120  # Block for 2 minutes
                            record_block()
                            print(f"[POLICY BLOCK] Block decision: Enforcing 120s TTL block on {src_ip}.")
                    
        # 4. Fetch flow context details for LLM
        flow_ctx = get_flow_context(src_ip, dst_ip)
        
        # 5. Call LLM Middleware to generate explanation
        llm_payload = {
            "decision": decision["decision"],
            "reason": decision["reason"],
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "pattern": pattern,
            "ml_score": decision["ml_score"],
            "packets": flow_ctx["packets"],
            "bytes": flow_ctx["bytes"],
            "ttl": decision["ttl"]
        }
        
        try:
            r = requests.post(f"{LLM_MIDDLEWARE_URL}/explain", json=llm_payload, timeout=10)
            if r.status_code == 200:
                decision["llm_explanation"] = r.json()
            else:
                decision["llm_explanation"] = {"summary": "Failed to generate LLM explanation", "evidence": [], "confidence_commentary": "Error code from LLM service"}
        except Exception as e:
            decision["llm_explanation"] = {"summary": "LLM Middleware unreachable", "evidence": [], "confidence_commentary": str(e)}
            
        # 6. Call Auto-Response service if decision is block
        if decision["decision"] == "block":
            try:
                headers = {"X-API-Key": AUTO_RESPONSE_KEY}
                ar_payload = {"src_ip": src_ip, "ttl": decision["ttl"]}
                r = requests.post(f"{AUTO_RESPONSE_URL}/action", json=ar_payload, headers=headers, timeout=5)
                if r.status_code == 200:
                    print(f"[*] Block successfully executed for {src_ip}")
                else:
                    print(f"[!] Failed to execute block: {r.text}")
                    decision["reason"] += " (Block enforcement failed)"
            except Exception as e:
                print(f"[!] Auto-response unreachable: {e}")
                decision["reason"] += f" (Enforcement service error: {e})"
                
        # 7. Audit log the final decision
        log_audit(decision)
        decisions.append(decision)
        
    return {"status": "processed", "decisions": decisions}

@app.post("/manual-action")
def handle_manual_action(req: ManualActionRequest):
    headers = {"X-API-Key": AUTO_RESPONSE_KEY}
    
    if req.action == "block":
        ar_payload = {"src_ip": req.src_ip, "ttl": req.ttl}
        try:
            r = requests.post(f"{AUTO_RESPONSE_URL}/action", json=ar_payload, headers=headers, timeout=5)
            if r.status_code == 200:
                log_audit({
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "src_ip": req.src_ip,
                    "dst_ip": "manual",
                    "pattern": "manual_override",
                    "ml_score": 1.0,
                    "decision": "block",
                    "reason": "Manual block action triggered by human operator from Grafana Console",
                    "ttl": req.ttl,
                    "llm_explanation": {
                        "summary": f"Manual override: Blocked source IP {req.src_ip}.",
                        "evidence": ["Triggered by human operator."],
                        "confidence_commentary": "Operator override."
                    }
                })
                return r.json()
            else:
                try:
                    detail = r.json().get("detail", r.text)
                except Exception:
                    detail = r.text
                raise HTTPException(status_code=r.status_code, detail=detail)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
            
    elif req.action == "unblock":
        ar_payload = {"src_ip": req.src_ip}
        try:
            r = requests.post(f"{AUTO_RESPONSE_URL}/unblock", json=ar_payload, headers=headers, timeout=5)
            if r.status_code == 200:
                log_audit({
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "src_ip": req.src_ip,
                    "dst_ip": "manual",
                    "pattern": "manual_override",
                    "ml_score": 0.0,
                    "decision": "allow",
                    "reason": "Manual unblock action triggered by human operator from Grafana Console",
                    "ttl": 0,
                    "llm_explanation": {
                        "summary": f"Manual override: Unblocked source IP {req.src_ip}.",
                        "evidence": ["Triggered by human operator."],
                        "confidence_commentary": "Operator override."
                    }
                })
                return r.json()
            else:
                try:
                    detail = r.json().get("detail", r.text)
                except Exception:
                    detail = r.text
                raise HTTPException(status_code=r.status_code, detail=detail)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="Invalid action")

@app.get("/decisions")
def get_decisions():
    # Read the audit log and return it
    if not os.path.exists(AUDIT_LOG_PATH):
        return []
    decisions = []
    try:
        with open(AUDIT_LOG_PATH, "r", errors="ignore") as f:
            for line in f:
                cleaned_line = line.replace("\x00", "").strip()
                if cleaned_line:
                    try:
                        decisions.append(json.loads(cleaned_line))
                    except json.JSONDecodeError as jde:
                        print(f"[!] Warning: Skipped malformed audit log entry due to JSON error: {jde}")
                        continue
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    # Return last 50 decisions
    return decisions[-50:]

@app.get("/status", response_class=HTMLResponse)
def get_status_html():
    decisions = get_decisions()
    
    cards_html = ""
    for d in reversed(decisions):
        # We only display evaluation records that have src/dst IPs and decision
        if "src_ip" not in d or "decision" not in d:
            continue
            
        severity_class = "severity-allow"
        badge_text = "ALLOWED"
        if d["decision"] == "block":
            severity_class = "severity-block"
            badge_text = f"BLOCKED (TTL {d['ttl']}s)"
        elif d["decision"] == "escalate_to_human":
            severity_class = "severity-escalate"
            badge_text = "ESCALATED TO HUMAN"
            
        llm = d.get("llm_explanation") or {}
        summary = llm.get("summary", "No explanation available.")
        evidence_list = "".join(f"<li>{ev}</li>" for ev in llm.get("evidence", []))
        commentary = llm.get("confidence_commentary", "")
        
        cards_html += f"""
        <div class="incident-card {severity_class}">
            <div class="incident-header">
                <div>
                    <span class="badge badge-{d['decision']}">{badge_text}</span>
                    <strong style="margin-left: 10px; font-size: 1.1em; color: #fff;">{d['src_ip']} &rarr; {d['dst_ip']}</strong>
                </div>
                <div class="timestamp">{d['timestamp']}</div>
            </div>
            <div class="incident-body">
                <p><strong>ML Score:</strong> <code style="color: #ffb86c;">{d.get('ml_score', 0.0):.3f}</code> | <strong>Traffic Pattern:</strong> <code>{d.get('pattern', 'unknown')}</code></p>
                <p><strong>Justification:</strong> {d.get('reason', '')}</p>
                
                <div class="llm-section">
                    <div class="llm-header">🤖 AI Security Analyst Report</div>
                    <div class="llm-content">
                        <p class="summary-text"><strong>Analysis Summary:</strong> {summary}</p>
                        {f'<ul class="evidence-list">{evidence_list}</ul>' if evidence_list else ''}
                        {f'<p class="commentary-text"><strong>Confidence Commentary:</strong> <em>{commentary}</em></p>' if commentary else ''}
                    </div>
                </div>
            </div>
        </div>
        """
        
    if not cards_html:
        cards_html = "<div class='no-incidents'>No decisions recorded yet. System monitoring normal traffic.</div>"
        
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>DDoS Response Incident Console</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap" rel="stylesheet">
        <style>
            body {{
                font-family: 'Inter', sans-serif;
                background-color: #1a1c23;
                color: #e2e8f0;
                margin: 0;
                padding: 20px;
            }}
            .container {{
                max-width: 900px;
                margin: 0 auto;
            }}
            h1 {{
                font-weight: 700;
                color: #f7fafc;
                margin-bottom: 5px;
                display: flex;
                align-items: center;
                gap: 10px;
            }}
            h1 .icon {{
                color: #e53e3e;
            }}
            .subtitle {{
                color: #a0aec0;
                margin-top: 0;
                margin-bottom: 30px;
                font-size: 0.95em;
            }}
            .incident-card {{
                background-color: #2d3748;
                border-radius: 8px;
                margin-bottom: 20px;
                border-left: 5px solid #a0aec0;
                overflow: hidden;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                transition: transform 0.2s;
            }}
            .incident-card:hover {{
                transform: translateY(-2px);
            }}
            .severity-allow {{
                border-left-color: #48bb78;
            }}
            .severity-block {{
                border-left-color: #e53e3e;
                background: linear-gradient(135deg, #2d3748 0%, #3f2022 100%);
            }}
            .severity-escalate {{
                border-left-color: #ecc94b;
            }}
            .incident-header {{
                background-color: rgba(0,0,0,0.15);
                padding: 12px 20px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                border-bottom: 1px solid rgba(255,255,255,0.05);
            }}
            .timestamp {{
                font-size: 0.8em;
                color: #a0aec0;
            }}
            .badge {{
                display: inline-block;
                padding: 3px 8px;
                border-radius: 4px;
                font-size: 0.75em;
                font-weight: 600;
                text-transform: uppercase;
            }}
            .badge-allow {{
                background-color: #48bb78;
                color: #fff;
            }}
            .badge-block {{
                background-color: #e53e3e;
                color: #fff;
                animation: pulse 2s infinite;
            }}
            .badge-escalate_to_human {{
                background-color: #ecc94b;
                color: #1a1c23;
            }}
            .incident-body {{
                padding: 20px;
            }}
            .incident-body p {{
                margin: 8px 0;
            }}
            code {{
                background-color: rgba(0,0,0,0.3);
                padding: 2px 6px;
                border-radius: 4px;
                font-family: monospace;
                font-size: 0.9em;
            }}
            .llm-section {{
                margin-top: 15px;
                background-color: rgba(0,0,0,0.2);
                border-radius: 6px;
                border: 1px solid rgba(255,255,255,0.05);
            }}
            .llm-header {{
                padding: 10px 15px;
                font-size: 0.85em;
                font-weight: 600;
                color: #90cdf4;
                border-bottom: 1px solid rgba(255,255,255,0.05);
            }}
            .llm-content {{
                padding: 15px;
                font-size: 0.9em;
            }}
            .summary-text {{
                margin-top: 0 !important;
                color: #e2e8f0;
            }}
            .evidence-list {{
                margin: 10px 0;
                padding-left: 20px;
                color: #cbd5e0;
            }}
            .evidence-list li {{
                margin: 4px 0;
            }}
            .commentary-text {{
                font-size: 0.95em;
                color: #a0aec0;
                border-top: 1px solid rgba(255,255,255,0.05);
                padding-top: 10px;
                margin-bottom: 0 !important;
            }}
            .no-incidents {{
                text-align: center;
                padding: 40px;
                background-color: #2d3748;
                border-radius: 8px;
                color: #a0aec0;
                font-size: 1.1em;
            }}
            @keyframes pulse {{
                0% {{ opacity: 1; }}
                50% {{ opacity: 0.8; }}
                100% {{ opacity: 1; }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1><span class="icon">🛡️</span> NetFlow DDoS Enforcement Response Console</h1>
            <p class="subtitle">Real-time threat evaluation timeline: Gated deterministic policies and LLM Middleware analysis.</p>
            
            <!-- Manual Threat Response Console -->
            <div style="background-color: #2d3748; padding: 20px; border-radius: 8px; margin-bottom: 30px; border: 1px solid rgba(255,255,255,0.05); box-shadow: 0 4px 6px rgba(0,0,0,0.15);">
                <h3 style="margin-top: 0; color: #90cdf4; font-weight: 600; font-size: 1.1em; display: flex; align-items: center; gap: 8px;">🎮 Interactive Enforcement Override</h3>
                <p style="font-size: 0.85em; color: #a0aec0; margin-top: 5px; margin-bottom: 15px;">Manually block or unblock network traffic source IPs directly on the OpenvSwitch router (192.168.42.254).</p>
                <div style="display: flex; gap: 10px; flex-wrap: wrap; align-items: center;">
                    <input type="text" id="target_ip" placeholder="Target IP (e.g. 172.66.152.176)" style="background-color: #1a1c23; border: 1px solid rgba(255,255,255,0.1); border-radius: 4px; padding: 8px 12px; color: #fff; flex: 1; min-width: 200px; font-family: monospace; font-size: 0.95em;" />
                    <button onclick="sendAction('block')" style="background-color: #e53e3e; color: #fff; border: none; padding: 8px 16px; border-radius: 4px; font-weight: 600; cursor: pointer; transition: background-color 0.2s;">🛑 Block IP (120s TTL)</button>
                    <button onclick="sendAction('unblock')" style="background-color: #48bb78; color: #fff; border: none; padding: 8px 16px; border-radius: 4px; font-weight: 600; cursor: pointer; transition: background-color 0.2s;">✅ No Block (Unblock)</button>
                </div>
                <div id="response_message" style="margin-top: 12px; font-size: 0.9em; font-family: monospace; padding: 10px; border-radius: 4px; display: none;"></div>
            </div>

            <script>
                async function sendAction(action) {{
                    const ip = document.getElementById('target_ip').value.trim();
                    const msgDiv = document.getElementById('response_message');
                    if (!ip) {{
                        msgDiv.style.display = 'block';
                        msgDiv.style.backgroundColor = 'rgba(229, 62, 62, 0.15)';
                        msgDiv.style.color = '#feb2b2';
                        msgDiv.innerText = 'Error: Please specify a valid IP address.';
                        return;
                    }}
                    
                    msgDiv.style.display = 'block';
                    msgDiv.style.backgroundColor = 'rgba(255,255,255,0.05)';
                    msgDiv.style.color = '#a0aec0';
                    msgDiv.innerText = 'Sending manual ' + action + ' command for IP ' + ip + '...';
                    
                    try {{
                        const response = await fetch('/manual-action', {{
                            method: 'POST',
                            headers: {{
                                'Content-Type': 'application/json'
                            }},
                            body: JSON.stringify({{ action: action, src_ip: ip, ttl: 120 }})
                        }});
                        
                        const result = await response.json();
                        if (response.ok) {{
                            msgDiv.style.backgroundColor = 'rgba(72, 187, 120, 0.15)';
                            msgDiv.style.color = '#9ae6b4';
                            msgDiv.innerText = 'Success: Manual ' + action + ' command completed successfully.\nResult: ' + JSON.stringify(result.ssh_output || result.status);
                            setTimeout(() => {{ window.location.reload(); }}, 2500);
                        }} else {{
                            msgDiv.style.backgroundColor = 'rgba(229, 62, 62, 0.15)';
                            msgDiv.style.color = '#feb2b2';
                            msgDiv.innerText = 'Error: ' + (result.detail || 'Failed to execute command.');
                        }}
                    }} catch (err) {{
                        msgDiv.style.backgroundColor = 'rgba(229, 62, 62, 0.15)';
                        msgDiv.style.color = '#feb2b2';
                        msgDiv.innerText = 'Connection error: ' + err.message;
                    }}
                }}
            </script>

            {cards_html}
        </div>
    </body>
    </html>
    """
    return html_content
