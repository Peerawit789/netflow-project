import os
import sys
import time
import threading
import ipaddress
import sqlite3
import json
import paramiko
from datetime import datetime
from fastapi import FastAPI, HTTPException, Header, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Automated Enforcement Response Service")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configs
SSH_KEY_PATH = os.environ.get("SSH_KEY_PATH", "/app/ssh/id_rsa")
FIREWALL_HOST = os.environ.get("FIREWALL_HOST", "firewall")
FIREWALL_PORT = int(os.environ.get("FIREWALL_PORT", 22))
API_KEY = os.environ.get("AUTO_RESPONSE_KEY", "super-secret-key-12345")
DB_PATH = os.environ.get("DB_PATH", "/app/data/blocks.db")
AUDIT_LOG_PATH = os.environ.get("AUDIT_LOG_PATH", "/logs/audit.log")

WHITELIST = {
    "192.168.42.1",
    "192.168.42.254",
    "192.168.42.20",
    "192.168.1.1",
    "8.8.8.8",
    "1.1.1.1",
    "127.0.0.1",
    "other"
}

class ActionRequest(BaseModel):
    src_ip: str
    ttl: int = 120

class UnblockRequest(BaseModel):
    src_ip: str

def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API Key"
        )
    return x_api_key

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS active_blocks (
            src_ip TEXT PRIMARY KEY,
            expiry_time REAL,
            blocked_at TEXT
        )
    """)
    conn.commit()
    conn.close()

def log_audit_action(action, ip, reason):
    os.makedirs(os.path.dirname(AUDIT_LOG_PATH), exist_ok=True)
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "action": action,
        "src_ip": ip,
        "reason": reason
    }
    try:
        with open(AUDIT_LOG_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        print(f"[!] Failed to write audit log: {e}")

def run_ssh_command(ip_to_block, action="block"):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    # Check if input is a valid IP or an interface name
    is_ip = True
    try:
        ipaddress.ip_address(ip_to_block)
    except ValueError:
        is_ip = False
        
    # Try connecting to the switch (192.168.42.254) first via password auth
    try:
        print(f"[*] Attempting SSH connection to switch 192.168.42.254 as root...")
        ssh.connect(
            hostname="192.168.42.254",
            port=22,
            username="root",
            password="1",
            timeout=3
        )
        
        # Build block/unblock commands for OpenvSwitch interface control
        cmd = ""
        if is_ip:
            if action == "block":
                # Find MAC -> Port -> Interface, then delete it. Fallback to drop flows.
                cmd = f"""
                IP="{ip_to_block}"
                MAC=$(ip neigh show "$IP" | awk '{{print $5}}')
                IFACE=""
                if [ ! -z "$MAC" ]; then
                    PORT_NUM=$(ovs-appctl fdb/show br0 2>/dev/null | grep -i "$MAC" | awk '{{print $1}}')
                    if [ ! -z "$PORT_NUM" ]; then
                        IFACE=$(ovs-ofctl show br0 2>/dev/null | grep "^ *${{PORT_NUM}}(" | cut -d'(' -f2 | cut -d')' -f1)
                    fi
                fi
                if [ ! -z "$IFACE" ]; then
                    echo "Deleting port $IFACE on switch for IP $IP"
                    ovs-vsctl del-port br0 "$IFACE" 2>/dev/null || true
                    mkdir -p /data && echo "$IP:$IFACE" >> /data/blocked_ips.txt
                else
                    echo "No interface found for IP $IP, using fallback drop rules"
                    iptables -A INPUT -s "$IP" -j DROP 2>/dev/null || true
                    ovs-ofctl add-flow br0 priority=40000,ip,nw_src="$IP",actions=drop 2>/dev/null || true
                    mkdir -p /data && echo "$IP:flow" >> /data/blocked_ips.txt
                fi
                """
            else:
                # Read prior resolution to restore interface, fallback to flow delete
                cmd = f"""
                IP="{ip_to_block}"
                RECORD=$(grep -w "^$IP" /data/blocked_ips.txt 2>/dev/null | tail -n 1)
                IFACE=$(echo "$RECORD" | cut -d':' -f2)
                if [ ! -z "$IFACE" ] && [ "$IFACE" != "flow" ]; then
                    echo "Adding port $IFACE back to switch"
                    ovs-vsctl add-port br0 "$IFACE" 2>/dev/null || true
                else
                    echo "Removing flow block for IP $IP"
                    iptables -D INPUT -s "$IP" -j DROP 2>/dev/null || true
                    ovs-ofctl del-flows br0 ip,nw_src="$IP" 2>/dev/null || true
                fi
                [ -f /data/blocked_ips.txt ] && (grep -v "^$IP" /data/blocked_ips.txt > /data/blocked_ips.tmp && mv /data/blocked_ips.tmp /data/blocked_ips.txt) || true
                """
        else:
            # Direct Interface Name Block/Unblock
            if action == "block":
                cmd = f"""
                IFACE="{ip_to_block}"
                echo "Deleting port $IFACE directly"
                ovs-vsctl del-port br0 "$IFACE" 2>/dev/null || true
                mkdir -p /data && echo "$IFACE:interface" >> /data/blocked_ips.txt
                """
            else:
                cmd = f"""
                IFACE="{ip_to_block}"
                echo "Adding port $IFACE back directly"
                ovs-vsctl add-port br0 "$IFACE" 2>/dev/null || true
                [ -f /data/blocked_ips.txt ] && (grep -v "^$IFACE" /data/blocked_ips.txt > /data/blocked_ips.tmp && mv /data/blocked_ips.tmp /data/blocked_ips.txt) || true
                """
                
        print(f"[*] Sending switch SSH Command script...")
        stdin, stdout, stderr = ssh.exec_command(cmd)
        exit_status = stdout.channel.recv_exit_status()
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()
        print(f"[*] Switch SSH Result: status={exit_status}, out='{out}', err='{err}'")
        return True, out, err
    except Exception as e:
        print(f"[~] Connection to switch 192.168.42.254 failed: {e}. Falling back to firewall container...")
        
        # Fallback to local firewall container (via key auth)
        if not os.path.exists(SSH_KEY_PATH):
            return False, "", f"Private SSH key file not found at {SSH_KEY_PATH}"
        try:
            private_key = paramiko.RSAKey.from_private_key_file(SSH_KEY_PATH)
            ssh.connect(
                hostname=FIREWALL_HOST,
                port=FIREWALL_PORT,
                username="enforcer",
                pkey=private_key,
                timeout=5
            )
            command = f"{action} {ip_to_block}"
            print(f"[*] Sending fallback SSH Command: {command}")
            stdin, stdout, stderr = ssh.exec_command(command)
            exit_status = stdout.channel.recv_exit_status()
            out = stdout.read().decode().strip()
            err = stderr.read().decode().strip()
            print(f"[*] Fallback SSH Result: status={exit_status}, out='{out}', err='{err}'")
            return exit_status == 0, out, err
        except Exception as ex:
            print(f"[!] Fallback SSH Command execution error: {ex}")
            return False, "", str(ex)
    finally:
        ssh.close()

def unblock_scheduler():
    print("[*] Starting TTL Expiry unblock scheduler background thread...")
    while True:
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            now = time.time()
            cursor.execute("SELECT src_ip FROM active_blocks WHERE expiry_time <= ?", (now,))
            rows = cursor.fetchall()
            for row in rows:
                ip = row[0]
                print(f"[*] Block expired for {ip}. Initiating unblock...")
                success, out, err = run_ssh_command(ip, "unblock")
                if success:
                    cursor.execute("DELETE FROM active_blocks WHERE src_ip = ?", (ip,))
                    conn.commit()
                    log_audit_action("unblock", ip, "TTL Expiry achieved")
                    print(f"[✓] Automatically unblocked {ip} on SSH target.")
                else:
                    print(f"[✗] Failed to automatically unblock {ip}: {err}")
            conn.close()
        except Exception as e:
            print(f"[!] Error in TTL scheduler loop: {e}")
            
        time.sleep(5)

@app.on_event("startup")
def startup_event():
    init_db()
    t = threading.Thread(target=unblock_scheduler, daemon=True)
    t.start()

@app.post("/action")
def enforce_block(req: ActionRequest, api_key: str = Depends(verify_api_key)):
    # 1. Strictly validate IP or interface formatting
    is_ip = False
    try:
        ip = ipaddress.ip_address(req.src_ip)
        src_ip_str = str(ip)
        is_ip = True
    except ValueError:
        import re
        if re.match(r"^[a-zA-Z0-9\.\-_]+$", req.src_ip):
            src_ip_str = req.src_ip
        else:
            raise HTTPException(status_code=400, detail="Invalid source IP address or interface format")
    
    # 2. Whitelist containment check
    if src_ip_str in WHITELIST:
        raise HTTPException(
            status_code=400,
            detail="Target IP is protected under critical infrastructure whitelist"
        )
        
    # 3. Call SSH to block target
    success, out, err = run_ssh_command(src_ip_str, "block")
    if not success:
        raise HTTPException(
            status_code=500,
            detail=f"SSH Firewall Enforcement failed: {err}"
        )
        
    # 4. Record block status to DB for expiry tracking
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        expiry_time = time.time() + req.ttl
        cursor.execute(
            "INSERT OR REPLACE INTO active_blocks (src_ip, expiry_time, blocked_at) VALUES (?, ?, ?)",
            (src_ip_str, expiry_time, datetime.utcnow().isoformat() + "Z")
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[!] Failed to insert block in db: {e}")
        
    # 5. Log action in audit log
    log_audit_action("block", src_ip_str, f"Requested with TTL {req.ttl}s")
    
    return {
        "status": "enforced",
        "action": "block",
        "target": src_ip_str,
        "ttl": req.ttl,
        "ssh_output": out
    }

@app.get("/blocks")
def get_active_blocks():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT src_ip, expiry_time, blocked_at FROM active_blocks")
        rows = cursor.fetchall()
        conn.close()
        
        blocks = []
        for r in rows:
            blocks.append({
                "src_ip": r[0],
                "time_remaining_seconds": max(0, int(r[1] - time.time())),
                "blocked_at": r[2]
            })
        return blocks
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/unblock")
def enforce_unblock(req: UnblockRequest, api_key: str = Depends(verify_api_key)):
    # 1. Strictly validate IP or interface formatting
    is_ip = False
    try:
        ip = ipaddress.ip_address(req.src_ip)
        src_ip_str = str(ip)
        is_ip = True
    except ValueError:
        import re
        if re.match(r"^[a-zA-Z0-9\.\-_]+$", req.src_ip):
            src_ip_str = req.src_ip
        else:
            raise HTTPException(status_code=400, detail="Invalid source IP address or interface format")
    
    # Call SSH to unblock target
    success, out, err = run_ssh_command(src_ip_str, "unblock")
    if not success:
        raise HTTPException(
            status_code=500,
            detail=f"SSH Firewall Unenforcement failed: {err}"
        )
        
    # Remove from DB
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM active_blocks WHERE src_ip = ?", (src_ip_str,))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[!] Failed to delete block in db: {e}")
        
    log_audit_action("unblock", src_ip_str, "Manual unblock action triggered by operator")
    
    return {
        "status": "unenforced",
        "action": "unblock",
        "target": src_ip_str,
        "ssh_output": out
    }

