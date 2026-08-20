import os
import sys
import time
import glob
import subprocess
from collections import defaultdict
from prometheus_client import start_http_server, Gauge

# Prom metrics definitions
netflow_bytes = Gauge('netflow_bytes', 'Total bytes transferred in the last window', ['src', 'dst', 'proto'])
netflow_packets = Gauge('netflow_packets', 'Total packets transferred in the last window', ['src', 'dst', 'proto'])
netflow_pps = Gauge('netflow_pps', 'Average packets per second per source in the last window', ['src'])

DATA_DIR = os.environ.get("DATA_DIR", "/data")
CHECK_INTERVAL = int(os.environ.get("CHECK_INTERVAL", 10))
TOP_N = int(os.environ.get("TOP_N", 50))

def get_latest_nfcapd_file(data_dir):
    # Search for files starting with nfcapd.20
    files = glob.glob(os.path.join(data_dir, "nfcapd.20*"))
    # Exclude temporary or active capture files
    files = [f for f in files if not f.endswith(".current") and not f.endswith(".tmp") and not os.path.isdir(f)]
    if not files:
        return None
    # Sort by modification time so timezone differences in filenames don't block new files
    files.sort(key=os.path.getmtime)
    return files[-1]

def parse_duration_to_seconds(td_str):
    try:
        parts = td_str.split(":")
        if len(parts) == 3:
            h = float(parts[0])
            m = float(parts[1])
            s = float(parts[2])
            return h * 3600 + m * 60 + s
        else:
            return float(td_str)
    except Exception:
        return 0.0

def run_nfdump(file_path):
    # Use version-stable format layout
    cmd = ["nfdump", "-r", file_path, "-o", "fmt:%ts,%td,%sa,%da,%sp,%dp,%pr,%pkt,%byt"]
    print(f"[*] Running command: {' '.join(cmd)}")
    
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if res.returncode != 0:
        print(f"[!] Error running nfdump: {res.stderr}")
        return []
    
    flows = []
    lines = res.stdout.splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        # Skip nfdump output formatting lines
        if (line.startswith("Date first seen") or 
            line.startswith("Summary:") or 
            line.startswith("Time window:") or 
            line.startswith("Total records") or 
            line.startswith("Sys:")):
            continue
            
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 9:
            continue
            
        try:
            flows.append({
                "ts": parts[0],
                "td": parts[1],
                "sa": parts[2],
                "da": parts[3],
                "sp": parts[4],
                "dp": parts[5],
                "pr": parts[6].upper().strip(),
                "pkt": int(parts[7]),
                "byt": int(parts[8])
            })
        except ValueError as e:
            # Skip invalid lines
            continue
    return flows

def process_file(file_path):
    print(f"[*] Processing rotated NetFlow file: {file_path}")
    flows = run_nfdump(file_path)
    if not flows:
        print("[*] No flows parsed from the file.")
        return
        
    print(f"[*] Parsed {len(flows)} flows from file.")
    
    # 1. Aggregate flows per (src_ip, dst_ip, proto)
    flow_agg = defaultdict(lambda: {"packets": 0, "bytes": 0, "duration": 0.0})
    # Also track packets per source for PPS
    src_packets = defaultdict(int)
    
    for f in flows:
        key = (f["sa"], f["da"], f["pr"])
        flow_agg[key]["packets"] += f["pkt"]
        flow_agg[key]["bytes"] += f["byt"]
        flow_agg[key]["duration"] += parse_duration_to_seconds(f["td"])
        
        src_packets[f["sa"]] += f["pkt"]
        
    # 2. Apply Cardinality Control (Top-N by bytes)
    sorted_flow_keys = sorted(flow_agg.keys(), key=lambda k: flow_agg[k]["bytes"], reverse=True)
    top_keys = sorted_flow_keys[:TOP_N]
    other_keys = sorted_flow_keys[TOP_N:]
    
    # Clear previous metrics to prevent stale IPs from persisting
    netflow_bytes.clear()
    netflow_packets.clear()
    netflow_pps.clear()
    
    # Populate top talkers
    for key in top_keys:
        sa, da, pr = key
        netflow_bytes.labels(src=sa, dst=da, proto=pr).set(flow_agg[key]["bytes"])
        netflow_packets.labels(src=sa, dst=da, proto=pr).set(flow_agg[key]["packets"])
        
    # Aggregate remaining flows into "other"
    if other_keys:
        other_bytes = sum(flow_agg[k]["bytes"] for k in other_keys)
        other_packets = sum(flow_agg[k]["packets"] for k in other_keys)
        netflow_bytes.labels(src="other", dst="other", proto="other").set(other_bytes)
        netflow_packets.labels(src="other", dst="other", proto="other").set(other_packets)
        
    # 3. Calculate PPS per Source (Assuming 60 seconds rotation interval)
    # PPS = total packets / interval
    INTERVAL = 60.0
    
    # Apply Cardinality control for source IPs too
    sorted_src_keys = sorted(src_packets.keys(), key=lambda k: src_packets[k], reverse=True)
    top_srcs = sorted_src_keys[:TOP_N]
    other_srcs = sorted_src_keys[TOP_N:]
    
    for src in top_srcs:
        pps = src_packets[src] / INTERVAL
        netflow_pps.labels(src=src).set(pps)
        
    if other_srcs:
        other_src_packets = sum(src_packets[src] for src in other_srcs)
        other_pps = other_src_packets / INTERVAL
        netflow_pps.labels(src="other").set(other_pps)
        
    print("[*] Prometheus metrics updated successfully.")

def main():
    print("[*] Starting Matrix Builder metrics exporter on port 8000")
    start_http_server(8000)
    
    last_processed = None
    
    while True:
        try:
            latest = get_latest_nfcapd_file(DATA_DIR)
            if latest and latest != last_processed:
                process_file(latest)
                last_processed = latest
            elif not latest:
                print(f"[~] Waiting for NetFlow rotated files in {DATA_DIR}...")
        except Exception as e:
            print(f"[!] Error in main loop: {e}")
            
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()
