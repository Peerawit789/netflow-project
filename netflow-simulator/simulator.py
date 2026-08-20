import os
import sys
import time
import socket
import struct
import re
from datetime import datetime

# Server target configuration
COLLECTOR_HOST = os.environ.get("COLLECTOR_HOST", "netflow-collector")
COLLECTOR_PORT = int(os.environ.get("COLLECTOR_PORT", 2055))
FLOWS_FILE = os.environ.get("FLOWS_FILE", "/data/test.txt")

def parse_bytes(val_str):
    val_str = val_str.strip()
    if not val_str:
        return 0
    # Handle metric suffixes if any
    if val_str.endswith('M'):
        return int(float(val_str[:-1].strip()) * 1000000)
    if val_str.endswith('G'):
        return int(float(val_str[:-1].strip()) * 1000000000)
    if val_str.endswith('K'):
        return int(float(val_str[:-1].strip()) * 1000)
    try:
        return int(float(val_str))
    except ValueError:
        return 0

def parse_line(line):
    # Regex to match: YYYY-MM-DD HH:MM:SS.mmm <evt> <xevt> PROTO SRC_IP:PORT -> DST_IP:PORT ... IN_BYTE OUT_BYTE
    # Example: 2026-06-25 12:02:38.539 <no-evt> <no-evt> UDP      192.168.42.20:60885 ->    192.168.154.1:53 ... 88 0
    parts = line.strip().split()
    if len(parts) < 10:
        return None
    
    # Check if first part looks like date
    if not re.match(r"\d{4}-\d{2}-\d{2}", parts[0]):
        return None

    try:
        ts_str = f"{parts[0]} {parts[1]}"
        ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S.%f")
        proto = parts[4].upper()
        
        # Parse Src IP & Port
        src_ap = parts[5].rsplit(":", 1)
        src_ip = src_ap[0]
        src_port = int(src_ap[1]) if len(src_ap) > 1 else 0
        
        # Arrow is parts[6]
        # Parse Dst IP & Port
        dst_ap = parts[7].rsplit(":", 1)
        dst_ip = dst_ap[0]
        dst_port = int(dst_ap[1]) if len(dst_ap) > 1 else 0
        
        # Bytes is the second-to-last or last non-zero field
        # The line structure ends with: X-Src -> X-Dst IN_BYTE OUT_BYTE
        # Let's count back: IN_BYTE is parts[-2], OUT_BYTE is parts[-1]
        bytes_val = parse_bytes(parts[-2])
        
        # Calculate packets roughly based on bytes (default 1, max MTU packet size)
        packets_val = max(1, bytes_val // 1300 + 1)
        
        # Protocol map
        if proto == "TCP":
            proto_num = 6
        elif proto == "UDP":
            proto_num = 17
        elif proto == "ICMP":
            proto_num = 1
        else:
            proto_num = 0
            
        return {
            "time": ts,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "proto": proto_num,
            "bytes": bytes_val,
            "packets": packets_val
        }
    except Exception as e:
        # Silently skip malformed lines
        return None

def pack_netflow_v5(uptime_ms, unix_secs, unix_nsecs, seq_num, flows):
    # Header format: !HHIIIBBH
    # - version (5)
    # - count (len(flows))
    # - sys_uptime (uptime_ms)
    # - unix_secs (unix_secs)
    # - unix_nsecs (unix_nsecs)
    # - flow_sequence (seq_num)
    # - engine_type (1)
    # - engine_id (1)
    # - sampling_interval (0)
    header = struct.pack(
        "!HHIIIIBBH",
        5,
        len(flows),
        uptime_ms,
        unix_secs,
        unix_nsecs,
        seq_num,
        1,
        1,
        0
    )
    
    payload = bytearray(header)
    for flow in flows:
        try:
            src_addr = socket.inet_aton(flow["src_ip"])
            dst_addr = socket.inet_aton(flow["dst_ip"])
        except OSError:
            # Skip invalid IP addresses
            continue
            
        # Record format: !4s4s4sHHIIIIHHBBBBBHHBB
        # srcaddr (4s), dstaddr (4s), nexthop (4s, 0.0.0.0), input (H, 1), output (H, 2),
        # dPkts (I), dOctets (I), first (I), last (I), srcport (H), dstport (H),
        # pad1 (B, 0), tcp_flags (B, 0), prot (B), tos (B, 0), src_as (H, 0), dst_as (H, 0),
        # src_mask (B, 24), dst_mask (B, 24), pad2 (H, 0)
        # Note: 4s4s4s is packed as raw bytes
        
        # Use simple flow durations: first seen uptime to last seen uptime
        first_uptime = max(0, uptime_ms - 100)
        last_uptime = uptime_ms
        
        record = struct.pack(
            "!4s4s4sHHIIIIHHBBBBHHBBH",
            src_addr,
            dst_addr,
            b"\x00\x00\x00\x00",  # nexthop
            1,                   # input interface
            2,                   # output interface
            flow["packets"],
            flow["bytes"],
            first_uptime,
            last_uptime,
            flow["src_port"],
            flow["dst_port"],
            0,                   # pad1
            0x02 if flow["proto"] == 6 else 0, # tcp flags (SYN if TCP)
            flow["proto"],
            0,                   # tos
            0,                   # src_as
            0,                   # dst_as
            24,                  # src_mask
            24,                  # dst_mask
            0                    # pad2
        )
        payload.extend(record)
        
    return bytes(payload)

def main():
    print(f"[*] Starting NetFlow V5 Simulator, sending to {COLLECTOR_HOST}:{COLLECTOR_PORT}")
    
    if not os.path.exists(FLOWS_FILE):
        print(f"[!] Error: Flows source file {FLOWS_FILE} not found!")
        sys.exit(1)
        
    # Read and parse all flows
    print(f"[*] Reading and parsing flow file: {FLOWS_FILE}")
    flows = []
    with open(FLOWS_FILE, "r", errors="ignore") as f:
        for line in f:
            flow = parse_line(line)
            if flow:
                flows.append(flow)
                
    if not flows:
        print("[!] No valid flows parsed from file.")
        sys.exit(1)
        
    # Sort flows by timestamp
    flows.sort(key=lambda x: x["time"])
    print(f"[*] Parsed {len(flows)} valid flows. Start: {flows[0]['time']}, End: {flows[-1]['time']}")
    
    # Calculate intervals
    flow_intervals = []
    for i in range(1, len(flows)):
        diff = (flows[i]["time"] - flows[i-1]["time"]).total_seconds()
        flow_intervals.append(max(0.001, diff))  # min 1ms between events
    flow_intervals.append(1.0) # default sleep for last flow
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    start_time = time.time()
    seq_num = 0
    
    while True:
        print("[*] Starting replay loop...")
        for idx, flow in enumerate(flows):
            uptime_ms = int((time.time() - start_time) * 1000) & 0xffffffff
            now = time.time()
            unix_secs = int(now)
            unix_nsecs = int((now - unix_secs) * 1000000000)
            
            # Send single flow per packet (can be batch but single is fine for simulated flow rate)
            packet = pack_netflow_v5(uptime_ms, unix_secs, unix_nsecs, seq_num, [flow])
            try:
                sock.sendto(packet, (COLLECTOR_HOST, COLLECTOR_PORT))
                seq_num += 1
            except Exception as e:
                print(f"[!] Error sending packet: {e}")
                time.sleep(1)
                
            # Speed up the replay slightly (e.g. 5x speed) so anomalies show up faster
            sleep_time = flow_intervals[idx] / 5.0
            time.sleep(sleep_time)

if __name__ == "__main__":
    main()
