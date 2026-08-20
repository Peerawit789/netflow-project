import os
import sys
import time
import threading
import requests
from collections import defaultdict
from fastapi import FastAPI, Response
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST, Gauge
from sklearn.ensemble import IsolationForest
import numpy as np

app = FastAPI(title="ML Anomaly Detection Engine")

@app.get("/metrics")
def get_metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

# Prometheus Gauges to expose anomaly scores
netflow_anomaly_score = Gauge(
    'netflow_anomaly_score',
    'ML anomaly score for host pairs',
    ['src', 'dst', 'pattern']
)

PROMETHEUS_URL = os.environ.get("PROMETHEUS_URL", "http://prometheus:9090")
CHECK_INTERVAL = int(os.environ.get("CHECK_INTERVAL", 15))
RETRAIN_INTERVAL = int(os.environ.get("RETRAIN_INTERVAL", 60))

# Model store per host (dst_ip)
models = {}
# Track drift alert status
host_drift_status = {}

def get_prometheus_metric(query_str):
    url = f"{PROMETHEUS_URL}/api/v1/query"
    try:
        response = requests.get(url, params={"query": query_str}, timeout=5)
        if response.status_code == 200:
            return response.json().get("data", {}).get("result", [])
    except Exception as e:
        print(f"[!] Error querying Prometheus: {e}")
    return []

def get_prometheus_range(query_str, duration_secs=900, step="60s"):
    url = f"{PROMETHEUS_URL}/api/v1/query_range"
    end_time = time.time()
    start_time = end_time - duration_secs
    params = {
        "query": query_str,
        "start": start_time,
        "end": end_time,
        "step": step
    }
    try:
        response = requests.get(url, params=params, timeout=5)
        if response.status_code == 200:
            return response.json().get("data", {}).get("result", [])
    except Exception as e:
        print(f"[!] Error querying Prometheus range: {e}")
    return []

def generate_synthetic_data():
    # Generate normal baseline profile data: low packets, low bytes, low PPS
    np.random.seed(42)
    bytes_norm = np.random.uniform(500, 10000, 50)
    packets_norm = np.random.uniform(5, 50, 50)
    pps_norm = packets_norm / 60.0
    return np.column_stack((bytes_norm, packets_norm, pps_norm))

def train_models():
    print("[*] Re-training host-based Isolation Forest models...")
    # Get last 15 mins range data for bytes and packets
    bytes_data = get_prometheus_range("netflow_bytes", duration_secs=900, step="60s")
    packets_data = get_prometheus_range("netflow_packets", duration_secs=900, step="60s")
    
    # Organize training sets by destination host
    host_train_data = defaultdict(list)
    
    # Map time points
    flows_by_dst = defaultdict(lambda: defaultdict(lambda: {"bytes": 0, "packets": 0}))
    
    # Process bytes data
    for series in bytes_data:
        labels = series.get("metric", {})
        dst = labels.get("dst")
        src = labels.get("src")
        if not dst or dst == "other" or src == "other":
            continue
        values = series.get("values", [])
        for val in values:
            t = val[0]
            b = float(val[1])
            flows_by_dst[dst][(src, t)]["bytes"] = b

    # Process packets data
    for series in packets_data:
        labels = series.get("metric", {})
        dst = labels.get("dst")
        src = labels.get("src")
        if not dst or dst == "other" or src == "other":
            continue
        values = series.get("values", [])
        for val in values:
            t = val[0]
            p = float(val[1])
            flows_by_dst[dst][(src, t)]["packets"] = p

    # Build features: [bytes, packets, pps]
    for dst, points in flows_by_dst.items():
        features = []
        for (src, t), val in points.items():
            b = val["bytes"]
            p = val["packets"]
            pps = p / 60.0
            features.append([b, p, pps])
        if features:
            host_train_data[dst] = np.array(features)

    # Train a model for each host
    for dst in list(host_train_data.keys()) + list(models.keys()):
        # Default fallback to synthetic if no traffic
        data = host_train_data.get(dst)
        if data is None or len(data) < 10:
            print(f"[*] Insufficient data for {dst} ({len(data) if data is not None else 0} points). Using synthetic baseline.")
            data = generate_synthetic_data()
            
        clf = IsolationForest(contamination=0.05, random_state=42)
        clf.fit(data)
        models[dst] = clf
        
        # Check for model drift: score the training dataset
        # If the fraction of data flagged as anomalous is high, baseline has drifted
        preds = clf.predict(data)  # -1 for anomaly, 1 for normal
        fpr = np.sum(preds == -1) / len(preds)
        if fpr > 0.20:
            print(f"[DRIFT WARNING] Host {dst} shows high anomaly rate ({fpr*100:.1f}%) in rolling window!")
            host_drift_status[dst] = True
        else:
            host_drift_status[dst] = False

def classify_pattern(proto, pps, avg_pkt_size, anomaly_score):
    if anomaly_score <= 0.6:
        return "normal"
        
    proto = proto.upper().strip()
    if proto == "UDP" and pps > 50:
        return "udp_flood"
    elif proto == "TCP" and pps > 50 and avg_pkt_size < 100:
        return "syn_flood"
    elif pps > 30 and avg_pkt_size < 100:
        # Coarse heuristic for generic flood or port scan
        return "port_scan"
    else:
        return "generic_anomaly"

def evaluate_flows():
    # Query current bytes, packets metrics
    bytes_curr = get_prometheus_metric("netflow_bytes")
    packets_curr = get_prometheus_metric("netflow_packets")
    
    current_metrics = defaultdict(lambda: {"bytes": 0.0, "packets": 0.0, "proto": "UDP"})
    
    for series in bytes_curr:
        labels = series.get("metric", {})
        src = labels.get("src")
        dst = labels.get("dst")
        proto = labels.get("proto")
        if not src or not dst or src == "other" or dst == "other":
            continue
        val = float(series.get("value", [0, 0])[1])
        current_metrics[(src, dst)]["bytes"] = val
        current_metrics[(src, dst)]["proto"] = proto

    for series in packets_curr:
        labels = series.get("metric", {})
        src = labels.get("src")
        dst = labels.get("dst")
        if not src or not dst or src == "other" or dst == "other":
            continue
        val = float(series.get("value", [0, 0])[1])
        current_metrics[(src, dst)]["packets"] = val

    # Clear previous anomaly scores
    netflow_anomaly_score.clear()

    # Score each active flow
    for (src, dst), flow in current_metrics.items():
        b = flow["bytes"]
        p = flow["packets"]
        pr = flow["proto"]
        pps = p / 60.0
        
        # Extract features
        X = np.array([[b, p, pps]])
        
        # Load or create model for this host
        if dst not in models:
            # Cold start: fit a temporary model using synthetic data
            print(f"[*] Cold start model initialization for destination {dst}")
            clf = IsolationForest(contamination=0.05, random_state=42)
            clf.fit(generate_synthetic_data())
            models[dst] = clf
            
        clf = models[dst]
        
        # Calculate score (decision_function ranges from ~ -0.5 to 0.5)
        # We map more negative -> higher score (close to 1.0)
        s = clf.decision_function(X)[0]
        # Map: s >= 0 -> 0.1-0.4 (normal range)
        # Map: s < 0 -> 0.6-1.0 (anomalous range)
        if s >= 0:
            score = max(0.1, 0.5 - s)
        else:
            # Scale more aggressively for large anomalies (s is negative)
            score = min(1.0, 0.5 - s * 8.0)
            
        avg_pkt_size = b / p if p > 0 else 0
        pattern = classify_pattern(pr, pps, avg_pkt_size, score)
        
        # Expose the score to metrics
        netflow_anomaly_score.labels(src=src, dst=dst, pattern=pattern).set(score)
        print(f"[*] ML Scored: {src} -> {dst} | Score: {score:.3f} | Pattern: {pattern} | Bytes: {b} | Packets: {p}")

def background_ml_loop():
    print("[*] Starting Background ML Loop...")
    # Wait for Prometheus to gather initial metrics
    time.sleep(15)
    
    last_retrain = 0
    while True:
        now = time.time()
        try:
            # Periodic retraining
            if now - last_retrain >= RETRAIN_INTERVAL:
                train_models()
                last_retrain = now
                
            # Periodic evaluation
            evaluate_flows()
        except Exception as e:
            print(f"[!] Error in ML loop: {e}")
            
        time.sleep(CHECK_INTERVAL)

@app.on_event("startup")
def startup_event():
    t = threading.Thread(target=background_ml_loop, daemon=True)
    t.start()

@app.get("/")
def read_root():
    return {
        "status": "online",
        "models_trained": list(models.keys()),
        "drift_status": host_drift_status
    }
