#!/usr/bin/env python3
import subprocess
import time
import sys
import os

# Set working directory to the directory containing this script
script_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(script_dir)

def run_command(cmd, shell=False):
    try:
        result = subprocess.run(
            cmd,
            shell=shell,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        return True, result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return False, e.stdout, e.stderr

def print_header(title):
    print("=" * 65)
    print(f" {title}")
    print("=" * 65)

def main():
    print_header("🛡️ NetFlow DDoS Detection & Automated Response System")
    
    # 1. Check Docker status
    print("[*] Checking Docker daemon status...")
    ok, out, err = run_command(["docker", "info"])
    if not ok:
        print("[Xin] Error: Docker daemon is not running. Please start Docker first.")
        print(err)
        sys.exit(1)
    print("[✓] Docker daemon is running.")

    # 2. Build and start containers
    print("\n[*] Rebuilding and starting containerized services (docker compose up)...")
    compose_cmd = ["docker", "compose", "up", "-d", "--build"]
    ok, out, err = run_command(compose_cmd)
    if not ok:
        print("[Xin] Error: Failed to start containers.")
        print(err)
        sys.exit(1)
    print(out.strip())
    print("[✓] All containers started successfully.")

    # 3. Wait for initial setup
    print("\n[*] Waiting 5 seconds for services to initialize...")
    time.sleep(5)

    # 4. Verify running containers
    print_header("📊 Container Services Status")
    ok, out, err = run_command(["docker", "compose", "ps"])
    if ok:
        print(out.strip())
    else:
        print("[Xin] Failed to fetch container status.")
        print(err)

    # 5. Output clickable system links
    print_header("🔗 System Web Consoles & API Endpoints")
    print("  • Grafana Dashboard:           http://localhost:3000")
    print("  • Threat Response Console:     http://localhost:8002/status")
    print("  • Decisions Audit Feed:        http://localhost:8002/decisions")
    print("  • ML Exporter:                 http://localhost:8001/metrics")
    print("  • Matrix Builder Exporter:     http://localhost:8000/metrics")
    print("  • Active Auto-Response Blocks: http://localhost:8004/blocks")
    print("=" * 65)
    
    print("\n[✓] System is fully operational and replaying NetFlow simulation data.")
    print("    - Log streams can be viewed via: docker compose logs -f")

if __name__ == "__main__":
    main()
