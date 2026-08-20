#!/bin/bash
# SSH ForceCommand Target Script for Firewall Enforcement

CMD=$SSH_ORIGINAL_COMMAND

# Regex checking for safe format: block <IP/Interface> or unblock <IP/Interface>
if [[ $CMD =~ ^(block|unblock)\ [a-zA-Z0-9\.\-_]+$ ]]; then
    ACTION=$(echo $CMD | cut -d' ' -f1)
    IP=$(echo $CMD | cut -d' ' -f2)
    
    echo "[FIREWALL] Processing action: $ACTION for target IP: $IP"
    
    # Store simulated block in a file in /data volume (verifiable)
    mkdir -p /data
    
    if [ "$ACTION" == "block" ]; then
        # Append to blocked IPs file
        echo "$IP" >> /data/blocked_ips.txt
        # Attempt to run iptables (requires NET_ADMIN capabilities)
        iptables -A INPUT -s "$IP" -j DROP 2>/dev/null
        if [ $? -eq 0 ]; then
            echo "[FIREWALL] Successfully blocked $IP via iptables."
        else
            echo "[FIREWALL] Added $IP to simulated blocks log (iptables failed due to privileges)."
        fi
    elif [ "$ACTION" == "unblock" ]; then
        # Remove from blocked IPs file
        if [ -f /data/blocked_ips.txt ]; then
            # Filter the IP out safely
            grep -v -w "$IP" /data/blocked_ips.txt > /data/blocked_ips.tmp
            mv /data/blocked_ips.tmp /data/blocked_ips.txt
        fi
        # Attempt to remove from iptables
        iptables -D INPUT -s "$IP" -j DROP 2>/dev/null
        if [ $? -eq 0 ]; then
            echo "[FIREWALL] Successfully unblocked $IP via iptables."
        else
            echo "[FIREWALL] Removed $IP from simulated blocks log."
        fi
    fi
    exit 0
else
    echo "Unauthorized: Only block/unblock commands with a single IPv4 address are allowed."
    exit 1
fi
