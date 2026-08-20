#!/bin/bash
# Firewall Container Entrypoint

# Generate SSH host keys if not present
ssh-keygen -A

# Create .ssh directory for enforcer user
mkdir -p /home/enforcer/.ssh

# Configure authorized_keys with restricted command
if [ -f /app/ssh/id_rsa.pub ]; then
    echo "Configuring ForceCommand authorized_keys for user 'enforcer'"
    PUBKEY=$(cat /app/ssh/id_rsa.pub)
    echo "command=\"/usr/local/bin/enforce.sh\" $PUBKEY" > /home/enforcer/.ssh/authorized_keys
else
    echo "[!] Warning: Public key /app/ssh/id_rsa.pub not found! SSH logins will fail."
fi

# Set correct SSH permissions (sshd requires strict permissions)
chown -R enforcer:enforcer /home/enforcer/.ssh
chmod 700 /home/enforcer/.ssh
chmod 600 /home/enforcer/.ssh/authorized_keys

# Set permissions for /data volume so enforcer user can write to it
mkdir -p /data
chown -R enforcer:enforcer /data

# Run SSH Server in foreground
echo "[*] Starting SSH Daemon..."
exec /usr/sbin/sshd -D
