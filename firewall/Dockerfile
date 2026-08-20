FROM debian:bookworm-slim

# Install SSH server and iptables
RUN apt-get update && \
    apt-get install -y openssh-server iptables && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure SSH daemon run directory
RUN mkdir -p /var/run/sshd

# Add enforcer user with a home directory
RUN useradd -rm -d /home/enforcer -s /bin/bash enforcer

# Add enforce script
COPY enforce.sh /usr/local/bin/enforce.sh
RUN chmod +x /usr/local/bin/enforce.sh

# Add entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22

ENTRYPOINT ["/entrypoint.sh"]
