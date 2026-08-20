FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y nfdump && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Expose internal UDP NetFlow port
EXPOSE 2055/udp

# Command runs nfcapd in the foreground:
# -w /data: store captures in /data
# -p 2055: listen on port 2055
# -t 60: rotate every 60s
# -D is NOT used to keep it in the foreground for Docker
ENTRYPOINT ["nfcapd", "-w", "/data", "-p", "2055", "-t", "60"]
