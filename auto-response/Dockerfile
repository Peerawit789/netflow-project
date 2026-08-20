FROM python:3.11-slim

# Install system dependencies for cryptography / paramiko
RUN apt-get update && \
    apt-get install -y gcc libffi-dev libssl-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY auto_response.py /app/

EXPOSE 8004

ENTRYPOINT ["uvicorn", "auto_response:app", "--host", "0.0.0.0", "--port", "8004"]
