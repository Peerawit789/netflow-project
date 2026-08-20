FROM python:3.11-alpine

WORKDIR /app

COPY simulator.py /app/simulator.py

# Expected mount: /data containing test.txt
ENTRYPOINT ["python", "simulator.py"]
