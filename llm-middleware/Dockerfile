FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY llm_middleware.py /app/

EXPOSE 8003

ENTRYPOINT ["uvicorn", "llm_middleware:app", "--host", "0.0.0.0", "--port", "8003"]
