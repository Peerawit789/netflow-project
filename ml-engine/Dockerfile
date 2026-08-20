FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY ml_engine.py /app/

EXPOSE 8001

ENTRYPOINT ["uvicorn", "ml_engine:app", "--host", "0.0.0.0", "--port", "8001"]
