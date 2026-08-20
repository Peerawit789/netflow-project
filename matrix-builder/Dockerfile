FROM python:3.11-slim

RUN apt-get update && \
    apt-get install -y nfdump && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY matrix_builder.py /app/

EXPOSE 8000

ENTRYPOINT ["python", "matrix_builder.py"]
