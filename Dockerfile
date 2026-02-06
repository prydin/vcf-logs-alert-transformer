FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY alert-transformer.py .
COPY config.yaml .

RUN mkdir -p /var/lib/alert-transformer/queue

EXPOSE 8080

CMD ["python", "alert-transformer.py", \
     "-c", "/app/config.yaml", \
     "-q", "/var/lib/alert-transformer/queue", \
     "-p", "8080"]

