FROM python:3.12-slim
WORKDIR /app
COPY webhook.py .
ENTRYPOINT ["python", "webhook.py"]
