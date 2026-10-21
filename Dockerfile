FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends smbclient libsmbclient-dev gcc && rm -rf /var/lib/apt/lists/*
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ ./
COPY frontend/public/ ./static/
EXPOSE 8080
CMD ["python", "main.py"]
