# Build context is the repository root (RAILWAY_DOCKERFILE_PATH=certin/Dockerfile)
FROM python:3.12-slim
WORKDIR /srv
COPY certin/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY certin/app.py .
ENV PYTHONUNBUFFERED=1
EXPOSE 8000
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-8000}"]
