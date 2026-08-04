# Build context is the repository root; this file lives at platform/Dockerfile
# (service env RAILWAY_DOCKERFILE_PATH=platform/Dockerfile)

# Stage 1: build the React admin console
FROM node:20-alpine AS ui
WORKDIR /ui
COPY platform/admin-ui/package.json platform/admin-ui/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY platform/admin-ui/ ./
RUN npm run build

# Stage 2: Python runtime
FROM python:3.12-slim
WORKDIR /srv
COPY platform/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY platform/app ./app
COPY --from=ui /ui/dist ./static/admin
ENV PYTHONUNBUFFERED=1
EXPOSE 8000
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
