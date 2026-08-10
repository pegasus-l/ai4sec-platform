# ai4sec Dockerfile——FastAPI + Vite SPA 打包在一个镜像里
FROM node:20-slim AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci --silent
COPY frontend/ ./
RUN npm run build

FROM python:3.10-slim AS backend
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml ./
RUN pip install --no-cache-dir -e .
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist
COPY src ./src
COPY configs ./configs
COPY run-pipeline.sh start-api.sh ./
RUN chmod +x run-pipeline.sh start-api.sh
EXPOSE 8100
CMD ["bash", "start-api.sh"]
