# Production: Vite build + Nginx gateway (static SPA + /api /ws → backend)
FROM node:20-bookworm-slim AS builder
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci --ignore-scripts 2>/dev/null || npm install --ignore-scripts
COPY frontend/ ./
RUN npm run build

FROM nginx:1.27-alpine
COPY deploy/nginx-gateway.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/dist /usr/share/nginx/html/command-center
EXPOSE 80
