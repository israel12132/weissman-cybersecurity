# Production: Vite build + Nginx gateway (static SPA + /api /ws → backend)
FROM node:22-bookworm-slim AS builder
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci --ignore-scripts
COPY frontend/ ./
RUN npm run build

# Non-root, unprivileged nginx: runs as UID 101 (no root master process) and listens
# on 8080 inside the container. The host still exposes :80 via the compose port map.
FROM nginxinc/nginx-unprivileged:1.27-alpine
USER root
RUN apk add --no-cache curl
COPY deploy/nginx-gateway.conf          /etc/nginx/conf.d/default.conf
COPY deploy/nginx-security-headers.inc  /etc/nginx/conf.d/security-headers.inc
COPY --from=builder /app/dist           /usr/share/nginx/html/command-center
# Public marketing site (landing, pricing, terms, privacy, dpa, security.txt, robots, sitemap).
COPY deploy/public                      /usr/share/nginx/html/public
USER 101
EXPOSE 8080
