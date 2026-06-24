# 04 — Installation: Kubernetes

## Purpose

Run Weissman on Kubernetes for horizontal scaling, rolling upgrades, and cloud-native ops. Manifests live under `deploy/k8s/` and mirror the Docker Compose topology: gateway, backend, worker, Redis, with Postgres typically managed externally.

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| Cluster | Kubernetes 1.28+ with ingress controller (nginx ingress assumed) |
| Postgres 16 + pgvector | Managed service (RDS, Cloud SQL) or in-cluster StatefulSet |
| Container registry | Images built from `deploy/backend.Dockerfile`, `deploy/frontend.Dockerfile` |
| TLS | cert-manager or cloud LB terminating HTTPS |
| Secrets vault | Sealed Secrets, External Secrets, or cloud KMS |

---

## Architecture on K8s

```
Ingress (weissmancyber.com)
  └─ weissman-gateway Service :80
       ├─ /command-center/* → static SPA (nginx sidecar or gateway image)
       ├─ /api/*            → weissman-backend :8000
       └─ /ws/*             → WebSocket to backend

weissman-backend Deployment  (weissman-server)
weissman-worker Deployment   (weissman-worker) — required for scans
redis Deployment             (rate limits, agent registry)
```

Postgres is **not** bundled in the default manifests — supply `DATABASE_URL` via Secret.

---

## Step-by-step

### 1. Build and push images

```bash
docker build -f deploy/backend.Dockerfile -t registry.example/weissman-backend:TAG .
docker build -f deploy/frontend.Dockerfile -t registry.example/weissman-gateway:TAG .
docker push registry.example/weissman-backend:TAG
docker push registry.example/weissman-gateway:TAG
```

Update image tags in `deploy/k8s/backend-deployment.yaml`, `worker-deployment.yaml`, and `gateway-deployment.yaml`.

### 2. Create namespace and secrets

```bash
kubectl create namespace weissman
```

Create a Secret (never commit filled values):

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: weissman-secrets
  namespace: weissman
type: Opaque
stringData:
  DATABASE_URL: "postgres://weissman_app:...@postgres-host:5432/weissman?sslmode=require"
  WEISSMAN_AUTH_DATABASE_URL: "postgres://weissman_auth:...@..."
  WEISSMAN_MIGRATE_URL: "postgres://postgres:...@..."
  WEISSMAN_JWT_SECRET: "<openssl rand -base64 48>"
  REDIS_URL: "redis://weissman-redis:6379/0"
  WEISSMAN_METRICS_TOKEN: "<random>"
  WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET: "<random>"
  WEISSMAN_ADMIN_PASSWORD: "<strong>"
  PADDLE_API_KEY: "<optional>"
  PADDLE_WEBHOOK_SECRET: "<optional>"
```

Reference `PRODUCTION.env.template` for the complete list.

### 3. Apply ConfigMap and deployments

```bash
kubectl apply -f deploy/k8s/configmap.yaml -n weissman
kubectl apply -f deploy/k8s/redis-deployment.yaml -n weissman
kubectl apply -f deploy/k8s/backend-deployment.yaml -n weissman
kubectl apply -f deploy/k8s/worker-deployment.yaml -n weissman
kubectl apply -f deploy/k8s/gateway-deployment.yaml -n weissman
kubectl apply -f deploy/k8s/backend-service.yaml -n weissman
kubectl apply -f deploy/k8s/gateway-service.yaml -n weissman
```

Ensure `ConfigMap` sets:

```yaml
WEISSMAN_ENV: "production"
WEISSMAN_COOKIE_SECURE: "1"
WEISSMAN_PUBLIC_BASE_URL: "https://your-domain.example"
PORT: "8000"
```

`deploy/k8s/configmap.yaml` documents that DB URLs and JWT secret **must** come from Secrets.

### 4. Configure Ingress

Edit `deploy/k8s/ingress.yaml` host name, then apply:

```bash
kubectl apply -f deploy/k8s/ingress.yaml -n weissman
```

Ingress routes `/` to `weissman-gateway:80`. WebSocket paths require nginx annotations:

```yaml
nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"
nginx.ingress.kubernetes.io/proxy-send-timeout: "3600"
```

### 5. Run database grants

Apply `deploy/grant-postgres-weissman-prod.sql` on the Postgres instance before first boot so RLS roles exist.

### 6. Scale workers

Heavy scan load: increase `weissman-worker` replicas. Workers use PostgreSQL `SKIP LOCKED` job claiming — multiple replicas are safe.

Light vs heavy concurrency per pod: `WEISSMAN_WORKER_LIGHT_CONCURRENCY`, `WEISSMAN_WORKER_HEAVY_CONCURRENCY`.

---

## Production security on K8s

| Control | Implementation |
|---------|----------------|
| `WEISSMAN_ENV=production` | Enables `security_startup.rs` guards in every backend/worker pod |
| Secure cookies | `WEISSMAN_COOKIE_SECURE=1` + HTTPS ingress |
| Metrics | Protect `GET /api/metrics` with `WEISSMAN_METRICS_TOKEN` |
| Destructive actions | Set `WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET`; operators send `X-Weissman-Destructive-Confirm` header |
| Billing | `WEISSMAN_BILLING_STRICT=1` default in production; configure Paddle secrets |

Never mount `.env` from git — inject via Secret references only.

---

## Verification

```bash
kubectl get pods -n weissman
kubectl logs -n weissman deploy/weissman-backend --tail=30
kubectl logs -n weissman deploy/weissman-worker --tail=30
curl -sf https://your-domain.example/api/health
curl -sf https://your-domain.example/command-center/
```

Log in via `POST /api/login` (Command Center login page). Trigger a scan; confirm worker pod logs show job claim.

Run QA scripts from manual **18** against the public URL.

---

## Upgrade procedure

```bash
kubectl set image deployment/weissman-backend backend=registry.example/weissman-backend:NEW -n weissman
kubectl set image deployment/weissman-worker worker=registry.example/weissman-backend:NEW -n weissman
kubectl rollout status deployment/weissman-backend -n weissman
```

Migrations run when backend pods restart with `WEISSMAN_MIGRATE_URL` set.

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Backend CrashLoopBackOff | Check Secret keys; JWT secret ≥ 32 chars; logs for `security_startup` errors |
| Scans never complete | Worker Deployment missing or scaled to 0 |
| WebSocket disconnects | Ingress timeout annotations; sticky sessions not required |
| 503 on billing | Paddle webhook or subscription not provisioned — see manual 08 |

See [17-troubleshooting](17-troubleshooting.md).

---

## Related manuals

- [02-installation-docker](02-installation-docker.md) — simpler single-node path
- [03-installation-vps-systemd](03-installation-vps-systemd.md) — non-container alternative
- [05-production-security](05-production-security.md)
- [06-environment-configuration](06-environment-configuration.md)
- [16-operations-monitoring](16-operations-monitoring.md)
