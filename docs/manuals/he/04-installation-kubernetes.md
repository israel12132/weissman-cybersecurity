# 04 — התקנה: Kubernetes

## מטרה

הרצת Weissman על Kubernetes לקנה מידה, rolling upgrades, וops cloud-native. Manifests ב-`deploy/k8s/` משקפים את Docker Compose: gateway, backend, worker, Redis; Postgres בדרך כלל שירות מנוה.

---

## דרישות מקדימות

| דרישה | הערות |
|--------|-------|
| Cluster | Kubernetes 1.28+ עם ingress controller |
| Postgres 16 + pgvector | RDS, Cloud SQL, או StatefulSet |
| Registry | Images מ-`deploy/backend.Dockerfile`, `deploy/frontend.Dockerfile` |
| TLS | cert-manager או cloud LB |
| Secrets | Sealed Secrets / External Secrets / KMS |

---

## ארכיטקטורה ב-K8s

```
Ingress (weissmancyber.com)
  └─ weissman-gateway :80
       ├─ /command-center/* → SPA
       ├─ /api/*            → weissman-backend :8000
       └─ /ws/*             → WebSocket

weissman-backend Deployment
weissman-worker Deployment   — חובה לסריקות
redis Deployment
```

Postgres **לא** ב-manifests ברירת מחדל — `DATABASE_URL` דרך Secret.

---

## שלב אחר שלב

### 1. Build והעלאת images

```bash
docker build -f deploy/backend.Dockerfile -t registry.example/weissman-backend:TAG .
docker build -f deploy/frontend.Dockerfile -t registry.example/weissman-gateway:TAG .
docker push registry.example/weissman-backend:TAG
docker push registry.example/weissman-gateway:TAG
```

עדכנו tags ב-`backend-deployment.yaml`, `worker-deployment.yaml`, `gateway-deployment.yaml`.

### 2. Namespace וSecrets

```bash
kubectl create namespace weissman
```

Secret (לעולם לא ב-git):

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: weissman-secrets
  namespace: weissman
type: Opaque
stringData:
  DATABASE_URL: "postgres://weissman_app:...@host:5432/weissman?sslmode=require"
  WEISSMAN_JWT_SECRET: "<openssl rand -base64 48>"
  REDIS_URL: "redis://weissman-redis:6379/0"
  WEISSMAN_METRICS_TOKEN: "<token>"
  WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET: "<secret>"
```

### 3. ConfigMap deployments

```bash
kubectl apply -f deploy/k8s/configmap.yaml -n weissman
kubectl apply -f deploy/k8s/redis-deployment.yaml -n weissman
kubectl apply -f deploy/k8s/backend-deployment.yaml -n weissman
kubectl apply -f deploy/k8s/worker-deployment.yaml -n weissman
kubectl apply -f deploy/k8s/gateway-deployment.yaml -n weissman
kubectl apply -f deploy/k8s/backend-service.yaml -n weissman
kubectl apply -f deploy/k8s/gateway-service.yaml -n weissman
```

ConfigMap חייב לכלול:

```yaml
WEISSMAN_ENV: "production"
WEISSMAN_COOKIE_SECURE: "1"
WEISSMAN_PUBLIC_BASE_URL: "https://your-domain.example"
```

### 4. Ingress

```bash
kubectl apply -f deploy/k8s/ingress.yaml -n weissman
```

WebSocket annotations:

```yaml
nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"
nginx.ingress.kubernetes.io/proxy-send-timeout: "3600"
```

### 5. Grants ב-Postgres

הריצו `deploy/grant-postgres-weissman-prod.sql` לפני boot ראשון.

### 6. Scale workers

עומס כבד: הגדילו replicas של worker. `SKIP LOCKED` — replicas מרובים בטוחים.

---

## אבטחה ב-production

| בקרה | יישום |
|------|--------|
| `WEISSMAN_ENV=production` | `security_startup.rs` guards |
| Cookies | `WEISSMAN_COOKIE_SECURE=1` + HTTPS |
| Metrics | `WEISSMAN_METRICS_TOKEN` על `GET /api/metrics` |
| פעולות הרסניות | `WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET` + header `X-Weissman-Destructive-Confirm` |
| Billing | `WEISSMAN_BILLING_STRICT=1` ברירת מחדל |

---

## אימות

```bash
kubectl get pods -n weissman
kubectl logs -n weissman deploy/weissman-backend --tail=30
curl -sf https://your-domain.example/api/health
```

התחברות דרך `POST /api/login`. הריצו סריקה; worker logs מראים claim.

---

## שדרוג

```bash
kubectl set image deployment/weissman-backend backend=registry.example/weissman-backend:NEW -n weissman
kubectl rollout status deployment/weissman-backend -n weissman
```

---

## פתרון תקלות

| תסמין | תיקון |
|--------|-------|
| CrashLoopBackOff | Secret/JWT; logs של `security_startup` |
| סריקות לא מסתיימות | Worker חסר או scaled ל-0 |
| WebSocket נופל | Ingress timeouts |
| 503 billing | Paddle / subscription |

ראו [17-troubleshooting](17-troubleshooting.md).

---

## ספרים קשורים

- [02-installation-docker](02-installation-docker.md)
- [03-installation-vps-systemd](03-installation-vps-systemd.md)
- [05-production-security](05-production-security.md)
- [06-environment-configuration](06-environment-configuration.md)
- [16-operations-monitoring](16-operations-monitoring.md)
