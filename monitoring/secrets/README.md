# Alertmanager secrets

The stock `prom/alertmanager` image ships no `envsubst`, so Alertmanager cannot
expand `${VAR}` placeholders in `alertmanager.yml`. Instead, every secret is read
from a file at notification time via Alertmanager's native `*_file` options:

| File                    | Consumed by (`alertmanager.yml`)                     | Alertmanager option   |
| ----------------------- | ---------------------------------------------------- | --------------------- |
| `slack_api_url`         | `critical-alerts` + `warning-alerts` slack receivers | `api_url_file`        |
| `pagerduty_routing_key` | `critical-alerts` pagerduty receiver                 | `routing_key_file`    |
| `watchdog_url`          | `watchdog-heartbeat` webhook receiver                | `url_file`            |

The directory is mounted read-only into the container at
`/etc/alertmanager/secrets/` (see the `alertmanager` service in
`docker-compose.yml`).

## Committed placeholders

The files in this directory are **committed, inert placeholders** so the stack
starts cleanly with no real secrets:

- `slack_api_url` → `https://slack-webhook.invalid/DISABLED-...` (syntactically
  valid URL on an unresolvable host — no messages are delivered)
- `pagerduty_routing_key` → `DISABLED` (no valid PagerDuty service is paged)
- `watchdog_url` → `https://heartbeat.invalid/DISABLED` (unresolvable host)

With these placeholders, `amtool check-config` passes and Alertmanager loads the
config without crash-looping. Alerts are grouped and logged but not delivered
anywhere real.

## ⚠️ Production / go-live requirement

**Alert delivery is a go-live gate.** `./scripts/go_live_check.sh` will FAIL
until all three secrets are replaced with real values. You cannot go live with
placeholders — alerts will fire, go nowhere, and SLA §4 (SEV-1 ≤ 15 min, 24/7)
cannot be met.

## Enabling live alerting

**Do NOT commit real secrets to this repository.** To enable live delivery,
overwrite these files at deploy time without committing them.

### Option A — Write directly on the host (Docker Compose deployments)

```bash
# On the production host, after cloning:
printf '%s' 'https://hooks.slack.com/services/T.../B.../...' > monitoring/secrets/slack_api_url
printf '%s' '<32-char-pagerduty-routing-key>'                > monitoring/secrets/pagerduty_routing_key
printf '%s' 'https://hc-ping.com/<your-uuid>'               > monitoring/secrets/watchdog_url

# Reload Alertmanager
docker compose restart alertmanager

# Verify go-live gate passes
./scripts/go_live_check.sh
```

### Option B — Docker Compose override (recommended for CI/CD)

Create `docker-compose.secrets.yml` (never commit):
```yaml
services:
  alertmanager:
    volumes:
      - /path/to/real/secrets:/etc/alertmanager/secrets:ro
```
Then: `docker compose -f docker-compose.yml -f docker-compose.secrets.yml up -d`

### Option C — Kubernetes Secret

```bash
kubectl create secret generic alertmanager-secrets \
  --from-literal=slack_api_url='https://hooks.slack.com/...' \
  --from-literal=pagerduty_routing_key='<key>' \
  --from-literal=watchdog_url='https://hc-ping.com/<uuid>' \
  -n weissman
```
Mount the secret at `/etc/alertmanager/secrets/` in the Alertmanager pod.

### How to get each secret

| Secret | Where to get it |
|--------|-----------------|
| `slack_api_url` | Slack → Apps → Incoming Webhooks → Add to Workspace |
| `pagerduty_routing_key` | PagerDuty → Services → Integration Key (Events API v2) |
| `watchdog_url` | healthchecks.io or Dead Man's Snitch → create a check → copy ping URL |

Each file holds a single secret value with no surrounding quotes. A trailing
newline is fine. After changing a file, restart the `alertmanager` service so it
re-reads the values.
