# Alertmanager delivery secrets

Alertmanager reads each delivery secret from a **file** here (see `../alertmanager.yml`,
`*_file` keys). The config is valid and Alertmanager starts even when these files are
empty or absent, so the stack boots with alerting inert. Populate a file to turn on that
channel — no restart of the rest of the stack is required (`docker compose restart
alertmanager`).

| File                     | Purpose                                                        |
|--------------------------|----------------------------------------------------------------|
| `slack_webhook_url`      | Slack Incoming Webhook URL (`#security-alerts` / warnings)      |
| `pagerduty_routing_key`  | PagerDuty Events API v2 routing key (critical paging)          |
| `watchdog_heartbeat_url` | External dead-man's-switch ping URL (healthchecks.io, etc.)    |

Each file must contain **only** the value, no trailing newline is required. Example:

```sh
printf '%s' 'https://hooks.slack.com/services/T00/B00/xxxx' \
  > monitoring/alertmanager-secrets/slack_webhook_url
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile monitoring \
  restart alertmanager
```

Do **not** commit populated secret files. `.gitignore` excludes everything here except
this README and `.gitkeep`.
