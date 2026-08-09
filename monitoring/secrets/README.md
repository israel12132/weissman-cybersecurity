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

## Enabling live alerting

**Do NOT commit real secrets to this repository.** To enable live delivery,
overwrite these files at deploy time without committing them — for example with a
compose override that bind-mounts a directory of real secrets over this one, or by
writing the real values into the mounted files on the host after checkout:

```
printf '%s' '<paste-your-slack-incoming-webhook-url>'                                       > slack_api_url
printf '%s' '<32-char-pagerduty-routing-key>'                                             > pagerduty_routing_key
printf '%s' 'https://hc-ping.com/<your-uuid>'                                             > watchdog_url
```

Each file holds a single secret value with no surrounding quotes. A trailing
newline is fine. After changing a file, restart the `alertmanager` service so it
re-reads the values.
