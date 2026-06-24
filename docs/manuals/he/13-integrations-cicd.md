# 13 — Integrations & CI/CD

## מטרה

חיבור Weissman ל-CI/CD, webhooks, feeds intel, OAST לאימות out-of-band.

---

## דרישות מקדימות

- operator ל-integrations
- client עם scope (ספר 09)
- OAST (אופציוני): `weissman-oast-server`
- egress מ-CI runners

---

## CI/CD

Webhooks **לא מאומתים** — אבטחה via secrets, IP allowlist, scope.

### Endpoints

| Path | פלטפורמה |
|------|----------|
| `/hooks/cicd/github` | GitHub Actions |
| `/hooks/cicd/gitlab` | GitLab |
| `/hooks/cicd/bitbucket` | Bitbucket |
| `/hooks/cicd/scan` | generic |

**Integrations** → CI/CD.

### GitHub Actions — שלבים

1. יצירת integration; URL + secret
2. `WEISSMAN_WEBHOOK_SECRET` ב-repo
3. Workflow:

```yaml
- name: Weissman security scan
  run: |
    curl -X POST https://your-domain.example/hooks/cicd/github \
      -H "Content-Type: application/json" \
      -H "X-Hub-Signature-256: sha256=$(echo -n '{}' | openssl dgst -sha256 -hmac ${{ secrets.WEISSMAN_WEBHOOK_SECRET }} | cut -d' ' -f2)" \
      -d '{"repository":"org/repo","ref":"main","client_id":1}'
```

4. job ב-queue; findings ל-client
5. fail pipeline על Critical (אופציוני)

### Generic

`POST /hooks/cicd/scan` — `client_id`, `engine`, `target`. `gate_scan_enqueue` כמו סריקה ידנית.

---

## Outbound webhooks

```bash
WEISSMAN_ALERT_WEBHOOK_URL=https://hooks.slack.com/...
```

Critical PoE, SOAR fallback, alert rules (ספר 15).

---

## Intel feeds

- CISA KEV
- FIRST EPSS
- IOC מותאם

```bash
WEISSMAN_INTEL_KEV_ENABLED=true
WEISSMAN_INTEL_EPSS_ENABLED=true
WEISSMAN_INTEL_DATABASE_URL=postgres://...
```

ספר 11. air-gap — mirror מקומי.

---

## OAST

SSRF, XXE — callback verification.

```bash
WEISSMAN_OAST_BASE_URL=https://oast.your-domain.example
```

שרת נפרד — לא ב-compose ברירת מחדל.

---

## SIEM / ticketing

CSV (ספר 11), webhooks, SOAR (ספר 15). `WEISSMAN_LOG_FORMAT=json`.

---

## API automation

```bash
curl -X POST -b cookies.txt https://localhost/api/command-center/scan \
  -H 'Content-Type: application/json' \
  -d '{"engine":"sast_github","client_id":1,"target":"org/repo"}'
```

service account עם `operator`. rate limits (Redis).

---

## אימות

```bash
curl -s -o /dev/null -w "%{http_code}" -X POST https://localhost/hooks/cicd/scan \
  -H 'Content-Type: application/json' -d '{}'
# 401/403 — לא 404
```

- [ ] webhook מ-pipeline → job
- [ ] findings scoped
- [ ] alert webhook
- [ ] OAST callback (אם פרוס)

---

## פתרון תקלות

| תסמין | תיקון |
|--------|-------|
| 404 | nginx routes |
| signature | HMAC secret |
| לא enqueue | billing; client_id |
| OAST | DNS/firewall |

ראו [17-troubleshooting](17-troubleshooting.md).

---

## ספרים קשורים

- [10-scans-engines-jobs](10-scans-engines-jobs.md)
- [11-findings-reports](11-findings-reports.md)
- [15-alerting-soar-ai](15-alerting-soar-ai.md)
- [06-environment-configuration](06-environment-configuration.md)
