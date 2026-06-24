# שבוע 1 — Go-Live (יום-יום)

**מטרה:** מ-repo → production שמוכר ועובד.

---

## לפני שמתחילים

```bash
./scripts/go_live_check.sh
```

---

| יום | משימה | אחראי | Done |
|-----|--------|--------|------|
| **1** | `git push` · סיבוב token אם צריך · VPS + Docker | DevOps | ☐ |
| **1** | עו"ד: MSA + Order Form מ-`docs/legal/` | CEO/Legal | ☐ |
| **1** | רו"ח: בע"מ + ח.פ. → `deploy/company.details.example.json` | Finance | ☐ |
| **2** | `cp PRODUCTION.env.template .env` — secrets חזקים | DevOps | ☐ |
| **2** | `docker compose -f docker-compose.yml -f docker-compose.staging.yml --profile staging up -d --build` | DevOps | ☐ |
| **2** | `./scripts/go_live_check.sh --live https://staging...` | QA | ☐ |
| **3** | Paddle sandbox: `pri_*` + webhook URL | Finance | ☐ |
| **3** | SMTP (Mailpit staging → SendGrid prod) | DevOps | ☐ |
| **3** | DNS + TLS + `@weissman.io` mailboxes | DevOps | ☐ |
| **4** | Demo script: Clients → Scan → Findings → PDF | Sales | ☐ |
| **4** | `docs/sales/viewer/index.html` — dry run CEO | Sales | ☐ |
| **5** | Paddle **live** + billing smoke | Finance | ☐ |
| **5** | On-call roster: `docs/operations/INCIDENT-ONCALL-RUNBOOK-he.md` | Ops | ☐ |
| **5** | לקוח pilot #1 — MSA חתום + scope | Sales | ☐ |

---

## Pass criteria (שבוע 1)

- [ ] `./scripts/go_live_check.sh --live` exit 0
- [ ] Login + scan + finding + PDF
- [ ] Billing checkout (sandbox minimum)
- [ ] `/status` public green
- [ ] MSA + scope appendix signed

---

## אחרי שבוע 1

- OAST profile (אם נמכר OOB)
- LLM endpoint (Council / Ask)
- Workshop / LMS (אופציונלי)
