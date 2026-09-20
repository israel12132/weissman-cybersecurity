# תפעול — Weissman Cybersecurity

מסמכי Ops לצוות פנימי (לא ללקוח).

| מסמך | תיאור |
|------|--------|
| [INCIDENT-ONCALL-RUNBOOK-he.md](INCIDENT-ONCALL-RUNBOOK-he.md) | תגובה לאירוע, on-call, escalation |
| [MAINTENANCE-PAGE-AND-ZERO-DOWNTIME-REBUILD-he.md](MAINTENANCE-PAGE-AND-ZERO-DOWNTIME-REBUILD-he.md) | דף המשכיות אוטומטי (503 + Retry-After בכל שכבה), rebuild ללא downtime עם `deploy/rebuild.sh`, חלון תחזוקה מוכרז (אופציונלי) |
| [GIT-CREDENTIALS-SECURITY.md](GIT-CREDENTIALS-SECURITY.md) | אין token ב-remote — SSH + rotation |
| [../sales/WEEK-1-GOLIVE-he.md](../sales/WEEK-1-GOLIVE-he.md) | שבוע ראשון אחרי deploy |
| [../sales/COMPANY-READINESS-he.md](../sales/COMPANY-READINESS-he.md) | מצב מוכנות חברה |

**אימות:** `./scripts/go_live_check.sh` מהשורש.
