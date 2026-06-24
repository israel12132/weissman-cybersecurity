# 15 — Alerting, SOAR & AI

## מטרה

הגדרת alert rules, SOAR playbooks, paging, מודולי AI (Supreme Council, General Mission) לתפעול SOC פרואקטיבי.

---

## דרישות מקדימות

- operator ל-alerts/playbooks
- admin ל-AI
- אופציוני: `WEISSMAN_ALERT_WEBHOOK_URL`, `WEISSMAN_PAGER_WEBHOOK_URL`
- LLM: `WEISSMAN_LLM_BASE_URL`, `OPENAI_API_KEY`
- Redis

---

## ארכיטקטורת alerting

```
Finding / PoE / Job
  → rule evaluation
  → webhook / email / page / SOAR
  → audit
```

| משתנה | תפקיד |
|--------|--------|
| `WEISSMAN_ALERT_WEBHOOK_URL` | Slack, Teams |
| `WEISSMAN_PAGER_WEBHOOK_URL` | PagerDuty |
| `WEISSMAN_SMTP_*` | email |

---

## שלב אחר שלב: alert rules

### 1. Alerting dashboard

Command Center → **Alerting**

### 2. יצירת rule

דוגמאות:

- severity = Critical
- KEV present
- engine ב-set מסוים
- client ספציפי

### 3. Actions

| Action | שימוש |
|--------|------|
| `webhook` | Slack |
| `email` | POC |
| `page_oncall` | 24/7 |
| `soar_playbook` | automation |

### 4. בדיקה (staging)

finding בדיקה / test button. cooldown против spam.

### 5. production

תיעוד ב-runbook; יישור עם ניטור הלקוח.

---

## SOAR playbooks

`soar_playbook.rs` — tickets, enrichment, notify, containment (destructive).

### בנייה

**Playbook Builder** → New:

1. trigger
2. steps + conditions
3. failure handling
4. publish
5. קישור מ-rule

Destructive (`containment_execute`, `deception_deploy`):

```
X-Weissman-Destructive-Confirm: <WEISSMAN_DESTRUCTIVE_CONFIRM_SECRET>
```

ספר **05**.

---

## Supreme Council (AI)

`/api/ceo/council/*`, job `council_debate`.

```bash
WEISSMAN_LLM_BASE_URL=https://your-llm/v1
OPENAI_API_KEY=sk-...
WEISSMAN_COUNCIL_MODEL_*=gpt-4o-mini
WEISSMAN_EMBEDDINGS_MODEL=text-embedding-3-small
```

ללא LLM — תור בלי synthesis (ספר 00).

SSE: `/api/ceo/council/sessions/{uuid}/stream`.

---

## General Mission (CEO)

`/command-center/ceo` — strategy, war room.

**`ceo` role** בלבד (ספר 07).

---

## Predictive / NL query

| תכונה | env |
|--------|-----|
| Ask Weissman | `WEISSMAN_NL_QUERY_MODEL` |
| Sovereign self-scan | `WEISSMAN_SOVEREIGN_SELF_SCAN_INTERVAL_SECS` (min 300) |

```bash
WEISSMAN_READ_ONLY_DATABASE_URL=postgres://weissman_ro:...
```

בלי URL — `/api/ask` → 503.

---

## אימות

```bash
curl -X POST "$WEISSMAN_ALERT_WEBHOOK_URL" \
  -H 'Content-Type: application/json' \
  -d '{"test":true,"source":"weissman-qa"}'
curl -sf "${WEISSMAN_LLM_BASE_URL}/models" -H "Authorization: Bearer $OPENAI_API_KEY"
```

- [ ] rule על Critical test
- [ ] webhook התקבל
- [ ] playbook non-destructive
- [ ] Council עם LLM
- [ ] CEO חסום ל-non-CEO

---

## פתרון תקלות

| תסמין | תיקון |
|--------|-------|
| alerts שקטים | conditions; URL |
| alert storm | cooldown |
| playbook תקוע | logs; creds |
| Council 503 | LLM |
| destructive 403 | header |

ראו [17-troubleshooting](17-troubleshooting.md).

---

## ספרים קשורים

- [05-production-security](05-production-security.md)
- [06-environment-configuration](06-environment-configuration.md)
- [07-authentication-rbac-mfa](07-authentication-rbac-mfa.md)
- [11-findings-reports](11-findings-reports.md)
- [13-integrations-cicd](13-integrations-cicd.md)
- [16-operations-monitoring](16-operations-monitoring.md)
