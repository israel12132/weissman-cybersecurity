# 12 — Endpoint Agent

## מטרה

פריסה, enrollment, ותפעול agent (`weissman-agent`) ל-detections על-host, UEBA, ו-~45 מנועי **agent_required**.

---

## דרישות מקדימות

- operator ל-token
- בינארים: `scripts/package_agent_binaries.sh`
- HTTPS `WEISSMAN_PUBLIC_BASE_URL` נגיש מ-endpoints
- firewall — egress WSS
- Windows/Linux ב-scope
- **linux-gnu:** ספריות TSS בזמן ריצה (`libtss2`). ה-installer מתקין אותן ב-apt כשחסרות. בלי זה ה-dynamic linker לא יעלה את התהליך. linux-musl בלי קישור TSS.

---

## ארכיטקטורה

```
Endpoint
  └─ weissman-agent
       ├─ JWT role=agent
       ├─ WebSocket → /ws/agent
       ├─ detections מקומיים
       └─ findings → server

Agent Management — fleet, tokens, scripts
```

תפקיד **`agent`** — נפרד מ-RBAC אנושי (ספר 07).

---

## שלב אחר שלב

### 1. Enrollment token

**Agent Management** → **Generate Token** — client, expiry אופציוני.

### 2. Linux

```bash
curl -sSL https://your-domain.example/install/agent.sh | \
  WEISSMAN_TOKEN="<token>" \
  WEISSMAN_SERVER=https://your-domain.example \
  bash
```

**`GET /install/agent.sh`** — `scripts/agent/install.sh`.

Binary מ-`/install/binaries/:platform/` + SHA256.

### 3. Windows

```powershell
iwr https://your-domain.example/install/agent.ps1 | iex
Install-WeissmanAgent -Token "<token>" -Server "https://your-domain.example"
```

**`GET /install/agent.ps1`**.

### 4. סטטוס fleet

hostname, OS, version, last seen, online/offline.

### 5. מנועי agent-required

**online** → Run נפתח; findings host (persistence, UEBA, ו).

---

## אריזה ל-production

```bash
cargo build --release -p weissman-agent
bash scripts/package_agent_binaries.sh
```

חסר binary ל-OS/arch → כשל install — QA בספר 18.

---

## אבטחת agent

| בקרה | פרט |
|------|-----|
| Tokens | חד-פעמי/מוגבל; revoke ב-UI |
| Transport | TLS |
| Auth | `role=agent`; `require_agent` |
| Scope | client-bound |

---

## Detections / UEBA

process anomalies, persistence, network, config drift — ב-**Findings** עם `engine_id` של agent.

---

## תפעול fleet

| משימה | נוהל |
|--------|------|
| שדרוג | install script מחדש |
| decommission | revoke + uninstall |
| offline | HTTPS/WSS; token |
| mass deploy | GPO/SCCM/Ansible |

---

## אימות

```bash
curl -sf https://your-domain.example/install/agent.sh | head -5
curl -sf -b cookies.txt https://your-domain.example/api/agents/fleet | jq '.agents | length'
```

- [ ] online ב-UI
- [ ] מנוע agent עם findings
- [ ] client נכון
- [ ] token revoked → לא מתחבר

---

## פתרון תקלות

| תסמין | תיקון |
|--------|-------|
| 404 install | `package_agent_binaries.sh` |
| SHA mismatch | rebuild |
| offline | firewall WSS |
| empty engines | token scope |

ראו [17-troubleshooting](17-troubleshooting.md).

---

## ספרים קשורים

- [09-client-onboarding](09-client-onboarding.md)
- [10-scans-engines-jobs](10-scans-engines-jobs.md)
- [05-production-security](05-production-security.md)
- [18-qa-verification](18-qa-verification.md)
