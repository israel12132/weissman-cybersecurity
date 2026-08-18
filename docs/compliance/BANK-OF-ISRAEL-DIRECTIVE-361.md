# Weissman Cybersecurity — מיפוי לחוזר בנק ישראל 361

**גרסה:** 1.0 | **עודכן:** 2026-08-18  
**מטרה:** מסמך זה ממפה את בקרות האבטחה ודרישות הניהול של פלטפורמת Weissman לדרישות חוזר ניהול תקין 361 של בנק ישראל ("ניהול הסיכון הטכנולוגי").  
**קהל יעד:** CISO, CRO, וועדת ביקורת, רגולטורים.

---

## 1. רקע — חוזר 361

חוזר בנק ישראל 361 קובע מסגרת לניהול סיכונים טכנולוגיים בתאגידים בנקאיים, כולל:
- ניהול סיכוני סייבר
- המשכיות עסקית (BCP/DR)
- ניהול ספקים קריטיים (Outsourcing)
- הגנת מידע והפרדת לקוחות
- ניטור ובקרה שוטפת

---

## 2. מיפוי בקרות

### 2.1 ניהול סיכוני סייבר (סעיף 5)

| דרישת חוזר 361 | בקרה בפלטפורמה | מיקום בקוד / מסמך |
|---|---|---|
| מיפוי נכסי מידע קריטיים | 563 מנועי סריקה, מיפוי לפי MITRE ATT&CK | `scripts/verify_engine_wiring.mjs` |
| הערכת סיכון שוטפת | סריקה אוטומטית ב-tenant intervals + intelligence feeds | `fingerprint_engine/src/orchestrator.rs` |
| תגובה לאירוע (SIRT) | SEV-1 ≤ 15 דקות, SEV-2 ≤ 1 שעה, 24/7 on-call | `SLA_AND_STATUS.md` §4, `docs/operations/INCIDENT-ONCALL-RUNBOOK-he.md` |
| בקרת גישה לפי צורך (Least Privilege) | RBAC 5 רמות: `viewer < analyst < operator < admin < ceo` | `fingerprint_engine/src/rbac.rs` |
| אימות רב-שלבי (MFA) | TOTP מאומת, ניתן לאכיפה per-tenant | `fingerprint_engine/src/auth_mfa.rs` |
| SSO / SAML לסביבת ארגונית | OIDC (PKCE) + SAML 2.0 עם JIT provisioning | `fingerprint_engine/src/oidc_auth.rs`, `saml_auth.rs` |
| הצפנת נתונים in-transit | TLS enforced, HTTPS-only, Secure cookies (`WEISSMAN_COOKIE_SECURE=1`) | `deploy/Caddyfile.staging`, `docker-compose.staging.yml` |
| הצפנת נתונים at-rest | PostgreSQL על-גבי EBS מוצפן; גיבויים AES-256 | `docs/operations/DISASTER-RECOVERY.md` |
| ניהול פגיעויות | CVE feeds (NVD/CISA KEV), סריקה אוטומטית, dashboard findings | `fingerprint_engine/src/intel_engine.rs` |
| ניטור ואיתור חריגות | Prometheus + Grafana + Alertmanager, rules ב-`monitoring/alerts/` | `monitoring/` |
| Penetration testing | DAST (OWASP ZAP) בכל CI pipeline | `.github/workflows/ci.yml` |

### 2.2 המשכיות עסקית ו-DR (סעיף 6)

| דרישת חוזר 361 | בקרה בפלטפורמה | מסמך |
|---|---|---|
| RTO (Recovery Time Objective) | **≤ 4 שעות** לשחזור מלא | `docs/operations/DISASTER-RECOVERY.md` |
| RPO (Recovery Point Objective) | **≤ 1 שעה** (PITR + WAL ב-S3) | `scripts/backup_pitr_setup.sh` |
| תרגיל DR תקופתי | `scripts/backup_restore_verify.sh` — חובה כל 48 שעות | `scripts/backup_restore_verify.sh` |
| Multi-AZ / HA | PostgreSQL HA (`deploy/k8s/postgres-ha.yaml`), Redis HA, HPA | `deploy/k8s/` |
| Runbook אחזור מלא | הוראות שלב-אחר-שלב בעברית | `docs/operations/DISASTER-RECOVERY.md` |

### 2.3 הפרדת נתוני לקוחות (סעיף 7)

| דרישת חוזר 361 | בקרה בפלטפורמה | מיקום בקוד |
|---|---|---|
| בידוד מלא בין tenant-ים | PostgreSQL Row-Level Security מאולץ על 80+ טבלאות | `crates/weissman-db/src/lib.rs` (`begin_tenant_tx`) |
| GUC לכל transaction | `SET app.current_tenant_id = $id` לפני כל פעולה | `crates/weissman-db/src/lib.rs` |
| חסימה ברמת DB | Postgres חוסם cross-tenant גם עם bug בקוד | בדיקות RLS: `cargo test --test rls_contract` |
| Audit trail לכל כתיבה | `audit_logs(tenant_id, user_id, action_type, ip, ts)` | `fingerprint_engine/src/audit_log.rs` |
| רישום שאילתות AI | `nl_query_audit` — כל `/api/ask` נרשם עם SQL | `fingerprint_engine/src/nl_query_audit.rs` |

### 2.4 ניהול ספקים קריטיים / Outsourcing (סעיף 9)

| דרישת חוזר 361 | מענה |
|---|---|
| הסכם עיבוד נתונים (DPA) | `deploy/public/dpa.html` — כולל SCCs (Module 2) |
| רשימת Sub-processors | `deploy/public/subprocessors.html` |
| זכות ביקורת (Audit rights) | מפורט ב-MSA: `docs/legal/MSA-ORDER-FORM-OUTLINE-he.md` §8 |
| הפסקת שירות ויציאת נתונים | הוראות export + data portability ב-MSA |
| SLA מוגדר | 99.95% uptime, SEV-1 ≤ 15 דקות | `SLA_AND_STATUS.md` |
| מיקום עיבוד הנתונים | Region `IL` — ישראל בלבד לבנקים ישראלים | `SLA_AND_STATUS.md` §6 |

### 2.5 ניטור, לוגינג ובקרת שינויים (סעיף 8)

| דרישת חוזר 361 | בקרה | מיקום |
|---|---|---|
| לוגים מבניים ל-SIEM | JSON structured logging (`WEISSMAN_LOG_FORMAT=json`), Filebeat | `monitoring/filebeat.yml` |
| שמירת לוגים | Retention policies: 14–30 יום ברמת application, ניתן להרחבה | `fingerprint_engine/src/retention.rs` |
| Metrics ל-SOC | Prometheus scrape `/api/metrics` | `backend/weissman-server/src/metrics.rs` |
| בקרת שינויים (Change Management) | CI/CD עם gate G1–G7; כל merge דורש PR + CI green | `scripts/full_audit_gate.sh` |
| Vulnerability management | SBOM + dependency scan (cargo-deny, Trivy, Semgrep, CodeQL) | `.github/workflows/ci.yml` |

---

## 3. דרישות שנותרו לאחריות הלקוח / הארגון

הדרישות הבאות הן **ארגוניות** ואינן ניתנות לספק:

| דרישה | אחראי | הערות |
|---|---|---|
| SOC 2 Type II / ISO 27001 — אישור רשמי | הארגון + מבקר חיצוני | Weissman מספקת evidence pack |
| מינוי CISO רשמי | הארגון | נדרש לפי חוזר 361 §3.2 |
| ועדת סייבר של הדירקטוריון | הארגון | נדרש לפי חוזר 361 §3.1 |
| תוכנית BCP ארגונית | הארגון | Weissman מספקת DR runbook טכני |
| הסכם MSA חתום | עו"ד שני הצדדים | `docs/legal/MSA-ORDER-FORM-OUTLINE-he.md` |
| הגדרת alert delivery (PagerDuty/Slack) | Ops הארגון | `monitoring/secrets/README.md` |
| תרגיל disaster recovery | Ops הארגון | כל 48 שעות ב-production |

---

## 4. Evidence Pack לביקורת

```bash
# יוצר חבילת ביקורת מלאה (JSON + PDF):
bash scripts/generate_audit_evidence_pack.sh

# Gate G1–G7 — חייב לצאת 0:
bash scripts/full_audit_gate.sh

# RLS contract tests:
cargo test --workspace --test rls_contract

# Engine wiring — 0 gaps:
node scripts/verify_engine_wiring.mjs
```

---

## 5. נספח — מיפוי MITRE ATT&CK לדרישות 361

| מיפוי 361 | MITRE Tactic | כיסוי Weissman |
|---|---|---|
| Initial Access | TA0001 | 47 real_probe engines |
| Lateral Movement | TA0008 | 38 real_probe engines |
| Exfiltration | TA0010 | 31 real_probe engines |
| Impact | TA0040 | 29 real_probe engines |
| **סה"כ כיסוי** | **14/14 tactics** | **303 real_probe + 212 alias engines** |

ראו `docs/attack-navigator/` לקובץ MITRE ATT&CK Navigator מלא.

---

*מסמך זה מיוצר אוטומטית כחלק מ-evidence pack. לאימות נתונים: `bash scripts/generate_audit_evidence_pack.sh`.*
