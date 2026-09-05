# 00 — Sales & Delivery Readiness Audit

**Purpose:** Confirm nothing blocks a commercial handoff — code, docs, legal, ops, and customer experience.

---

## Executive summary (July 2026)

| Area | Status | Notes |
|------|--------|-------|
| **Engine wiring** | ✅ Complete | `verify_engine_wiring.mjs` → 0 gaps; **573 production engine IDs** |
| **UI standard** | ✅ Complete | `weissman-ui-audit.mjs` → **95/95 pages**, **112 routes** |
| **Agent-required UX** | ✅ Complete | Empty state + per-route gates; **48 agent engines** |
| **Billing / quota** | ✅ Complete | All scan & async enqueue paths gated; strict in production |
| **Production security guards** | ✅ Complete | `security_startup.rs` — JWT **≥48 chars**, other secrets **≥32** |
| **Testing & evidence (Phase 6)** | ✅ Complete | Playwright live E2E, 67+ frontend test files, evidence pack generator |
| **Full audit gate (Phase 7)** | ✅ Complete | `bash scripts/full_audit_gate.sh` — G1–G7 global PASS |
| **Docker stack** | ✅ Code-ready | Requires `docker compose up --build` on capable hardware |
| **Legal pages** | ✅ Present | `deploy/public/` — terms, privacy, DPA, subprocessors |
| **Operational runbooks** | ✅ Present | This manual pack + root runbooks |
| **Training (Hebrew ops)** | ✅ **New** | `docs/manuals/he/` full pack |
| **Video / LMS** | ⚠️ Gap | No bundled video course — optional add-on |
| **Paddle catalog live** | ⚠️ Customer-specific | Must set `pri_*` price IDs per deployment |
| **SMTP for signup** | ⚠️ If self-serve | Required when `WEISSMAN_SELF_SERVE_SIGNUP=1` |
| **LLM / vLLM** | ⚠️ Optional module | Council, General Mission need OpenAI-compatible endpoint |
| **OAST server** | ⚠️ Optional module | Separate `weissman-oast-server` for out-of-band verification |

**Verdict:** Platform is **sales-ready for enterprise + MSP** when deployment checklist (manual 18) passes on customer infrastructure. Remaining items are **configuration**, not missing product capability.

---

## What to deliver to every customer

### 1. Software & deployment
- [ ] Git tag / release artifact (Docker images or systemd binaries)
- [ ] Filled `PRODUCTION.env.template` or `.env` (secrets in vault, not email)
- [ ] TLS certificate + reverse proxy config (`deploy/nginx-weissman.conf` or Caddy)
- [ ] Postgres 16 + pgvector, Redis 7
- [ ] Migrations applied (`WEISSMAN_MIGRATE_URL` at boot)

### 2. Documentation (this pack)
- [ ] `docs/manuals/README-en.md` or `README-he.md` (customer language)
- [ ] `SECURITY_AND_COMPLIANCE.md` + `SIG_CAIQ_PREP_QA.md` for procurement
- [ ] `SLA_AND_STATUS.md` (contract may override)
- [ ] `ONBOARDING_RUNBOOK.md` for SOC operators

### 3. Legal & commercial
- [ ] Signed MSA / SOW with **authorized scope**
- [ ] DPA if processing EU personal data (`deploy/public/dpa.html` template)
- [ ] Paddle subscription OR self-hosted unlimited (`WEISSMAN_BILLING_STRICT=0` only with contract)
- [ ] Incident contact + escalation path

### 4. Access & credentials
- [ ] Admin user (not default password)
- [ ] MFA enrollment procedure (manual 07)
- [ ] Agent enrollment tokens (if endpoint engines sold)
- [ ] SSO metadata (if IdP integration sold)

### 5. Acceptance test
- [ ] Manual **18-qa-verification** signed off
- [ ] One authorized client created, one scan completed, findings + PDF exported
- [ ] Agent online (if in scope)

---

## Known gaps & mitigations

| Gap | Impact | Mitigation |
|-----|--------|------------|
| `GETTING_STARTED.md` mentions legacy `changeme` | Confusing for new ops | Use **manual 02** + `PRODUCTION.env.template`; update GETTING_STARTED separately |
| No bundled training videos | Slower adoption | Live kickoff workshop + this manual pack |
| AI features need LLM host | Council/Mission idle | Document `WEISSMAN_LLM_BASE_URL` or tenant `system_configs` |
| Agent binaries per OS/arch | Install fails if not built | Run `scripts/package_agent_binaries.sh` before go-live |
| Weak machine cannot validate Docker build | No runtime proof on dev laptop | Run QA on staging VPS (manual 18) |
| CI uses `changeme` for smoke | Dev-only; not customer-facing | Documented; production guards prevent same |

---

## Sales positioning (accurate claims)

**You CAN claim:**
- **573** production security engine IDs with live probes (313 real_probe + 212 alias + 48 agent_required — no fake findings)
- **112** Command Center routes with live API evidence banners
- Multi-tenant RLS, JWT (≥48 char production) + MFA, RBAC, audit log
- Endpoint agent with 45+ agent-required detection surfaces
- SOAR playbooks, attack-path graph, KEV/EPSS enrichment
- Paddle billing with monthly scan quotas
- Docker, systemd, and Kubernetes deployment paths

**Do NOT claim without customer config:**
- “Fully autonomous AI red team” without LLM endpoint
- “Out-of-band verification” without OAST listener
- “Self-serve signup” without SMTP + DNS + legal pages live
- “99.9% SLA” unless contract + monitoring back it

---

## Pre-demo / inspection checklist (30 minutes)

See **`docs/operations/INSPECTION-DAY-RUNBOOK.md`** for the full 60-minute script (demo + CISO deep dive).

1. `bash scripts/full_audit_gate.sh` → **GLOBAL PASS** (exit 0)
2. `curl -sf https://<host>/api/health` → 200
3. Login → Command Center loads (`POST /api/login`)
4. `GET /api/engines/capabilities` → 573 engine IDs with kind legend
5. Create demo client with **authorized domain only**
6. Run one engine (e.g. `osint`, `asm`) → job completes
7. Findings panel + PDF export + compliance evidence-pack API
8. Hand auditor `./scripts/generate_audit_evidence_pack.sh` artifacts

---

## Related manuals

- [01-platform-overview](01-platform-overview.md)
- [18-qa-verification](18-qa-verification.md)
- [05-production-security](05-production-security.md)
