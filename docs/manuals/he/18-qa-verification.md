# 18 — QA & Verification (קבלה לפני מסירה)

## מטרה

Sign-off לפני handoff או go-live. מאמת wiring, UI, guards, smoke end-to-end, ו**חבילת ראיות לביקורת**.

---

## שער ראשי — להריץ קודם

```bash
bash scripts/full_audit_gate.sh
```

**Pass:** exit 0, `GLOBAL PASS`. מאגד G1–G7 (בנייה, בדיקות, lint, wiring, reality, migrations, live + evidence).

---

## דרישות מקדימות

- staging כ-production
- `WEISSMAN_ENV=production` (מומלץ)
- JWT **≥48 תווים**; סודות metrics/destructive/job-bus **≥32**
- פריסה מלאה (Docker/systemd/K8s)
- admin + MFA

---

## סקריפטים אוטומטיים

### 1. Engine wiring

```bash
node scripts/verify_engine_wiring.mjs
```

**Pass:** exit 0. **563 מנועים**, 0 gaps.

### 2. Engine reality

```bash
node scripts/engine_reality_audit.mjs
```

**Pass:** 0 `no_path`. **300** real_probe, **213** alias, **45** agent_required.

### 3. UI audit

```bash
node scripts/weissman-ui-audit.mjs
```

**Pass:** **95/95** דפים, **112/112** נתיבים.

### 4. Rust + Frontend

```bash
cargo test --workspace --all-targets
cd frontend && npm run test:coverage
```

### 5. Playwright live (שלב 6)

```bash
./scripts/run_playwright_live_e2e.sh
```

### 6. Evidence pack (שלב 6)

```bash
./scripts/generate_audit_evidence_pack.sh
```

### 7. Go-live

```bash
./scripts/go_live_check.sh
```

---

## אימות אבטחה

| בדיקה | Pass |
|-------|------|
| JWT < 48 → refuse boot | blocked |
| secure cookies + HTTPS | Secure flag |
| metrics ללא token → 401 | 401 |
| destructive ללא header → 403 | 403 |

ראו ספר **05**.

---

## Sign-off

```
  [ ] full_audit_gate.sh — GLOBAL PASS
  [ ] 563 engine IDs, 112 routes, 0 gaps
  [ ] evidence-pack JSON + PDF
  [ ] login + scan + findings + PDF
```

---

## קשור

- [00-sales-delivery-readiness](00-sales-delivery-readiness.md)
- [05-production-security](05-production-security.md)
- [Inspection Day Runbook](../../operations/INSPECTION-DAY-RUNBOOK.md)
