# MSA + Order Form — Outline (English)

**Status:** Template for legal counsel — not a binding contract until signed.  
**Operator:** Weissman Cybersecurity Ltd., Tel Aviv-Yafo, Israel.

---

## 1. Master Service Agreement (MSA)

| Section | Content |
|---------|---------|
| **Parties** | Weissman Cybersecurity Ltd. ("Provider") and Customer legal entity ("Customer") |
| **Effective date** | Date of last signature |
| **Scope** | Continuous offensive security platform (SaaS or self-hosted) |
| **Authorized testing** | Customer warrants written authorization for all Targets in scope |
| **Order of precedence** | Order Form → DPA → MSA → Terms of Service (`deploy/public/terms.html`) |
| **Term** | Initial term + auto-renewal unless 30-day notice |
| **Fees** | Per Order Form; Paddle or invoice |
| **SLA** | Per plan: 99.5% (Professional) / 99.9% (Enterprise) — see `SLA_AND_STATUS.md` |
| **Support** | Email/Slack; response targets per tier |
| **Data** | Customer owns findings; Provider processes per DPA |
| **Security** | RLS multi-tenant, MFA, audit logs — `SECURITY_AND_COMPLIANCE.md` |
| **Confidentiality** | Mutual NDA provisions |
| **Limitation of liability** | Cap = 12 months fees paid (align with Terms §11) |
| **Indemnification** | Customer for unauthorized scanning; Provider for platform breach negligence |
| **Governing law** | Israel; courts Tel Aviv-Yafo |
| **Termination** | For cause / convenience per Terms |

---

## 2. Order Form (attach to MSA)

| Field | Example |
|-------|---------|
| Customer legal name | Acme Corp Ltd. |
| Billing contact | |
| Plan | Starter / Professional / Enterprise / Self-hosted |
| Deployment | Cloud SaaS / Dedicated / Self-hosted |
| **Authorized scope** | Domains, IP ranges, cloud account IDs (appendix) |
| **ROE** | Business hours only / 24×7 / emergency contact |
| Client quota | e.g. 25 clients |
| Scan quota | e.g. 300 scans/month |
| Data residency | EU-West / US / IL / customer VPC |
| SSO | OIDC / SAML / local only |
| Agent | Yes / No — number of endpoints |
| Price | $___ / month or annual |
| Start date | |
| Signatures | Customer authorized signatory + Weissman |

---

## 3. Statement of Work (SOW) — optional add-on

- Onboarding workshop (N hours)
- Custom engine development
- Red team engagement boundaries
- Deliverables: PDF report, evidence vault export, compliance mapping
- Acceptance criteria: demo scan + findings + sign-off per manual 18

---

## 4. Attachments checklist

- [ ] Signed MSA
- [ ] Signed Order Form with **scope appendix**
- [ ] DPA (`deploy/public/dpa.html` or signed PDF)
- [ ] Sub-processors list (`deploy/public/subprocessors.html`)
- [ ] Security overview (`SECURITY_AND_COMPLIANCE.md`)
- [ ] SLA (`SLA_AND_STATUS.md`)

---

## 5. Internal (Provider) before signature

- [ ] `deploy/company.details.example.json` filled → ח.פ. on Order Form
- [ ] Paddle `pri_*` live for plan
- [ ] Production staging QA signed (manual 18)
- [ ] Sales product book: `docs/sales/viewer/index.html`
