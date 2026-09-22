# Vendor Viability, Governance & Business-Continuity Package

> Purpose: the artifact a Fortune-500 Third-Party Risk Management (TPRM) team asks for to
> clear the **concentration / key-person / vendor-viability** section of a security review.
> This document is honest about current state and gives the concrete instruments that
> mitigate each risk. Items marked **[ACTION]** require a human/legal step Weissman must
> complete before Fortune-500 GA; items marked **[IN PLACE]** already exist in this repo.

Last updated: 2026-09-22 · Owner: platform maintainer (see `.github/CODEOWNERS`)

---

## 1. Key-person / bus-factor risk (the honest position)

**Current state (do not overstate to a buyer):** the platform has a single human maintainer
and a large share of AI-authored code. A Tier-1 (high-access) buyer treats a single-maintainer
vendor as an automatic finding. We do not hide this; we mitigate it with the instruments below,
and we gate "24×7 on-call" and "Fortune-500 GA" on the second-responder milestone in §2.

| Risk | Mitigation instrument | Status |
|---|---|---|
| Sole maintainer unavailable during a SEV-1 | Named second on-call responder + escalation tree | **[ACTION]** — §2 |
| Loss of the maintainer / company failure | Source-code + build-pipeline **escrow** with defined release conditions | **[ACTION]** — §3 |
| Undocumented tribal knowledge | Architecture Decision Records (`docs/adr/`), runbooks (`docs/operations/`), this package | **[IN PLACE]** (partial) |
| Single approver merges own code | Branch protection requiring a second reviewer | **[ACTION]** — §2 |

## 2. Second-responder & code-review governance **[ACTION]**

The true exit criterion (stated in `.github/CODEOWNERS`) is a **second qualified human**.
Until then, do not contract 24×7×365 response (see `SLA_AND_STATUS.md` §4, now qualified).

Required before Fortune-500 GA:
1. Onboard a second engineer with production and security context; add them to
   `.github/CODEOWNERS` as a co-owner of the crown-jewel paths (auth, DB/RLS, secrets, deploy, CI).
2. Enable branch protection on the default branch: **require 1 review from a different person
   than the author** (four-eyes), require the CI gates (`ci_supply_chain_gate.mjs`, gitleaks,
   semgrep, `cargo test`, `verify_doc_metrics`) to pass, and disallow force-push.
3. Publish a written **succession plan**: who holds the escrow release keys, cloud/root
   credentials custody (in a shared, access-logged secrets manager, not one laptop), and the
   documented "cold-start from escrow" runbook.

## 3. Source-code & deployment-artifact escrow **[ACTION]**

A software escrow agreement directly neutralizes the "company fails / maintainer gone" finding.

- **Agent:** a recognized escrow provider (e.g. NCC Group, Iron Mountain, Codekeeper).
- **Deposit:** the full source repository, build pipeline definitions, infrastructure-as-code
  (the Helm chart in `deploy/helm/`, `deploy/k8s/`), a documented build/run runbook, and the
  dependency lockfiles (`Cargo.lock`, `package-lock.json`) so a licensee can rebuild.
- **Update cadence:** on every tagged release (automatable from CI).
- **Release conditions (verification-of-deposit + trigger events):** vendor bankruptcy/insolvency,
  cessation of maintenance beyond a cure period, or failure to meet a contractual SEV-1
  remediation obligation. Include a **right-to-cure** window before release.
- **Verification:** buyer may request escrow-agent verification that the deposit builds.
- Escrow existence, agent name, and release conditions are disclosed to the buyer under NDA.

## 4. Cyber-liability & professional-indemnity insurance **[ACTION]**

For a vendor with production access to a Fortune-500 environment, procurement typically requires:

| Coverage | Typical minimum for this access tier | Notes |
|---|---|---|
| Cyber liability / data-breach | **USD 5–10M** per occurrence | Names the customer as additional insured on request |
| Technology E&O / professional indemnity | **USD 2–5M** | Covers negligent performance / defects |
| General commercial liability | Per buyer's standard | |

Provide the certificate of insurance (COI) and carrier during procurement. Until bound,
disclose the gap honestly; a liability cap without a **data-breach super-cap** and one-way
indemnity (both current gaps) will be renegotiated by counsel — see §6.

## 5. Legal entity & KYC **[ACTION]**

Counsel cannot execute an MSA/DPA against an unverifiable counterparty.

- **Incorporate** the operating entity and publish the Israeli company registration (ח.פ.) on
  the real entity documents (not "upon incorporation" placeholder language in `deploy/public/terms.html`).
- Fill `deploy/company.details.example.json` → the real `company.details.json` (registered name,
  ח.פ., registered address, authorized signatory, VAT id) and reference it in the Order Form.
- Replace the personal Gmail organization contact in the schema.org blocks and DPA/Terms with a
  **corporate-domain** address (e.g. legal@ / security@ on the company domain).
- Provide most-recent financials or a viability letter for the financial-stability check.

## 6. Contractual gaps to close with counsel **[ACTION]**

Findings from the enterprise-readiness review that are legal-text changes, not code:
- **Data-breach super-cap:** the liability cap must not swallow breach liability at the general cap.
- **Indemnity symmetry:** current one-way indemnity should be made mutual/appropriate.
- **Data return & deletion on termination:** the DPA promises it; the *implementation* is tracked
  in `docs/trust/DATA-LIFECYCLE-AND-DSR.md` (GDPR erasure/portability) and must be wired in code.
- **Sub-processors:** any LLM provider that can receive customer data must be listed as a
  sub-processor with change-notification (see `deploy/public/subprocessors.html`), and the
  either/or infrastructure vendors resolved to the actual ones in use.

---

### Checklist to hand a TPRM reviewer

- [ ] Second on-call responder onboarded; CODEOWNERS co-owner added; four-eyes branch protection on
- [ ] Source-code escrow executed (agent, deposit verified, release conditions) — summary under NDA
- [ ] Cyber + E&O insurance bound; COI available
- [ ] Entity incorporated; ח.פ. + corporate contact published; company.details.json filled
- [ ] MSA/DPA redlines closed with counsel (breach super-cap, mutual indemnity, data-return)
- [ ] Trust Center live (`docs/trust/TRUST-CENTER.md`) with SOC 2 roadmap and sub-processor list
