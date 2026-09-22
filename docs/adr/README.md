# Architecture Decision Records (ADRs)

Short, durable records of the load-bearing architecture decisions — so the reasoning
behind the security model is not single-homed in one maintainer's head (roadmap step
11 / bus-factor). Add a new numbered file when a decision is hard to reverse or
security-relevant; keep each one to context / decision / enforcement / consequences.

| ADR | Title |
|-----|-------|
| [0001](0001-multi-tenant-and-customer-isolation.md) | Multi-tenant and customer (MSSP) data isolation |
| [0002](0002-authentication-rbac-and-secrets.md) | Authentication, RBAC, and secrets-at-rest |
| [0003](0003-dedicated-single-tenant-tier.md) | Dedicated (single-tenant) deployment tier vs logical (shared-RLS) tier |

Reviewer note: changes to the paths in `.github/CODEOWNERS` (isolation, migrations,
auth, deploy, engines) require a named human review. The standing exit criterion for
the bus-factor risk is a **second** qualified reviewer added to CODEOWNERS — this
file and the ADRs reduce the knowledge risk but do not remove the single-reviewer
one. The canonical GitHub remote retains full, un-shallowed history for audit.
