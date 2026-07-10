# Security Policy

Weissman Cybersecurity builds offensive-security and active-defence tooling, so we hold
our own platform to the standard we sell. We welcome coordinated disclosure of any
vulnerability in this repository or a Weissman-operated deployment.

## Reporting a vulnerability

- **Email:** <security@weissman.io> (primary channel).
- **Machine-readable contacts:** [`/.well-known/security.txt`](deploy/public/.well-known/security.txt) (RFC 9116).
- **Full policy & acknowledgements:** <https://weissman.io/security-policy.html>.

Please include: affected component (server / worker / agent / engine / frontend), version
or commit, a minimal reproduction, and the impact you observed. Do **not** open a public
GitHub issue for a security report.

We aim to:

| Stage | Target |
|-------|--------|
| Acknowledge receipt | within **2 business days** |
| Triage + severity | within **5 business days** |
| Fix or mitigation for critical issues | as fast as safely possible; status updates until resolved |

## Scope

In scope: the code in this repository and Weissman-operated production/staging endpoints
you are explicitly authorised to test. Out of scope: denial-of-service, social
engineering of staff, physical attacks, and testing against tenants or targets you do not
own or have written authorisation to assess. Respect the platform's own scope-validation
and rate-limit controls during testing.

## Safe harbour

We will not pursue or support legal action against researchers who, in good faith:

- make a genuine effort to avoid privacy violations, data destruction, and service
  degradation;
- only interact with accounts/tenants they own or have permission to test;
- give us a reasonable time to remediate before any public disclosure.

If in doubt about whether an action is authorised, email us first and ask.

## Supported versions

The `main` branch and the most recent tagged release receive security fixes. Older tags
are supported on a best-effort basis for critical issues only.

## Handling of platform findings

Vulnerabilities we confirm are tracked internally, fixed on a private branch where
necessary, and disclosed in [`CHANGELOG.md`](CHANGELOG.md) once a fix ships. Reporters are
credited on the security-policy page unless they request anonymity.
