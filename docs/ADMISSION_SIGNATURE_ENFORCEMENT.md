# Admission Signature Enforcement

> Engine id: `admission_signature_enforcement` · crate module:
> [`fingerprint_engine/src/admission_signature_enforcement/`](../fingerprint_engine/src/admission_signature_enforcement/)
> · MITRE ATT&CK: **T1610 Deploy Container** (blocks **T1525 Implant Internal
> Image**).

Cryptographic verification and approval of container images **before** they are
allowed to run in a Kubernetes cluster — the control every serious platform
aims for: nothing runs unless a trusted party has cryptographically vouched for
the **exact bytes** of the image.

This is defensive security. It answers a single admission-time question with a
cryptographic proof rather than a policy label:

> *Is the image in this Pod signed, by an identity we trust, over the exact
> digest we are about to run — and was that signature publicly logged?*

**No mock data.** Every branch is real OpenSSL / RFC 6962 math. The engine's
posture findings come from live read-only probes; its capability proof is a
self-test that runs the decision engine over freshly-generated keys; its
hardening bundle is `kubectl apply`-ready configuration.

---

## 1. Why this is subtle (the bypasses it refuses to allow)

A signature gate that "checks a signature" is easy to build and easy to bypass.
The value is in the obligations that are usually skipped:

| Bypass | How it works | How this engine refuses it |
|--------|--------------|----------------------------|
| **Confused deputy** | Present a valid signature over *another* image. | The cosign payload's `docker-manifest-digest` must equal the admitted digest ([`simple_signing`](../fingerprint_engine/src/admission_signature_enforcement/simple_signing.rs)). |
| **Mutable tag** | Sign `:latest`, then repoint the tag to a malicious image. | Enforcement requires a `sha256:` digest; unpinned tags are denied ([`admission`](../fingerprint_engine/src/admission_signature_enforcement/admission.rs)). |
| **initContainers gap** | Hide the payload in an init or ephemeral container. | Every container of every workload kind is extracted and checked. |
| **Fail open** | `failurePolicy: Ignore` — disrupt the webhook, deploy freely. | The rendered `ValidatingWebhookConfiguration` is `failurePolicy: Fail`; the posture probe flags any `Ignore`. |
| **Issuer swap** | Get a Fulcio cert for the same SAN from a *different* OIDC provider. | Keyless identity pins **both** SAN subject and OIDC issuer ([`fulcio`](../fingerprint_engine/src/admission_signature_enforcement/fulcio.rs) + [`der`](../fingerprint_engine/src/admission_signature_enforcement/der.rs)). |
| **Expired-cert replay** | Use a since-revoked identity's old signature. | Keyless requires a verified Rekor inclusion proof + SET; the cert is validated against the log's `integratedTime`, not wall-clock now ([`rekor`](../fingerprint_engine/src/admission_signature_enforcement/rekor.rs)). |
| **Default allow** | Deploy an image no rule mentions. | `default_action` is **Deny**; unverifiable input fails closed. |

---

## 2. Architecture (bottom-up)

| Layer | Module | Responsibility |
|-------|--------|----------------|
| Identity | `image_ref` | Parse OCI references (distribution/reference rules); resolve to an immutable `sha256:` digest — the anchor of every signature. |
| Primitive | `keyring` | Multi-algorithm signature verification over OpenSSL: ECDSA P-256/SHA-256, P-384/SHA-384, Ed25519, RSA PKCS#1 v1.5, RSA-PSS. Cosign key-ids (SHA-256 of DER SPKI). |
| Cosign | `simple_signing` | Verify a keyed cosign signature **and** that its payload names the admitted digest and carries the cosign signature type. |
| Attestation | `dsse` | DSSE PAE (`DSSEv1 …`) + in-toto Statement: verify SLSA provenance / SBOM attestations, bound to the image subject digest and predicate type. |
| Transparency | `rekor` | RFC 6962 Merkle inclusion proof (`RootFromInclusionProof`) + Signed Entry Timestamp over the canonical log entry. |
| Keyless | `fulcio` | Verify a Fulcio X.509 chain to a trusted root (validity checked at log time, not now), extract SAN + the issuer extension. |
| Policy | `policy` | What "signed" means for which images/namespaces; fail-closed defaults, N-of-M authorities, required attestations, exemptions, audited break-glass. |
| Decision | `admission` | Kubernetes `AdmissionReview` → allow/deny across every container of every workload kind, with a tamper-evident audit id. |
| Engine | `posture` | Live read-only posture probes, a cryptographic control self-test, and a ready-to-apply enforcement bundle. |

The verification primitives are re-exported from the module root so sibling
engines (`cicd_pipeline`, `container_registry`, `supply_chain`) can reuse the
same trust core.

---

## 3. The admission decision

`admission::evaluate_admission(review, policy, trust, evidence)` is the pure,
deterministic core:

1. **Namespace exemption** → allow, recorded on the decision.
2. **Break-glass** (annotation-gated) → allow, recorded as `break_glass`, never
   a silent allow.
3. **Extract images** from Pods and all workload controllers (Deployment,
   StatefulSet, DaemonSet, ReplicaSet, ReplicationController, Job, CronJob),
   across `initContainers`, `containers`, and `ephemeralContainers`.
4. For each image: resolve the policy rule (first match wins; no match →
   `default_action`). For a `Signed` requirement:
   - require a digest (deny unpinned tags),
   - satisfy `threshold` of the listed **authorities** (keyed and/or keyless),
   - satisfy every required **attestation** predicate,
   - verify the **transparency log** when required (always, for keyless).
5. Aggregate: admit iff **every** image is admitted. The decision carries a
   per-image reason and a SHA-256 **audit id** over its stable projection.

The `AdmissionResponse` echoes the request `uid`, sets `allowed`, and on denial
returns HTTP 403 with reason `AdmissionSignatureEnforcementDenied`.

### Evidence

Signature material — cosign signatures, Fulcio certs, DSSE attestations, Rekor
bundles — is supplied through the `EvidenceProvider` trait. The default
`EmptyEvidenceProvider` yields nothing, so a `Signed` requirement with no
evidence **denies** (the safe direction). Production wires this to a live
registry + Rekor fetch; tests and dry-runs use `StaticEvidenceProvider`.

---

## 4. Policy

Policies are JSON/YAML (`policy::AdmissionPolicy`). Hardened defaults:

```yaml
default_action: deny            # unmatched images are refused
rules:
  - name: require-keyless-signature-all-images
    image_glob: "*"
    requirement:
      kind: signed
      threshold: 1
      require_transparency_log: true
      authorities:
        - type: keyless
          identities:
            - subject_regexp: "https://github.com/acme/.+/.github/workflows/.+@refs/heads/main"
              issuer: "https://token.actions.githubusercontent.com"
namespace_exemptions: ["kube-system"]
```

- **N-of-M signers**: list M authorities, set `threshold: N`.
- **Keyed authorities** pin cosign key-ids; **keyless** pin SAN subject
  (exact or anchored regexp) **and** OIDC issuer.
- **Attestations**: require an in-toto `predicateType` (e.g.
  `https://slsa.dev/provenance/v1`) signed by an accepted authority.
- **Break-glass** is an explicit, annotated, audited bypass — never a default.

`AdmissionPolicy::hardened_starter(subject_regexp, issuer)` renders the
secure-by-default policy the engine ships in its bundle.

---

## 5. Running the engine

```bash
# Via the command center / orchestrator (engine id):
admission_signature_enforcement   target = https://<api-server-host>

# Tunable job_params:
#   api_ports:                     [6443, 443, 8443, 16443]
#   timeout_ms:                    8000
#   certificate_identity_regexp:   subject regexp for the rendered policy
#   certificate_oidc_issuer:       OIDC issuer for the rendered policy
```

The engine emits three classes of finding:

1. **Live posture** (real observations only): API server reachability, anonymous
   discovery of the admission API group, anonymously-readable
   `ValidatingWebhookConfigurations` (a serious RBAC gap), missing signature
   webhook, and `failurePolicy: Ignore` (fail-open) — each backed by an HTTP
   observation.
2. **Cryptographic control self-test** (`advisory`): the decision engine is run
   over a freshly generated key with four adversarial cases — correctly signed
   (admit), forged signature (deny), valid signature over a **different** digest
   (deny), and unsigned (deny). This proves the core is sound and fail-closed
   before it is relied upon.
3. **Hardened enforcement bundle** (`advisory`): a `kubectl apply`-ready
   `ValidatingWebhookConfiguration` (fail-closed), a Sigstore policy-controller
   `ClusterImagePolicy` (keyless + transparency log, `mode: enforce`), and the
   machine-readable `AdmissionPolicy`.

Findings that are not backed by a live probe are labelled `advisory` in their
evidence, consistent with the platform's honesty contract.

---

## 6. Deploying enforcement in a cluster

The bundle rendered by the engine is the production wiring. Two supported paths:

- **Sigstore policy-controller** — apply the emitted `ClusterImagePolicy`; the
  controller admits only images matching the keyless identity with a verified
  transparency-log entry.
- **This engine as the webhook backend** — serve `admission::evaluate_admission`
  behind the emitted `ValidatingWebhookConfiguration` (`/validate`,
  `failurePolicy: Fail`), backed by an `EvidenceProvider` that fetches cosign
  signatures/attestations from the registry and their Rekor bundles.

Either way: `kube-system` is excluded, the webhook is fail-closed, and keyless
trust requires the transparency log.

---

## 7. Tests

Every module carries unit tests exercising the real crypto and the bypasses:

```bash
cargo test -p fingerprint_engine --lib admission_signature_enforcement
```

Coverage includes: OCI reference normalization; multi-algorithm sign/verify
round-trips and forgeries; cosign digest-mismatch rejection; DSSE PAE spec
vector + tampered-payload rejection; RFC 6962 inclusion proofs across tree sizes
1..17 with SET verification; Fulcio chain + validity-window + untrusted-root
rejection; identity issuer-pinning (the forgery case); and end-to-end admit/deny
decisions including fail-closed, digest-required, exemption, and break-glass.
