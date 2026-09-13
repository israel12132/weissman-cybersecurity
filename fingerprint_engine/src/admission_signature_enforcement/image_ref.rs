//! OCI / Docker image reference parsing and digest handling.
//!
//! Admission enforcement is only sound if the *identity* of the image being admitted is
//! resolved to an immutable content digest before any signature is trusted. A signature binds
//! a signer to a `sha256:` manifest digest — never to a mutable tag. This module parses image
//! references the way the container runtime and the OCI distribution spec do, so a policy that
//! says "images from `registry.example.com/prod/*` must be signed" matches exactly the strings a
//! kubelet would pull, with no room for a normalization mismatch that could be used to smuggle an
//! unsigned image past the gate.
//!
//! Grammar (subset of the OCI reference grammar, github.com/distribution/reference):
//!   reference  := name [ ":" tag ] [ "@" digest ]
//!   name       := [ host "/" ] path
//!   host       := hostname [ ":" port ]           (has a "." or ":" or == "localhost")
//!   digest     := algorithm ":" hex

use std::fmt;

/// Docker Hub's canonical registry host, injected when a reference has no explicit host.
pub const DEFAULT_REGISTRY: &str = "docker.io";
/// The registry host actually contacted for `docker.io` references.
pub const DEFAULT_REGISTRY_ENDPOINT: &str = "registry-1.docker.io";
/// Namespace prepended to single-segment official images (`nginx` -> `library/nginx`).
pub const OFFICIAL_NAMESPACE: &str = "library";
/// Tag assumed when a reference carries neither a tag nor a digest.
pub const DEFAULT_TAG: &str = "latest";

/// A validated content digest (`algorithm:hex`). Only lower-case hex of the exact length for the
/// algorithm is accepted; this is the anchor every signature is checked against.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Digest {
    algorithm: String,
    hex: String,
}

impl Digest {
    /// Parse and validate `algorithm:hex`. Returns `None` for anything that is not a
    /// canonically-encoded digest (unknown algorithm, wrong length, non-lowercase-hex).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let (algorithm, hex) = s.split_once(':')?;
        let expected = match algorithm {
            "sha256" => 64,
            "sha384" => 96,
            "sha512" => 128,
            _ => return None,
        };
        if hex.len() != expected || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        // Canonical OCI digests are lower-case; reject mixed case so two spellings of the same
        // bytes can never both slip through a policy string comparison.
        if hex.bytes().any(|b| b.is_ascii_uppercase()) {
            return None;
        }
        Some(Self {
            algorithm: algorithm.to_string(),
            hex: hex.to_string(),
        })
    }

    #[must_use]
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    #[must_use]
    pub fn hex(&self) -> &str {
        &self.hex
    }

    /// Raw digest bytes, e.g. the 32 bytes of a `sha256` digest.
    #[must_use]
    pub fn raw(&self) -> Vec<u8> {
        (0..self.hex.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&self.hex[i..i + 2], 16).ok())
            .collect()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.algorithm, self.hex)
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({}:{})", self.algorithm, self.hex)
    }
}

/// A parsed, normalized image reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageReference {
    /// Registry host as written by the operator (`docker.io`, `ghcr.io`, `registry:5000`).
    pub registry: String,
    /// Repository path without the host (`library/nginx`, `prod/api`).
    pub repository: String,
    /// Tag when present (mutually informative with `digest`; a reference may carry both).
    pub tag: Option<String>,
    /// Immutable content digest when the reference is digest-pinned.
    pub digest: Option<Digest>,
    /// The exact input string, retained for audit and evidence records.
    pub original: String,
}

impl ImageReference {
    /// Parse an image reference, applying Docker's normalization rules so the result matches what
    /// the runtime resolves. Returns `None` only for structurally invalid input.
    #[must_use]
    pub fn parse(input: &str) -> Option<Self> {
        let raw = input.trim();
        if raw.is_empty() || raw.len() > 4096 {
            return None;
        }

        // Split the digest suffix first (`@sha256:...`); a digest can only appear once and last.
        let (before_digest, digest) = match raw.split_once('@') {
            Some((head, dig)) => (head, Some(Digest::parse(dig)?)),
            None => (raw, None),
        };
        if before_digest.is_empty() {
            return None;
        }

        // Separate an optional host. A leading segment is a host iff it contains '.', ':' or is
        // exactly "localhost" — otherwise it is part of the repository path (Docker's rule).
        let (host_opt, remainder) = match before_digest.split_once('/') {
            Some((first, rest)) if is_registry_host(first) => (Some(first.to_string()), rest),
            _ => (None, before_digest),
        };

        // The remainder is `path[:tag]`. The tag is only after the LAST '/' segment's colon, so a
        // port in an un-hosted path never confuses tag splitting (there is no port without a host).
        let last_slash = remainder.rfind('/').map_or(0, |i| i + 1);
        let (path, tag) = match remainder[last_slash..].split_once(':') {
            Some((seg, tag)) => {
                let full_path = format!("{}{}", &remainder[..last_slash], seg);
                (full_path, Some(tag.to_string()))
            }
            None => (remainder.to_string(), None),
        };

        if path.is_empty() {
            return None;
        }
        if let Some(t) = tag.as_deref() {
            if !is_valid_tag(t) {
                return None;
            }
        }
        if !is_valid_repository_path(&path) {
            return None;
        }

        let registry = host_opt.unwrap_or_else(|| DEFAULT_REGISTRY.to_string());
        // Official images on Docker Hub gain the implicit `library/` namespace.
        let repository = if registry == DEFAULT_REGISTRY && !path.contains('/') {
            format!("{OFFICIAL_NAMESPACE}/{path}")
        } else {
            path
        };

        Some(Self {
            registry,
            repository,
            tag,
            digest,
            original: raw.to_string(),
        })
    }

    /// The `registry/repository` identity without any tag or digest — the key policy rules match on.
    #[must_use]
    pub fn repository_name(&self) -> String {
        format!("{}/{}", self.registry, self.repository)
    }

    /// True when the reference is pinned to an immutable digest.
    #[must_use]
    pub fn is_digest_pinned(&self) -> bool {
        self.digest.is_some()
    }

    /// The effective tag (`latest` when neither tag nor digest is present).
    #[must_use]
    pub fn effective_tag(&self) -> &str {
        self.tag.as_deref().unwrap_or(DEFAULT_TAG)
    }
}

impl fmt::Display for ImageReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.registry, self.repository)?;
        if let Some(t) = &self.tag {
            write!(f, ":{t}")?;
        }
        if let Some(d) = &self.digest {
            write!(f, "@{d}")?;
        }
        Ok(())
    }
}

/// A leading path segment is a registry host when it looks like one: contains a dot, a port colon,
/// or is exactly `localhost`. This mirrors distribution/reference's `splitDockerDomain`.
fn is_registry_host(seg: &str) -> bool {
    seg == "localhost" || seg.contains('.') || seg.contains(':')
}

fn is_valid_tag(tag: &str) -> bool {
    // OCI tag grammar: 1..=128 chars of [A-Za-z0-9_.-], not starting with '.' or '-'.
    if tag.is_empty() || tag.len() > 128 {
        return false;
    }
    let first = tag.as_bytes()[0];
    if first == b'.' || first == b'-' {
        return false;
    }
    tag.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

fn is_valid_repository_path(path: &str) -> bool {
    if path.is_empty() || path.len() > 255 {
        return false;
    }
    // Each component is lower-case alphanumerics with internal separators (`.`, `_`, `-`).
    path.split('/').all(|component| {
        !component.is_empty()
            && component.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
            })
            && !component.starts_with(['.', '_', '-'])
            && !component.ends_with(['.', '_', '-'])
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_image_gains_library_namespace_and_default_registry() {
        let r = ImageReference::parse("nginx").unwrap();
        assert_eq!(r.registry, "docker.io");
        assert_eq!(r.repository, "library/nginx");
        assert_eq!(r.effective_tag(), "latest");
        assert!(!r.is_digest_pinned());
        assert_eq!(r.repository_name(), "docker.io/library/nginx");
    }

    #[test]
    fn tagged_namespaced_image() {
        let r = ImageReference::parse("bitnami/redis:7.2").unwrap();
        assert_eq!(r.registry, "docker.io");
        assert_eq!(r.repository, "bitnami/redis");
        assert_eq!(r.tag.as_deref(), Some("7.2"));
    }

    #[test]
    fn private_registry_with_port_is_host_not_tag() {
        let r = ImageReference::parse("registry.example.com:5000/prod/api:v1").unwrap();
        assert_eq!(r.registry, "registry.example.com:5000");
        assert_eq!(r.repository, "prod/api");
        assert_eq!(r.tag.as_deref(), Some("v1"));
    }

    #[test]
    fn digest_pinned_reference_parses_and_exposes_raw_bytes() {
        let d = "sha256:".to_string() + &"ab".repeat(32);
        let r = ImageReference::parse(&format!("ghcr.io/org/app@{d}")).unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "org/app");
        assert!(r.is_digest_pinned());
        let digest = r.digest.unwrap();
        assert_eq!(digest.algorithm(), "sha256");
        assert_eq!(digest.raw().len(), 32);
        assert_eq!(digest.raw()[0], 0xab);
    }

    #[test]
    fn tag_and_digest_together() {
        let d = "sha256:".to_string() + &"cd".repeat(32);
        let r = ImageReference::parse(&format!("ghcr.io/org/app:v2@{d}")).unwrap();
        assert_eq!(r.tag.as_deref(), Some("v2"));
        assert!(r.is_digest_pinned());
    }

    #[test]
    fn localhost_is_a_registry_host() {
        let r = ImageReference::parse("localhost/dev/tool:latest").unwrap();
        assert_eq!(r.registry, "localhost");
        assert_eq!(r.repository, "dev/tool");
    }

    #[test]
    fn bad_digests_are_rejected() {
        assert!(Digest::parse("sha256:short").is_none());
        assert!(Digest::parse("sha256:").is_none()); // empty hex
        assert!(Digest::parse(&("sha256:".to_string() + &"AB".repeat(32))).is_none()); // upper-case
        assert!(Digest::parse(&("md5:".to_string() + &"ab".repeat(16))).is_none()); // unknown alg
        assert!(Digest::parse(&("sha512:".to_string() + &"ab".repeat(64))).is_some());
    }

    #[test]
    fn structurally_invalid_references_rejected() {
        assert!(ImageReference::parse("").is_none());
        assert!(ImageReference::parse("   ").is_none());
        assert!(ImageReference::parse("nginx@sha256:zzzz").is_none());
        assert!(ImageReference::parse("UPPER/case").is_none());
        assert!(ImageReference::parse("bad/.leadingdot").is_none());
    }

    #[test]
    fn display_round_trips_normalized_form() {
        let r = ImageReference::parse("ghcr.io/org/app:v1").unwrap();
        assert_eq!(r.to_string(), "ghcr.io/org/app:v1");
    }
}
