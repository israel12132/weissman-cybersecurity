//! Spec §5: the LLM semantic fuzzer must classify the target technology
//! before the first mutation. OpenAPI/discovered paths are preferred; a
//! parseable HTTP(S) URL is sufficient to know the stack family.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TechFingerprint {
    pub label: &'static str,
    pub ready: bool,
}

pub fn fingerprint_target(target: &str) -> TechFingerprint {
    let t = target.trim().to_ascii_lowercase();
    if t.is_empty() {
        return TechFingerprint {
            label: "unknown",
            ready: false,
        };
    }
    if t.contains("graphql") {
        return TechFingerprint {
            label: "graphql",
            ready: true,
        };
    }
    if t.contains("grpc") || t.contains(":50051") {
        return TechFingerprint {
            label: "grpc",
            ready: true,
        };
    }
    if t.contains("swagger") || t.contains("openapi") || t.contains("/api") {
        return TechFingerprint {
            label: "rest_api",
            ready: true,
        };
    }
    if t.starts_with("http://")
        || t.starts_with("https://")
        || t.contains('.')
        || t.parse::<std::net::IpAddr>().is_ok()
    {
        return TechFingerprint {
            label: "http",
            ready: true,
        };
    }
    TechFingerprint {
        label: "unknown",
        ready: false,
    }
}

/// LLM mutation is allowed once we know the technology *or* OpenAPI paths exist.
pub fn allow_llm_mutation(fp: &TechFingerprint, has_openapi_paths: bool) -> bool {
    fp.ready || has_openapi_paths
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_url_is_ready() {
        let fp = fingerprint_target("https://api.example.com/v1");
        assert!(fp.ready);
        assert_eq!(fp.label, "rest_api");
        assert!(allow_llm_mutation(&fp, false));
    }

    #[test]
    fn empty_is_not_ready_without_paths() {
        let fp = fingerprint_target("   ");
        assert!(!fp.ready);
        assert!(!allow_llm_mutation(&fp, false));
        assert!(allow_llm_mutation(&fp, true));
    }
}
