#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Domain {
    Identity,
    Data,
    Network,
    Compute,
    Governance,
}

impl Domain {
    fn as_str(self) -> &'static str {
        match self {
            Domain::Identity => "identity",
            Domain::Data => "data",
            Domain::Network => "network",
            Domain::Compute => "compute",
            Domain::Governance => "governance",
        }
    }
}

#[derive(Clone, Debug)]
struct ComplianceRef {
    cis: &'static str,
    soc2: &'static str,
    iso27001: &'static str,
    pci: &'static str,
    nist: &'static str,
    gdpr: &'static str,
}

#[allow(clippy::too_many_arguments)]
fn posture_finding(
    domain: Domain,
    rule_id: &str,
    title: &str,
    severity: &str,
    mitre: &str,
    compliance: &ComplianceRef,
    target: &str,
    confidence: f64,
    description: &str,
    remediation: &str,
    evidence: Evidence,
    resource_type: &str,
    resource_id: &str,
    region: &str,
) -> Value {
    let mut f = finding_rich(
        ENGINE_ID,
        title,
        severity,
        mitre,
        description,
        target,
        confidence,
        evidence,
    );
    if let Some(obj) = f.as_object_mut() {
        obj.insert("domain".to_string(), json!(domain.as_str()));
        obj.insert("category".to_string(), json!(domain.as_str()));
        obj.insert("rule_id".to_string(), json!(rule_id));
        obj.insert("remediation".to_string(), json!(remediation));
        obj.insert("resource_type".to_string(), json!(resource_type));
        obj.insert("resource_id".to_string(), json!(resource_id));
        obj.insert("region".to_string(), json!(region));
        obj.insert(
            "compliance".to_string(),
            json!({
                "cis_aws": compliance.cis,
                "soc2": compliance.soc2,
                "iso27001": compliance.iso27001,
                "pci_dss": compliance.pci,
                "nist_csf": compliance.nist,
                "gdpr": compliance.gdpr,
            }),
        );
        if !compliance.cis.is_empty() {
            obj.insert("cis_aws".to_string(), json!(compliance.cis));
        }
    }
    f
}

fn map_bucket_location(constraint: Option<&str>) -> String {
    match constraint.unwrap_or("").trim() {
        "" | "US" => "us-east-1".to_string(),
        "EU" => "eu-west-1".to_string(),
        other => other.to_string(),
    }
}

fn port_in_dangerous(from: Option<i32>, to: Option<i32>) -> bool {
    let start = from.unwrap_or(-1);
    let end = to.unwrap_or(start);
    DANGEROUS_PORTS.iter().any(|&p| p >= start && p <= end)
}

// ─── Security Graph (Wiz-style asset + relationship model) ─────────────────────

#[derive(Clone, Debug, Default)]
struct GraphNode {
    id: String,
    kind: String,
    region: String,
    exposure: String,
    risk_tags: Vec<String>,
}

#[derive(Clone, Debug)]
struct GraphEdge {
    from: String,
    to: String,
    rel: String,
}

#[derive(Default)]
struct SecurityGraph {
    nodes: BTreeMap<String, GraphNode>,
    edges: Vec<GraphEdge>,
}

impl SecurityGraph {
    fn upsert(&mut self, id: &str, kind: &str, region: &str, exposure: &str, tags: &[&str]) {
        let node = self.nodes.entry(id.to_string()).or_insert_with(|| GraphNode {
            id: id.to_string(),
            kind: kind.to_string(),
            region: region.to_string(),
            exposure: exposure.to_string(),
            risk_tags: Vec::new(),
        });
        for t in tags {
            if !node.risk_tags.iter().any(|x| x == t) {
                node.risk_tags.push((*t).to_string());
            }
        }
        if exposure == "internet" {
            node.exposure = "internet".to_string();
        }
    }

    fn link(&mut self, from: &str, to: &str, rel: &str) {
        self.edges.push(GraphEdge {
            from: from.to_string(),
            to: to.to_string(),
            rel: rel.to_string(),
        });
    }

    fn is_privileged_identity(node: &GraphNode) -> bool {
        node.kind.contains("iam")
            && node.risk_tags.iter().any(|t| {
                t.contains("admin")
                    || t.contains("wildcard")
                    || t.contains("privileged")
                    || t == "administrator_access"
                    || t == "permissive_trust"
            })
    }

    fn identity_edge_targets(&self, from: &str) -> Vec<&str> {
        self.edges
            .iter()
            .filter(|e| {
                e.from == from
                    && (e.rel == "assumes_role"
                        || e.rel == "execution_role"
                        || e.rel == "assumes")
            })
            .map(|e| e.to.as_str())
            .collect()
    }

    /// Follow identity edges from an internet-exposed asset to over-privileged IAM targets (1–2 hops).
    fn privileged_identity_peers(&self, from: &str) -> Vec<&GraphNode> {
        let mut out = Vec::new();
        let mut seen = BTreeSet::new();

        for hop1 in self.identity_edge_targets(from) {
            if let Some(n) = self.nodes.get(hop1) {
                if Self::is_privileged_identity(n) && seen.insert(hop1.to_string()) {
                    out.push(n);
                }
            }
            for hop2 in self.identity_edge_targets(hop1) {
                if let Some(n) = self.nodes.get(hop2) {
                    if Self::is_privileged_identity(n) && seen.insert(hop2.to_string()) {
                        out.push(n);
                    }
                }
            }
        }
        out
    }

    fn internet_exposed_nodes(&self) -> Vec<&GraphNode> {
        self.nodes
            .values()
            .filter(|n| n.exposure == "internet")
            .collect()
    }

    fn to_json(&self) -> Value {
        json!({
            "node_count": self.nodes.len(),
            "edge_count": self.edges.len(),
            "nodes": self.nodes.values().map(|n| json!({
                "id": n.id,
                "kind": n.kind,
                "region": n.region,
                "exposure": n.exposure,
                "risk_tags": n.risk_tags,
            })).collect::<Vec<_>>(),
            "edges": self.edges.iter().map(|e| json!({
                "from": e.from,
                "to": e.to,
                "relationship": e.rel,
            })).collect::<Vec<_>>(),
        })
    }
}

