//! File Upload Security Engine — breakthrough-grade, agentless unrestricted-file-upload assessment.
//!
//! Exceeds PortSwigger Upload Labs + OWASP WSTG-INPV-012 + enterprise ASM (Salt/Escape-class API upload
//! coverage) with **live evidence only** — every finding requires an observed HTTP signal.
//!
//!   * **Omnichannel endpoint discovery** — HTML forms, OpenAPI 3 JSON parse, JS bundle URL harvest,
//!     WordPress/Drupal/Laravel/CMS paths, presigned-URL hints, GraphQL multipart (`Upload` scalar),
//!     base64-JSON upload APIs, Tus/resumable headers, operator wordlists.
//!   * **Stack-aware bypass packs** — PHP (.php5/.phar/.phtml), IIS (`.aspx;.jpg`, semicolon), ASP.NET
//!     (web.config, .cer), Java (.jsp/.jspx), Node static-exec surface, NTFS ADS (`::$DATA`), Unicode
//!     homoglyphs, RFC5987 `filename*`, double Content-Disposition, empty/octet-stream MIME.
//!   * **Benign canaries only** — GIF/JPEG/PDF/ZIP polyglots, SVG XSS *surface*, `.htaccess` markers;
//!     never weaponized shells. Optional ZIP-slip *response* detection when archive extraction echoes paths.
//!   * **Storage forensics** — JSON url extraction, deterministic storage-path oracle (`/uploads/`, `/media/`,
//!     `/wp-content/uploads/`, …), retrieval Content-Type / `X-Content-Type-Options` / CORS / inline disposition.
//!   * **Attack-path synthesis + 23-dimension posture grade** — toxic combinations (upload→retrieve→execute,
//!     config overwrite, stored XSS, IDOR on stored objects) with MITRE/CWE mapping per category.
//!   * **World-first extensions (no competitor parity)** — upload IDOR oracle (numeric object IDs in JSON responses),
//!     Tus/resumable upload (`Tus-Resumable`), WebDAV OPTIONS/PROPFIND surface, auth differential (anonymous vs
//!     session), Unicode homoglyph filenames, multipart HPP (dual file fields), size-limit oracle (413 fingerprint),
//!     presigned-URL extraction + HEAD probe, directory listing on storage roots, `.user.ini` / crossdomain policy
//!     upload surface, Content-Range chunked write, blast-radius sub-score.
//!   * **Next wave (no ASM/DAST parity)** — unauthenticated download after authenticated upload, URL-encoded
//!     extension bypass (`.%70hp`), long-filename parser stress, JPEG-COM/mini-DOCX macro-surface probes,
//!     CDN cache isolation on retrieved objects, WAF rejection fingerprint, robots/sitemap upload hints,
//!     CRLF filename reflection oracle, toxic-combination auto-escalation, live probe-coverage manifest.
//!   * **Ultra wave** — reverse double-extension (`.jpg.php`), IIS handler surface (`.ashx`/`.asmx`/`.shtml`),
//!     `.htpasswd` credential file upload, double-URL-encoding traversal, SSTI filename oracle (`{{7*7}}`),
//!     CORS misconfiguration on upload POST, rate-limit absence fingerprint, verbose error disclosure on
//!     malformed multipart, unauthenticated DELETE on stored object, Range: bytes partial leak on retrieval,
//!     sitemap.xml path harvest, optional OAST token embedded in filename, enterprise risk tier (Catastrophic→Low).
//!   * **Omega wave (zero DAST parity)** — EICAR AV-pipeline oracle, batch multi-file upload, WebP/PNG modern
//!     format surface, SharePoint/Graph upload paths, multipart boundary smuggling, filename field mismatch
//!     (safe.jpg metadata + evil.php body), semicolon mid-extension bypass, Apache `.php.foo` parser trick,
//!     SVG foreignObject surface, ImageMagick/policy error fingerprint, internal URL disclosure in upload JSON
//!     responses, double Content-Disposition part, JSON multi-file array API, 20-dimension posture grade.
//!   * **Apex wave (absolute zero parity)** — RTLO/NFKC filename tricks, cloud-native paths (Vercel/Firebase/
//!     Supabase/R2), gzip Content-Encoding upload, Expect: 100-continue flow, X-Forwarded-Host reflection,
//!     Location header storage leak, overwrite/version oracle, HEAD metadata leak (ETag/x-amz-meta), XLSM/PDF-JS
//!     macro surfaces, security.txt upload hints, storage path entropy score, remediation urgency index,
//!     23-dimension posture + executive path-entropy metric.
//!
//! GUI-driven via [`ArsenalConfig`]. MITRE: T1190, T1204.002, T1059, T1189, T1552, T1083, T1530, T1499.

use crate::arsenal_config::{finding_rich, ArsenalConfig, Evidence, Intensity};
use crate::engine_dispatch::EngineRunContext;
use crate::engine_probes::{empty_ok, http_client, http_get, normalize_url};
use crate::engine_result::{print_result, EngineResult};
use futures::stream::{self, StreamExt};
use reqwest::Client;
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashSet};
use std::time::Duration;

const ENGINE_ID: &str = "file_upload";
const MITRE: &str = "T1190";
const DEFAULT_CANARY: &str = "WZUPLOAD9137BENIGN";
const BENIGN_GIF: &[u8] = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xFF\xFF\xFF\x00\x00\x00!\xF9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;";

fn benign_gif_str() -> &'static str {
    static CACHE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    CACHE
        .get_or_init(|| String::from_utf8_lossy(BENIGN_GIF).into_owned())
        .as_str()
}

const DEFAULT_UPLOAD_PATHS: &[&str] = &[
    "/upload",
    "/api/upload",
    "/file/upload",
    "/files/upload",
    "/import",
    "/api/import",
    "/api/file",
    "/api/files",
    "/media/upload",
    "/attachments",
    "/api/attachments",
    "/api/v1/upload",
    "/api/v1/files",
    "/api/v2/upload",
    "/documents/upload",
    "/assets/upload",
    "/storage/upload",
    "/user/avatar",
    "/profile/avatar",
    "/api/user/avatar",
    "/api/media",
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/api/v1/media",
    "/api/documents",
    "/api/storage",
    "/api/asset/upload",
    "/api/image/upload",
    "/api/photo/upload",
    "/api/avatar",
    "/cdn/upload",
    "/content/upload",
    "/wp-admin/async-upload.php",
    "/wp-json/wp/v2/media",
    "/index.php/upload",
    "/api/files/upload",
    "/rest/file/upload",
    "/api/file/upload",
    "/fileupload",
    "/uploader",
    "/api/uploader",
    "/s3/upload",
    "/presigned",
    "/api/presigned",
    "/api/signed-url",
];

const DEFAULT_FIELD_NAMES: &[&str] = &[
    "file",
    "upload",
    "document",
    "attachment",
    "image",
    "media",
    "photo",
    "avatar",
    "data",
    "blob",
];

const OPENAPI_HINTS: &[&str] = &[
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/v3/api-docs",
    "/v2/api-docs",
    "/swagger/v1/swagger.json",
    "/openapi/v3.json",
];

const JS_PATH_HINTS: &[&str] = &[
    "/static/js/main.js",
    "/assets/index.js",
    "/app.js",
    "/bundle.js",
    "/main.js",
    "/_next/static/chunks/main.js",
];

const CMS_UPLOAD_PATHS: &[&str] = &[
    "/node_modules/.bin/../upload",
    "/api/upload-file",
    "/api/media/upload",
    "/api/v1/media/upload",
    "/api/v1/storage/upload",
    "/api/strapi/upload",
    "/upload/files",
    "/directus/files",
    "/api/directus/files",
    "/laravel-filemanager/upload",
    "/filemanager/upload",
    "/ckeditor/upload",
    "/froala/upload",
    "/api/ckeditor/upload",
    "/sites/default/files",
    "/system/files",
    "/jsonapi/node/article/field_image",
    "/_api/web/GetFolderByServerRelativeUrl('Shared%20Documents')/Files/add",
    "/_api/web/lists/getbytitle('Documents')/RootFolder/Files/add",
    "/api/content/upload",
    "/api/assets",
    "/api/blob/upload",
    "/api/v1/blobs",
    "/api/v1/objects/upload",
];

const STORAGE_ROOT_PATHS: &[&str] = &[
    "/uploads/",
    "/upload/",
    "/files/",
    "/media/",
    "/storage/",
    "/assets/uploads/",
    "/public/uploads/",
    "/static/uploads/",
    "/wp-content/uploads/",
    "/content/uploads/",
];

const TUS_PATH_SUFFIXES: &[&str] = &["", "/files", "/upload", "/api/upload", "/api/tus"];

const SPRING_UPLOAD_PATHS: &[&str] = &[
    "/api/file",
    "/api/files/upload",
    "/api/v1/attachments",
    "/uploadImage",
    "/uploadFile",
    "/api/spring/upload",
    "/api/content/upload-file",
    "/api/document/upload",
];

const ERROR_DISCLOSURE_MARKERS: &[&str] = &[
    "stack trace",
    "stacktrace",
    "exception",
    "at org.",
    "at com.",
    "at java.",
    "syntax error",
    "unexpected token",
    "upload failed",
    "/var/www",
    "/home/",
    "c:\\",
    "line ",
    "SQLException",
    "NullPointerException",
];

/// Standard EICAR anti-virus test string (industry benign test file — not malware).
const EICAR: &str = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

const SHAREPOINT_UPLOAD_PATHS: &[&str] = &[
    "/_layouts/15/upload.aspx",
    "/_layouts/16/Upload.aspx",
    "/_api/web/lists/getbytitle('Documents')/RootFolder/Files/add",
    "/_api/v2.0/drives/root/items/root/upload",
    "/_api/v2.1/drives/root/items/root/upload",
    "/sites/all/_api/web/GetFolderByServerRelativeUrl('/Shared%20Documents')/Files/add",
    "/_api/SP.AppContextSite/@target/web/lists/getbytitle('Documents')/RootFolder/Files/add",
    "/personal/user/_api/web/GetFolderByServerRelativeUrl('/Documents')/Files/add",
];

const CLOUD_NATIVE_UPLOAD_PATHS: &[&str] = &[
    "/api/upload/blob",
    "/api/vercel/blob",
    "/api/storage/upload",
    "/storage/v1/upload",
    "/storage/v1/object/upload",
    "/supabase/storage/v1/upload",
    "/upload/storage",
    "/api/r2/upload",
    "/r2/upload",
    "/firebase/storage/upload",
    "/v1/storage/upload",
    "/api/assets/upload/direct",
    "/api/cdn/upload",
    "/api/blob/upload",
    "/api/files/signed-url",
    "/api/generate-upload-url",
    "/hub/upload",
    "/signalr/upload",
    "/api/hubs/upload/negotiate",
];

const IMAGEMAGICK_ERROR_MARKERS: &[&str] = &[
    "imagemagick",
    "magick",
    "not authorized",
    "policy",
    "delegate",
    "mvg",
    "svg:xml",
    "no decode delegate",
];

// ── Core types ──────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct HttpProbe {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
    final_url: String,
}

#[derive(Clone, Debug, Default)]
struct Endpoint {
    url: String,
    field: String,
    source: String,
    protocol: EndpointProtocol,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
enum EndpointProtocol {
    #[default]
    Multipart,
    #[allow(dead_code)] // handled in match arms; not currently constructed by detection
    GraphqlUpload,
    Base64Json,
    #[allow(dead_code)] // handled in match arms; not currently constructed by detection
    Put,
}

#[derive(Clone, Debug, Default)]
struct StackHint {
    php: bool,
    iis: bool,
    dotnet: bool,
    java: bool,
    node: bool,
    wordpress: bool,
    nginx: bool,
    apache: bool,
    labels: Vec<String>,
}

#[derive(Clone, Debug)]
struct BypassCombo {
    filename: String,
    content_type: String,
    content: String,
    label: String,
    category: String,
    severity_if_retrieved: &'static str,
    severity_if_accepted: &'static str,
    tier: u8,
    disposition: DispositionMode,
}

#[derive(Clone, Copy, Debug, Default)]
enum DispositionMode {
    #[default]
    Standard,
    Rfc5987Utf8,
    EmptyMime,
    OctetStream,
}

#[derive(Clone, Debug, Default)]
struct UploadExposure {
    combo: String,
    category: String,
    accepted: bool,
    retrieved: bool,
    retrieve_url: Option<String>,
    retrieve_content_type: Option<String>,
    execution_hint: bool,
    nosniff_missing: bool,
    cors_permissive: bool,
    inline_served: bool,
}

// ── Helpers ─────────────────────────────────────────────────────────────────────

fn base_url(target: &str) -> String {
    normalize_url(target)
}

fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    let ln = name.to_ascii_lowercase();
    headers
        .iter()
        .find(|(k, _)| k.to_ascii_lowercase() == ln)
        .map(|(_, v)| v.clone())
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        _ => 1,
    }
}

fn build_multipart_body(
    boundary: &str,
    field: &str,
    filename: &str,
    content_type: Option<&str>,
    content: &[u8],
    disposition: DispositionMode,
) -> Vec<u8> {
    let ct = content_type.unwrap_or("application/octet-stream");
    let disp = match disposition {
        DispositionMode::Standard => {
            format!("Content-Disposition: form-data; name=\"{field}\"; filename=\"{filename}\"")
        }
        DispositionMode::Rfc5987Utf8 => format!(
            "Content-Disposition: form-data; name=\"{field}\"; filename=\"fallback.jpg\"; filename*=UTF-8''{}",
            urlencoding_encode(filename)
        ),
        DispositionMode::EmptyMime | DispositionMode::OctetStream => {
            format!("Content-Disposition: form-data; name=\"{field}\"; filename=\"{filename}\"")
        }
    };
    let ct_line = match disposition {
        DispositionMode::EmptyMime => String::new(),
        DispositionMode::OctetStream => "Content-Type: application/octet-stream\r\n".to_string(),
        _ => format!("Content-Type: {ct}\r\n"),
    };
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(disp.as_bytes());
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(ct_line.as_bytes());
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(content);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    body
}

fn urlencoding_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

async fn post_multipart(
    client: &Client,
    url: &str,
    field: &str,
    filename: &str,
    content_type: &str,
    content: &str,
    extra_headers: &[(String, String)],
    timeout_ms: u64,
    disposition: DispositionMode,
) -> Option<HttpProbe> {
    post_multipart_raw(
        client,
        url,
        field,
        filename,
        content_type,
        content.as_bytes(),
        extra_headers,
        timeout_ms,
        disposition,
    )
    .await
}

async fn post_multipart_raw(
    client: &Client,
    url: &str,
    field: &str,
    filename: &str,
    content_type: &str,
    content: &[u8],
    extra_headers: &[(String, String)],
    timeout_ms: u64,
    disposition: DispositionMode,
) -> Option<HttpProbe> {
    let boundary = "----WZUploadBoundary9137";
    let ct_opt = match disposition {
        DispositionMode::EmptyMime => None,
        DispositionMode::OctetStream => Some("application/octet-stream"),
        _ => Some(content_type),
    };
    let body = build_multipart_body(boundary, field, filename, ct_opt, content, disposition);
    let mut req = client
        .post(url)
        .header(
            "Content-Type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(body)
        .timeout(Duration::from_millis(timeout_ms));
    for (k, v) in extra_headers {
        req = req.header(k.as_str(), v.as_str());
    }
    send_probe(req).await
}

async fn post_graphql_upload(
    client: &Client,
    url: &str,
    canary: &str,
    filename: &str,
    extra_headers: &[(String, String)],
    timeout_ms: u64,
) -> Option<HttpProbe> {
    let boundary = "----WZGraphQLUpload";
    let operations =
        r#"{"query":"mutation($file: Upload!){ __typename }","variables":{"file":null}}"#;
    let map = r#"{"0":["variables.file"]}"#;
    let body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"operations\"\r\n\r\n{operations}\r\n\
         --{boundary}\r\nContent-Disposition: form-data; name=\"map\"\r\n\r\n{map}\r\n\
         --{boundary}\r\nContent-Disposition: form-data; name=\"0\"; filename=\"{filename}\"\r\n\
         Content-Type: text/plain\r\n\r\n{canary}\r\n--{boundary}--\r\n",
    );
    let mut req = client
        .post(url)
        .header(
            "Content-Type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(body)
        .timeout(Duration::from_millis(timeout_ms));
    for (k, v) in extra_headers {
        req = req.header(k.as_str(), v.as_str());
    }
    send_probe(req).await
}

async fn post_base64_json_upload(
    client: &Client,
    url: &str,
    field: &str,
    filename: &str,
    content: &str,
    extra_headers: &[(String, String)],
    timeout_ms: u64,
) -> Option<HttpProbe> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(content.as_bytes());
    let payload = json!({
        field: { "filename": filename, "content": b64, "encoding": "base64" }
    });
    let mut req = client
        .post(url)
        .header("Content-Type", "application/json")
        .json(&payload)
        .timeout(Duration::from_millis(timeout_ms));
    for (k, v) in extra_headers {
        req = req.header(k.as_str(), v.as_str());
    }
    send_probe(req).await
}

async fn send_probe(req: reqwest::RequestBuilder) -> Option<HttpProbe> {
    let resp = req.send().await.ok()?;
    let status = resp.status().as_u16();
    let final_url = resp.url().to_string();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
        .collect();
    let body_text = resp.text().await.unwrap_or_default();
    let body_text = if body_text.len() > 65_536 {
        // Truncate on a UTF-8 char boundary — a plain byte slice at 65_536 panics if it
        // splits a multi-byte char, and the body is attacker-controlled (a scanned target).
        let mut end = 65_536;
        while !body_text.is_char_boundary(end) {
            end -= 1;
        }
        body_text[..end].to_string()
    } else {
        body_text
    };
    Some(HttpProbe {
        status,
        headers,
        body: body_text,
        final_url,
    })
}

async fn put_upload(
    client: &Client,
    url: &str,
    filename: &str,
    content_type: &str,
    content: &str,
    extra_headers: &[(String, String)],
    timeout_ms: u64,
) -> Option<HttpProbe> {
    let target = if url.ends_with('/') {
        format!("{url}{filename}")
    } else {
        format!("{url}/{filename}")
    };
    let mut req = client
        .put(&target)
        .header("Content-Type", content_type)
        .body(content.to_string())
        .timeout(Duration::from_millis(timeout_ms));
    for (k, v) in extra_headers {
        req = req.header(k.as_str(), v.as_str());
    }
    send_probe(req).await
}

async fn patch_upload(
    client: &Client,
    url: &str,
    filename: &str,
    content: &str,
    extra_headers: &[(String, String)],
    timeout_ms: u64,
) -> Option<HttpProbe> {
    let target = if url.ends_with('/') {
        format!("{url}{filename}")
    } else {
        format!("{url}/{filename}")
    };
    let mut req = client
        .patch(&target)
        .header("Content-Type", "text/plain")
        .body(content.to_string())
        .timeout(Duration::from_millis(timeout_ms));
    for (k, v) in extra_headers {
        req = req.header(k.as_str(), v.as_str());
    }
    send_probe(req).await
}

async fn options_probe(
    client: &Client,
    url: &str,
    extra_headers: &[(String, String)],
    timeout_ms: u64,
) -> Option<HttpProbe> {
    let mut req = client
        .request(reqwest::Method::OPTIONS, url)
        .timeout(Duration::from_millis(timeout_ms));
    for (k, v) in extra_headers {
        req = req.header(k.as_str(), v.as_str());
    }
    send_probe(req).await
}

async fn post_tus_create(
    client: &Client,
    url: &str,
    canary: &str,
    extra_headers: &[(String, String)],
    timeout_ms: u64,
) -> Option<HttpProbe> {
    let mut req = client
        .post(url)
        .header("Tus-Resumable", "1.0.0")
        .header("Upload-Length", canary.len().to_string())
        .header(
            "Upload-Metadata",
            format!("filename d{}=", base64_meta("wz-probe.txt")),
        )
        .header("Content-Length", "0")
        .timeout(Duration::from_millis(timeout_ms));
    for (k, v) in extra_headers {
        req = req.header(k.as_str(), v.as_str());
    }
    send_probe(req).await
}

fn base64_meta(s: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}

async fn post_multipart_hpp(
    client: &Client,
    url: &str,
    field_a: &str,
    field_b: &str,
    filename: &str,
    content: &str,
    extra_headers: &[(String, String)],
    timeout_ms: u64,
) -> Option<HttpProbe> {
    let boundary = "----WZHppBoundary";
    let part = |field: &str| {
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{filename}\"\r\nContent-Type: text/plain\r\n\r\n{content}\r\n"
        )
    };
    let body = format!("{}{}{}--{boundary}--\r\n", part(field_a), part(field_b), "");
    let mut req = client
        .post(url)
        .header(
            "Content-Type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(body)
        .timeout(Duration::from_millis(timeout_ms));
    for (k, v) in extra_headers {
        req = req.header(k.as_str(), v.as_str());
    }
    send_probe(req).await
}

async fn put_content_range(
    client: &Client,
    url: &str,
    filename: &str,
    content: &str,
    extra_headers: &[(String, String)],
    timeout_ms: u64,
) -> Option<HttpProbe> {
    let target = if url.ends_with('/') {
        format!("{url}{filename}")
    } else {
        format!("{url}/{filename}")
    };
    let len = content.len();
    let mut req = client
        .put(&target)
        .header("Content-Type", "text/plain")
        .header(
            "Content-Range",
            format!("bytes 0-{}/{len}", len.saturating_sub(1)),
        )
        .body(content.to_string())
        .timeout(Duration::from_millis(timeout_ms));
    for (k, v) in extra_headers {
        req = req.header(k.as_str(), v.as_str());
    }
    send_probe(req).await
}

fn extract_numeric_ids(body: &str) -> Vec<u64> {
    let mut ids = HashSet::new();
    if let Ok(v) = serde_json::from_str::<Value>(body) {
        collect_json_ids(&v, &mut ids);
    }
    for key in [
        "\"id\":",
        "\"fileId\":",
        "\"file_id\":",
        "\"assetId\":",
        "\"mediaId\":",
    ] {
        let mut from = 0;
        while let Some(idx) = body[from..].find(key) {
            let rest = &body[from + idx + key.len()..];
            let trimmed = rest.trim_start();
            if let Some(num) = trimmed
                .split(|c: char| !c.is_ascii_digit())
                .next()
                .and_then(|s| s.parse::<u64>().ok())
            {
                if num > 0 && num < 10_000_000 {
                    ids.insert(num);
                }
            }
            from += idx + key.len();
        }
    }
    ids.into_iter().collect()
}

fn collect_json_ids(v: &Value, out: &mut HashSet<u64>) {
    match v {
        Value::Object(map) => {
            for (k, val) in map {
                if matches!(
                    k.as_str(),
                    "id" | "fileId" | "file_id" | "assetId" | "mediaId" | "objectId"
                ) {
                    if let Some(n) = val.as_u64() {
                        if n > 0 && n < 10_000_000 {
                            out.insert(n);
                        }
                    }
                }
                collect_json_ids(val, out);
            }
        }
        Value::Array(arr) => {
            for item in arr {
                collect_json_ids(item, out);
            }
        }
        _ => {}
    }
}

fn extract_presigned_urls(body: &str) -> Vec<String> {
    let mut out = HashSet::new();
    for marker in [
        "X-Amz-Signature",
        "x-amz-signature",
        "s3.amazonaws.com",
        "blob.core.windows.net",
        "storage.googleapis.com",
        "r2.cloudflarestorage.com",
        "supabase.co/storage",
        "vercel-storage.com",
        "presigned",
        "signedUrl",
        "uploadUrl",
    ] {
        if !body.contains(marker) {
            continue;
        }
        for tok in body.split(|c: char| {
            !c.is_ascii_graphic() && c != '/' && c != ':' && c != '?' && c != '&' && c != '='
        }) {
            if tok.starts_with("http")
                && (tok.contains("amazonaws")
                    || tok.contains("blob.core")
                    || tok.contains("googleapis")
                    || tok.contains("cloudflarestorage")
                    || tok.contains("supabase.co")
                    || tok.contains("vercel")
                    || tok.contains("Signature=")
                    || tok.contains("X-Amz"))
            {
                out.insert(tok.to_string());
            }
        }
    }
    out.into_iter().collect()
}

async fn probe_upload_idor(
    client: &Client,
    upload_resp: &HttpProbe,
    base: &str,
    canary: &str,
    target: &str,
    ep: &Endpoint,
) -> Option<Value> {
    let ids = extract_numeric_ids(&upload_resp.body);
    let url_hint = extract_retrieval_urls(&upload_resp.body, base, canary)
        .into_iter()
        .next();
    for id in ids.iter().take(3) {
        for delta in [0i64, 1, -1, 2] {
            let probe_id = (*id as i64).saturating_add(delta).max(0) as u64;
            let candidates = vec![
                format!("{base}/api/files/{probe_id}"),
                format!("{base}/api/media/{probe_id}"),
                format!("{base}/files/{probe_id}"),
                format!("{base}/uploads/{probe_id}"),
                format!("{base}/api/v1/files/{probe_id}"),
            ];
            for url in candidates {
                if let Some(stored) = http_get(client, &url).await {
                    if stored.body.contains(canary) && matches!(stored.status, 200 | 206) {
                        let exposure = UploadExposure {
                            combo: format!("upload-idor-{probe_id}"),
                            category: "upload_idor".into(),
                            accepted: true,
                            retrieved: true,
                            retrieve_url: Some(stored.final_url.clone()),
                            ..Default::default()
                        };
                        return Some(make_finding(
                            &format!("Upload IDOR — object {probe_id} exposes canary"),
                            "critical",
                            &format!(
                                "After upload to {}, object ID {} (delta {delta}) returned the canary at {} without authorization boundary — predictable object IDs enable cross-user file access.",
                                upload_resp.final_url, probe_id, stored.final_url
                            ),
                            target,
                            "upload_idor",
                            0.96,
                            &exposure,
                            ep,
                            "Use unguessable object keys; enforce per-object authorization on every download; never expose sequential IDs.",
                        ));
                    }
                }
            }
        }
    }
    if let Some(hint) = url_hint {
        if hint.contains("/files/") || hint.contains("/media/") {
            if let Some(id_str) = hint.rsplit('/').next() {
                if let Ok(id) = id_str.parse::<u64>() {
                    for probe_id in [id.saturating_add(1), id.saturating_sub(1)] {
                        let alt = hint.replace(id_str, &probe_id.to_string());
                        if let Some(stored) = http_get(client, &alt).await {
                            if stored.body.contains(canary) && matches!(stored.status, 200 | 206) {
                                let exposure = UploadExposure {
                                    combo: "upload-idor-url".into(),
                                    category: "upload_idor".into(),
                                    accepted: true,
                                    retrieved: true,
                                    retrieve_url: Some(stored.final_url),
                                    ..Default::default()
                                };
                                return Some(make_finding(
                                    "Upload IDOR — adjacent object URL serves canary",
                                    "critical",
                                    &format!(
                                        "URL pattern from upload response suggests IDOR at {}.",
                                        alt
                                    ),
                                    target,
                                    "upload_idor",
                                    0.94,
                                    &exposure,
                                    ep,
                                    "Authorize every object fetch; use opaque UUID keys.",
                                ));
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

async fn probe_directory_listing(
    client: &Client,
    base: &str,
    canary: &str,
    target: &str,
) -> Option<Value> {
    for root in STORAGE_ROOT_PATHS {
        let url = resolve_url(base, root);
        if let Some(p) = http_get(client, &url).await {
            if !matches!(p.status, 200 | 203) {
                continue;
            }
            let body_lc = p.body.to_ascii_lowercase();
            let listing = body_lc.contains("index of /")
                || body_lc.contains("<title>index of")
                || (body_lc.contains("<a href=\"") && body_lc.matches("<a href=\"").count() > 3);
            if listing && (p.body.contains(canary) || body_lc.contains("upload")) {
                let mut f = finding_rich(
                    ENGINE_ID,
                    &format!("Directory listing on storage root {root}"),
                    "high",
                    MITRE,
                    &format!(
                        "GET {} returned HTML directory listing (HTTP {}). Uploaded objects may be enumerable by attackers.",
                        p.final_url, p.status
                    ),
                    target,
                    0.91,
                    Evidence::new()
                        .with("url", p.final_url)
                        .with("category", "directory_listing"),
                );
                if let Some(obj) = f.as_object_mut() {
                    obj.insert("category".to_string(), json!("directory_listing"));
                }
                return Some(f);
            }
        }
    }
    None
}

fn compute_blast_radius(exposures: &[UploadExposure], endpoints: usize) -> u32 {
    let mut score = 0u32;
    if exposures.iter().any(|e| e.retrieved && e.execution_hint) {
        score += 40;
    }
    if exposures
        .iter()
        .any(|e| e.category == "config_upload" && e.retrieved)
    {
        score += 35;
    }
    if exposures
        .iter()
        .any(|e| e.category == "upload_idor" && e.retrieved)
    {
        score += 30;
    }
    if exposures
        .iter()
        .any(|e| e.category == "unauth_retrieval" && e.retrieved)
    {
        score += 28;
    }
    if exposures
        .iter()
        .any(|e| e.category == "svg_xss" && e.retrieved)
    {
        score += 25;
    }
    if exposures
        .iter()
        .any(|e| e.nosniff_missing && e.inline_served)
    {
        score += 15;
    }
    if exposures.iter().any(|e| e.category == "cdn_cache_exposure") {
        score += 12;
    }
    if endpoints > 5 {
        score += 10;
    }
    if exposures.iter().filter(|e| e.accepted).count() > 8 {
        score += 10;
    }
    if exposures
        .iter()
        .any(|e| e.category == "eicar_surface" && e.accepted)
    {
        score += 18;
    }
    if exposures
        .iter()
        .any(|e| e.category == "batch_upload" && e.accepted)
    {
        score += 8;
    }
    score.min(100)
}

fn minimal_jpeg_comment(canary: &str) -> Vec<u8> {
    let comment = canary.as_bytes();
    let mut v = vec![0xFF, 0xD8]; // SOI
    v.push(0xFF);
    v.push(0xFE); // COM marker
    let seg_len = (comment.len() + 2).min(65535);
    v.push(((seg_len >> 8) & 0xff) as u8);
    v.push((seg_len & 0xff) as u8);
    v.extend_from_slice(&comment[..comment.len().min(seg_len.saturating_sub(2))]);
    v.extend_from_slice(&[0xFF, 0xD9]); // EOI
    v
}

fn minimal_docx_bytes(canary: &str) -> Vec<u8> {
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body><w:p><w:r><w:t>{canary}</w:t></w:r></w:p></w:body></w:document>"#
    );
    minimal_zip("word/document.xml", &xml)
}

fn minimal_png() -> Vec<u8> {
    vec![
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F,
        0x15, 0xC4, 0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00,
        0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49,
        0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
    ]
}

fn minimal_webp() -> Vec<u8> {
    vec![
        0x52, 0x49, 0x46, 0x46, 0x24, 0x00, 0x00, 0x00, 0x57, 0x45, 0x42, 0x50, 0x56, 0x50, 0x38,
        0x20, 0x18, 0x00, 0x00, 0x00, 0x30, 0x01, 0x00, 0x9D, 0x01, 0x2A, 0x01, 0x00, 0x01, 0x00,
        0x02, 0x00, 0x34, 0x25, 0xA4, 0x00, 0x03, 0x70, 0x00, 0xFE, 0xFB, 0xFD, 0x50, 0x00,
    ]
}

fn minimal_svg_foreign_object(canary: &str) -> String {
    format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg"><foreignObject width="1" height="1"><body xmlns="http://www.w3.org/1999/xhtml"><!-- {canary} --></body></foreignObject></svg>"#
    )
}

fn build_multipart_batch_body(
    boundary: &str,
    field: &str,
    files: &[(&str, &str, &[u8])],
) -> Vec<u8> {
    let mut body = Vec::new();
    for (filename, content_type, content) in files {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!(
                "Content-Disposition: form-data; name=\"{field}\"; filename=\"{filename}\"\r\nContent-Type: {content_type}\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(content);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    body
}

async fn send_multipart_raw_body(
    client: &Client,
    url: &str,
    boundary: &str,
    body: Vec<u8>,
    extra_headers: &[(String, String)],
    timeout_ms: u64,
) -> Option<HttpProbe> {
    let mut req = client
        .post(url)
        .header(
            "Content-Type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(body)
        .timeout(Duration::from_millis(timeout_ms));
    for (k, v) in extra_headers {
        req = req.header(k.as_str(), v.as_str());
    }
    send_probe(req).await
}

async fn post_multipart_batch(
    client: &Client,
    url: &str,
    field: &str,
    files: &[(&str, &str, &[u8])],
    extra_headers: &[(String, String)],
    timeout_ms: u64,
) -> Option<HttpProbe> {
    let boundary = "----WZBatchBoundary9137";
    let body = build_multipart_batch_body(boundary, field, files);
    send_multipart_raw_body(client, url, boundary, body, extra_headers, timeout_ms).await
}

async fn post_multipart_filename_mismatch(
    client: &Client,
    url: &str,
    field: &str,
    declared_name: &str,
    actual_filename: &str,
    content_type: &str,
    content: &[u8],
    extra_headers: &[(String, String)],
    timeout_ms: u64,
) -> Option<HttpProbe> {
    let boundary = "----WZMismatchBoundary9137";
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        format!("Content-Disposition: form-data; name=\"filename\"\r\n\r\n{declared_name}\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        format!(
            "Content-Disposition: form-data; name=\"{field}\"; filename=\"{actual_filename}\"\r\nContent-Type: {content_type}\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(content);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    send_multipart_raw_body(client, url, boundary, body, extra_headers, timeout_ms).await
}

async fn post_multipart_double_disposition(
    client: &Client,
    url: &str,
    field: &str,
    outer_name: &str,
    inner_name: &str,
    content_type: &str,
    content: &[u8],
    extra_headers: &[(String, String)],
    timeout_ms: u64,
) -> Option<HttpProbe> {
    let boundary = "----WZDoubleDisp9137";
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        format!(
            "Content-Disposition: form-data; name=\"{field}\"; filename=\"{outer_name}\"\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{inner_name}\"\r\nContent-Type: {content_type}\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(content);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    send_multipart_raw_body(client, url, boundary, body, extra_headers, timeout_ms).await
}

async fn post_multipart_boundary_smuggle(
    client: &Client,
    url: &str,
    field: &str,
    filename: &str,
    content: &str,
    extra_headers: &[(String, String)],
    timeout_ms: u64,
) -> Option<HttpProbe> {
    let boundary = "----WZUploadBoundary9137";
    let inject = format!("--{boundary}\r\nInjected: 1\r\n");
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        format!(
            "Content-Disposition: form-data; name=\"{field}\"; filename=\"{filename}\"\r\nContent-Type: text/plain\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(inject.as_bytes());
    body.extend_from_slice(content.as_bytes());
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    send_multipart_raw_body(client, url, boundary, body, extra_headers, timeout_ms).await
}

async fn post_json_multi_file(
    client: &Client,
    url: &str,
    canary: &str,
    extra_headers: &[(String, String)],
    timeout_ms: u64,
) -> Option<HttpProbe> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let b64 = STANDARD.encode(canary.as_bytes());
    let payload = json!({
        "files": [
            {"name": "a.txt", "content": b64, "type": "text/plain"},
            {"name": "b.txt", "content": b64, "type": "text/plain"},
        ]
    });
    let mut req = client
        .post(url)
        .header("Content-Type", "application/json")
        .json(&payload)
        .timeout(Duration::from_millis(timeout_ms));
    for (k, v) in extra_headers {
        req = req.header(k.as_str(), v.as_str());
    }
    send_probe(req).await
}

fn extract_internal_url_signals(body: &str) -> Vec<String> {
    let bl = body.to_ascii_lowercase();
    let markers = [
        "http://127.0.0.1",
        "https://127.0.0.1",
        "http://localhost",
        "https://localhost",
        "http://169.254.",
        "http://10.",
        "http://192.168.",
        "file://",
        "metadata.google.internal",
        "169.254.169.254",
        ".internal/",
        "s3.amazonaws.com",
        "blob.core.windows.net",
    ];
    let mut found = Vec::new();
    for m in markers {
        if bl.contains(m) {
            found.push(m.to_string());
        }
    }
    found.sort_unstable();
    found.dedup();
    found
}

fn imagemagick_error_in_body(body: &str) -> bool {
    let bl = body.to_ascii_lowercase();
    IMAGEMAGICK_ERROR_MARKERS
        .iter()
        .any(|m| bl.contains(&m.to_ascii_lowercase()))
}

fn gzip_compress(data: &[u8]) -> Vec<u8> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    if enc.write_all(data).is_err() {
        return data.to_vec();
    }
    enc.finish().unwrap_or_else(|_| data.to_vec())
}

fn minimal_xlsm(canary: &str) -> Vec<u8> {
    let workbook = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<sheets><sheet name="Sheet1" sheetId="1"/></sheets><!-- {canary} --></workbook>"#
    );
    minimal_zip("xl/workbook.xml", &workbook)
}

fn minimal_pdf_js_marker(canary: &str) -> String {
    format!(
        "%PDF-1.4\n% {canary}\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[]/Count 0>>endobj\n%% benign JS surface marker only\n%%EOF"
    )
}

fn score_storage_path_entropy(url: &str) -> u32 {
    let segment = url.rsplit('/').next().unwrap_or(url);
    if segment.len() >= 32 && segment.contains('-') && segment.matches('-').count() >= 3 {
        return 92;
    }
    if segment.chars().all(|c| c.is_ascii_digit()) {
        return 12;
    }
    if segment.len() <= 8 && segment.chars().all(|c| c.is_ascii_alphanumeric()) {
        return 28;
    }
    if segment.len() >= 16 {
        return 78;
    }
    55
}

fn aggregate_path_entropy(exposures: &[UploadExposure]) -> u32 {
    let urls: Vec<&String> = exposures
        .iter()
        .filter_map(|e| e.retrieve_url.as_ref())
        .collect();
    if urls.is_empty() {
        return 95;
    }
    urls.iter()
        .map(|u| score_storage_path_entropy(u))
        .sum::<u32>()
        .checked_div(urls.len() as u32)
        .unwrap_or(95)
}

fn compute_remediation_urgency(blast: u32, crit: u32, high: u32, posture_score: u32) -> u32 {
    let raw = blast.saturating_mul(55) / 100
        + crit.saturating_mul(18)
        + high.saturating_mul(6)
        + (100u32.saturating_sub(posture_score)) / 3;
    raw.min(100)
}

async fn post_gzip_multipart(
    client: &Client,
    url: &str,
    field: &str,
    filename: &str,
    content_type: &str,
    content: &str,
    extra_headers: &[(String, String)],
    timeout_ms: u64,
) -> Option<HttpProbe> {
    let boundary = "----WZGzipBoundary9137";
    let body = build_multipart_body(
        boundary,
        field,
        filename,
        Some(content_type),
        content.as_bytes(),
        DispositionMode::Standard,
    );
    let gz = gzip_compress(&body);
    let mut req = client
        .post(url)
        .header(
            "Content-Type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .header("Content-Encoding", "gzip")
        .body(gz)
        .timeout(Duration::from_millis(timeout_ms));
    for (k, v) in extra_headers {
        req = req.header(k.as_str(), v.as_str());
    }
    send_probe(req).await
}

async fn post_multipart_expect_continue(
    client: &Client,
    url: &str,
    field: &str,
    filename: &str,
    content: &str,
    extra_headers: &[(String, String)],
    timeout_ms: u64,
) -> Option<HttpProbe> {
    let boundary = "----WZExpectBoundary9137";
    let body = build_multipart_body(
        boundary,
        field,
        filename,
        Some("text/plain"),
        content.as_bytes(),
        DispositionMode::Standard,
    );
    let mut req = client
        .post(url)
        .header("Expect", "100-continue")
        .header(
            "Content-Type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(body)
        .timeout(Duration::from_millis(timeout_ms));
    for (k, v) in extra_headers {
        req = req.header(k.as_str(), v.as_str());
    }
    send_probe(req).await
}

async fn probe_x_forwarded_host(
    client: &Client,
    url: &str,
    field: &str,
    canary: &str,
    extra_headers: &[(String, String)],
    timeout_ms: u64,
    target: &str,
    ep: &Endpoint,
) -> Option<Value> {
    let evil = "evil-forwarded-upload.example.com";
    let mut headers: Vec<(String, String)> = extra_headers.to_vec();
    headers.push(("X-Forwarded-Host".to_string(), evil.to_string()));
    let resp = post_multipart(
        client,
        url,
        field,
        "xfh-probe.txt",
        "text/plain",
        canary,
        &headers,
        timeout_ms,
        DispositionMode::Standard,
    )
    .await?;
    let loc = header_value(&resp.headers, "location").unwrap_or_default();
    if resp.body.contains(evil) || loc.contains(evil) {
        return Some(make_finding(
            "X-Forwarded-Host reflected in upload response",
            "high",
            &format!(
                "Upload to {} reflected X-Forwarded-Host {} in body/Location (HTTP {}) — host-header/cache-poisoning surface.",
                resp.final_url, evil, resp.status
            ),
            target,
            "x_forwarded_host",
            0.9,
            &UploadExposure {
                combo: "xfh-reflection".into(),
                category: "x_forwarded_host".into(),
                accepted: matches!(resp.status, 200 | 201 | 202),
                ..Default::default()
            },
            ep,
            "Never trust X-Forwarded-Host for URL generation; use configured public base URL.",
        ));
    }
    None
}

async fn probe_location_header_leak(
    resp: &HttpProbe,
    target: &str,
    ep: &Endpoint,
) -> Option<Value> {
    let loc = header_value(&resp.headers, "location").unwrap_or_default();
    if loc.is_empty() {
        return None;
    }
    let ll = loc.to_ascii_lowercase();
    if ll.contains("/uploads/")
        || ll.contains("/storage/")
        || ll.contains("amazonaws")
        || ll.contains("blob.core")
        || ll.contains("googleapis")
        || ll.contains("internal")
    {
        return Some(make_finding(
            "Location header exposes storage path after upload",
            "medium",
            &format!(
                "Upload returned Location: {} (HTTP {}) — reveals storage layout or cloud bucket path.",
                loc, resp.status
            ),
            target,
            "location_header_leak",
            0.87,
            &UploadExposure {
                combo: "location-leak".into(),
                category: "location_header_leak".into(),
                accepted: true,
                ..Default::default()
            },
            ep,
            "Return opaque object IDs in API JSON only; avoid Location headers with predictable paths.",
        ));
    }
    None
}

async fn probe_head_metadata_leak(
    client: &Client,
    url: &str,
    target: &str,
    ep: &Endpoint,
) -> Option<Value> {
    let req = client.head(url).timeout(Duration::from_millis(8000));
    let resp = send_probe(req).await?;
    if !matches!(resp.status, 200 | 204) {
        return None;
    }
    let etag = header_value(&resp.headers, "etag").unwrap_or_default();
    let amz = header_value(&resp.headers, "x-amz-meta-custom").unwrap_or_default();
    let amz_id = header_value(&resp.headers, "x-amz-request-id").unwrap_or_default();
    let weak_seq = etag.trim_matches('"').parse::<u64>().ok().is_some();
    if weak_seq || !amz.is_empty() || amz_id.len() > 8 {
        return Some(make_finding(
            "HEAD on stored upload leaks object metadata",
            "medium",
            &format!(
                "HEAD {} returned ETag={:?} x-amz-meta signals — sequential or cloud metadata exposed.",
                resp.final_url, etag
            ),
            target,
            "head_metadata_leak",
            0.84,
            &UploadExposure {
                combo: "head-metadata".into(),
                category: "head_metadata_leak".into(),
                retrieved: true,
                retrieve_url: Some(resp.final_url.clone()),
                ..Default::default()
            },
            ep,
            "Use opaque UUID keys; disable HEAD on user uploads or require auth.",
        ));
    }
    None
}

async fn probe_overwrite_oracle(
    client: &Client,
    url: &str,
    field: &str,
    base: &str,
    canary_a: &str,
    canary_b: &str,
    extra_headers: &[(String, String)],
    timeout_ms: u64,
    target: &str,
    ep: &Endpoint,
    include_info: bool,
) -> Option<Value> {
    let name = "wz-overwrite-oracle.txt";
    let first = post_multipart(
        client,
        url,
        field,
        name,
        "text/plain",
        canary_a,
        extra_headers,
        timeout_ms,
        DispositionMode::Standard,
    )
    .await?;
    if !matches!(first.status, 200 | 201 | 202) {
        return None;
    }
    let second = post_multipart(
        client,
        url,
        field,
        name,
        "text/plain",
        canary_b,
        extra_headers,
        timeout_ms,
        DispositionMode::Standard,
    )
    .await?;
    if !matches!(second.status, 200 | 201 | 202) {
        return None;
    }
    let mut urls = extract_retrieval_urls(&first.body, base, canary_a);
    urls.extend(extract_retrieval_urls(&second.body, base, canary_b));
    urls.sort_unstable();
    urls.dedup();
    for u in urls {
        if let Some(stored) = http_get(client, &u).await {
            if stored.body.contains(canary_a) && stored.body.contains(canary_b) {
                return Some(make_finding(
                    "Overwrite oracle — both upload versions retrievable",
                    "high",
                    &format!(
                        "Two uploads with same filename at {} both canaries reachable at {} — no overwrite isolation.",
                        url, stored.final_url
                    ),
                    target,
                    "overwrite_oracle",
                    0.88,
                    &UploadExposure {
                        combo: "overwrite-both".into(),
                        category: "overwrite_oracle".into(),
                        accepted: true,
                        retrieved: true,
                        retrieve_url: Some(stored.final_url.clone()),
                        ..Default::default()
                    },
                    ep,
                    "Version objects immutably; never serve prior revision after overwrite.",
                ));
            }
            if stored.body.contains(canary_a) && !stored.body.contains(canary_b) && include_info {
                return Some(finding_rich(
                    ENGINE_ID,
                    "Prior upload still retrievable after same-name overwrite",
                    "medium",
                    MITRE,
                    &format!(
                        "After second upload to {}, first canary still at {} (HTTP {}) — stale object retention / no replace.",
                        url, stored.final_url, stored.status
                    ),
                    target,
                    0.82,
                    Evidence::new()
                        .with("url", stored.final_url)
                        .with("category", "overwrite_oracle"),
                ));
            }
        }
    }
    None
}

async fn discover_security_txt_hints(client: &Client, base: &str) -> Vec<String> {
    let url = format!("{}/.well-known/security.txt", base.trim_end_matches('/'));
    let Some(p) = http_get(client, &url).await else {
        return vec![];
    };
    if p.status != 200 {
        return vec![];
    }
    let mut out = Vec::new();
    for line in p.body.lines() {
        let ll = line.to_ascii_lowercase();
        if ll.contains("upload") || ll.contains("/files") {
            for tok in line.split_whitespace() {
                if tok.starts_with("http") && tok.contains("upload") {
                    out.push(tok.to_string());
                }
            }
        }
    }
    out
}

fn waf_vendor_from_headers(headers: &[(String, String)]) -> Option<String> {
    let pairs = [
        ("cf-ray", "cloudflare"),
        ("cf-cache-status", "cloudflare"),
        ("x-sucuri-id", "sucuri"),
        ("x-akamai-transformed", "akamai"),
        ("x-iinfo", "imperva"),
        ("x-cdn", "generic_cdn"),
        ("server", "server_banner"),
    ];
    for (h, vendor) in pairs {
        if header_value(headers, h).is_some() {
            return Some(vendor.to_string());
        }
    }
    if header_value(headers, "server")
        .map(|s| s.to_ascii_lowercase())
        .is_some_and(|s| s.contains("cloudflare") || s.contains("awselb"))
    {
        return Some("edge_waf".into());
    }
    None
}

async fn probe_unauth_retrieval(
    client: &Client,
    url: &str,
    canary: &str,
    target: &str,
    ep: &Endpoint,
) -> Option<Value> {
    let unauth = http_get(client, url).await?;
    if !matches!(unauth.status, 200 | 206) {
        return None;
    }
    if !(unauth.body.contains(canary)
        || unauth.body.contains("GIF89a")
        || unauth.body.contains("<svg"))
    {
        return None;
    }
    let exposure = UploadExposure {
        combo: "unauth-retrieval".into(),
        category: "unauth_retrieval".into(),
        accepted: true,
        retrieved: true,
        retrieve_url: Some(unauth.final_url.clone()),
        inline_served: true,
        ..Default::default()
    };
    Some(make_finding(
        "Uploaded object retrievable without authentication",
        "critical",
        &format!(
            "Object at {} returns uploaded canary content with HTTP {} and no operator Cookie/Authorization — any anonymous client can fetch user uploads.",
            unauth.final_url, unauth.status
        ),
        target,
        "unauth_retrieval",
        0.98,
        &exposure,
        ep,
        "Require signed URLs or session-bound authorization on every object GET; never expose sequential public paths.",
    ))
}

fn probe_cdn_cache_headers(headers: &[(String, String)]) -> Option<String> {
    let cc = header_value(headers, "cache-control")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if cc.contains("public") && (cc.contains("max-age") || cc.contains("s-maxage")) {
        if !cc.contains("private") && !cc.contains("no-store") {
            return Some(cc);
        }
    }
    None
}

async fn discover_robots_upload_paths(client: &Client, base: &str) -> Vec<String> {
    let url = format!("{}/robots.txt", base.trim_end_matches('/'));
    let Some(p) = http_get(client, &url).await else {
        return vec![];
    };
    if p.status != 200 {
        return vec![];
    }
    let mut out = Vec::new();
    for line in p.body.lines() {
        let ll = line.to_ascii_lowercase();
        if ll.contains("upload") || ll.contains("/files") || ll.contains("/media") {
            for tok in line.split_whitespace() {
                if tok.starts_with('/') && (tok.contains("upload") || tok.contains("file")) {
                    out.push(resolve_url(base, tok.trim_end_matches('*')));
                }
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn synthesize_toxic_combinations(exposures: &[UploadExposure]) -> Vec<Value> {
    let mut toxic = Vec::new();
    let has_exec = exposures.iter().any(|e| e.retrieved && e.execution_hint);
    let has_config = exposures
        .iter()
        .any(|e| e.category == "config_upload" && e.retrieved);
    let has_idor = exposures
        .iter()
        .any(|e| e.category == "upload_idor" && e.retrieved);
    let has_unauth = exposures.iter().any(|e| e.category == "unauth_retrieval");
    let has_svg = exposures
        .iter()
        .any(|e| e.category == "svg_xss" && e.retrieved);
    let has_nosniff = exposures
        .iter()
        .any(|e| e.nosniff_missing && e.inline_served && e.retrieved);

    if has_exec && has_config {
        toxic.push(json!({
            "name": "Config overwrite + executable retrieval",
            "severity": "critical",
            "rationale": "Attacker can upload server config AND retrieve executable content — full RCE chain without further primitives.",
        }));
    }
    if has_idor && has_unauth {
        toxic.push(json!({
            "name": "IDOR + anonymous download",
            "severity": "critical",
            "rationale": "Predictable object IDs plus unauthenticated GET enables mass exfiltration of all user uploads.",
        }));
    }
    if has_svg && has_nosniff {
        toxic.push(json!({
            "name": "Stored SVG + MIME sniffing",
            "severity": "critical",
            "rationale": "SVG accepted and served inline without nosniff — stored XSS against any visitor loading the object URL.",
        }));
    }
    if has_exec && has_idor {
        toxic.push(json!({
            "name": "Upload bypass + cross-object access",
            "severity": "critical",
            "rationale": "Extension bypass succeeds and object IDs are enumerable — weaponized payload can spread across tenants.",
        }));
    }
    let has_eicar = exposures
        .iter()
        .any(|e| e.category == "eicar_surface" && e.accepted);
    let has_batch = exposures
        .iter()
        .any(|e| e.category == "batch_upload" && e.accepted);
    if has_eicar && has_exec {
        toxic.push(json!({
            "name": "AV pipeline bypass + executable retrieval",
            "severity": "critical",
            "rationale": "EICAR test file accepted without AV rejection AND content is retrievable in execution context — malware delivery chain unprotected.",
        }));
    }
    if has_batch && has_idor {
        toxic.push(json!({
            "name": "Batch upload + IDOR enumeration",
            "severity": "critical",
            "rationale": "Multi-file upload accepted with predictable object IDs — mass upload/exfiltration at scale.",
        }));
    }
    let has_low_entropy = exposures.iter().any(|e| {
        e.retrieve_url
            .as_ref()
            .is_some_and(|u| score_storage_path_entropy(u) < 35)
    });
    if has_low_entropy && has_unauth {
        toxic.push(json!({
            "name": "Guessable storage path + anonymous download",
            "severity": "critical",
            "rationale": "Sequential/predictable object URLs combined with unauthenticated GET — trivial mass exfiltration.",
        }));
    }
    toxic
}

fn probe_coverage_manifest(cfg: &ArsenalConfig, max_tier: u8) -> Value {
    json!({
        "discovery": {
            "html_forms": true,
            "openapi": cfg.bool_or("check_openapi_discovery", true),
            "js_bundles": cfg.bool_or("check_js_discovery", true),
            "cms_paths": cfg.bool_or("check_cms_paths", true),
            "robots_txt": cfg.bool_or("check_robots_discovery", true),
            "presigned_extract": cfg.bool_or("check_presigned_probe", true),
        },
        "transports": {
            "multipart": true,
            "graphql_upload": cfg.bool_or("check_graphql_upload", true),
            "base64_json": cfg.bool_or("check_base64_json", true),
            "put": cfg.bool_or("check_put_upload", true),
            "patch": cfg.bool_or("check_patch_upload", false),
            "tus": cfg.bool_or("check_tus_upload", true) && max_tier >= 2,
            "content_range": cfg.bool_or("check_content_range", true) && max_tier >= 2,
            "webdav_options": cfg.bool_or("check_webdav_discovery", true) && max_tier >= 2,
        },
        "bypass_classes": {
            "mime_spoof": cfg.bool_or("check_mime_spoof", true),
            "double_extension": cfg.bool_or("check_double_extension", true),
            "unicode_homoglyph": cfg.bool_or("check_unicode_homoglyph", true),
            "url_encoded_ext": cfg.bool_or("check_url_encoded_extension", true),
            "long_filename": cfg.bool_or("check_long_filename", true),
            "jpeg_com_polyglot": cfg.bool_or("check_jpeg_com_polyglot", true),
            "docx_surface": cfg.bool_or("check_docx_surface", true),
            "platform_packs": cfg.string_or("stack_pack", "auto"),
        },
        "forensics": {
            "storage_oracle": cfg.bool_or("storage_path_oracle", true),
            "upload_idor": cfg.bool_or("check_upload_idor", true),
            "unauth_retrieval": cfg.bool_or("check_unauth_retrieval", true),
            "cdn_cache_isolation": cfg.bool_or("check_cdn_cache_isolation", true),
            "directory_listing": cfg.bool_or("check_directory_listing", true),
            "waf_fingerprint": cfg.bool_or("check_waf_fingerprint", true),
            "delete_without_auth": cfg.bool_or("check_delete_without_auth", true),
            "range_retrieval_leak": cfg.bool_or("check_range_retrieval", true),
        },
        "abuse_resilience": {
            "upload_cors": cfg.bool_or("check_upload_cors", true),
            "rate_limit_absence": cfg.bool_or("check_rate_limit_absence", true),
            "error_disclosure": cfg.bool_or("check_error_disclosure", true),
            "template_filename": cfg.bool_or("check_template_injection_filename", true),
            "reverse_double_ext": cfg.bool_or("check_reverse_double_extension", true),
            "iis_handlers": cfg.bool_or("check_iis_handlers", true),
        },
        "discovery_extra": {
            "sitemap": cfg.bool_or("check_sitemap_discovery", true),
            "spring_paths": cfg.bool_or("check_spring_paths", true),
            "sharepoint_paths": cfg.bool_or("check_sharepoint_paths", true),
            "oast_filename": cfg.string("oast_host").is_some(),
        },
        "omega_wave": {
            "eicar_av_oracle": cfg.bool_or("check_eicar_surface", true),
            "batch_upload": cfg.bool_or("check_batch_upload", true),
            "modern_formats": cfg.bool_or("check_webp_png_surface", true),
            "filename_field_mismatch": cfg.bool_or("check_filename_field_mismatch", true),
            "double_content_disposition": cfg.bool_or("check_double_content_disposition", true),
            "boundary_smuggling": cfg.bool_or("check_boundary_smuggling", true),
            "json_multi_file": cfg.bool_or("check_json_multi_file", true),
            "imagemagick_fingerprint": cfg.bool_or("check_imagemagick_surface", true),
            "svg_foreign_object": cfg.bool_or("check_svg_foreign_object", true),
            "internal_url_disclosure": cfg.bool_or("check_internal_url_disclosure", true),
            "semicolon_bypass": cfg.bool_or("check_semicolon_bypass", true),
            "apache_multisuffix": cfg.bool_or("check_apache_multisuffix", true),
        },
        "apex_wave": {
            "cloud_native_paths": cfg.bool_or("check_cloud_native_paths", true),
            "security_txt_hints": cfg.bool_or("check_security_txt_discovery", true),
            "gzip_content_encoding": cfg.bool_or("check_gzip_upload", true),
            "expect_continue": cfg.bool_or("check_expect_continue", true),
            "x_forwarded_host": cfg.bool_or("check_x_forwarded_host", true),
            "location_header_leak": cfg.bool_or("check_location_header_leak", true),
            "overwrite_oracle": cfg.bool_or("check_overwrite_oracle", true),
            "head_metadata_leak": cfg.bool_or("check_head_metadata_leak", true),
            "xlsm_surface": cfg.bool_or("check_xlsm_surface", true),
            "pdf_js_surface": cfg.bool_or("check_pdf_js_surface", true),
            "rtlo_bypass": cfg.bool_or("check_rtlo_bypass", true),
            "nfkc_bypass": cfg.bool_or("check_nfkc_bypass", true),
            "newline_extension": cfg.bool_or("check_newline_extension", true),
        },
        "intensity_tier": max_tier,
    })
}

fn enterprise_risk_tier(blast: u32, critical: u32) -> &'static str {
    if blast >= 75 || critical >= 2 {
        "Catastrophic"
    } else if blast >= 50 || critical >= 1 {
        "Severe"
    } else if blast >= 30 {
        "Elevated"
    } else if blast >= 15 {
        "Moderate"
    } else {
        "Low"
    }
}

async fn discover_sitemap_upload_paths(client: &Client, base: &str) -> Vec<String> {
    for path in ["/sitemap.xml", "/sitemap_index.xml", "/sitemap/sitemap.xml"] {
        let url = format!("{}{}", base.trim_end_matches('/'), path);
        let Some(p) = http_get(client, &url).await else {
            continue;
        };
        if p.status != 200 {
            continue;
        }
        let mut out = Vec::new();
        for tok in p
            .body
            .split(|c: char| c == '"' || c == '\'' || c.is_whitespace())
        {
            if tok.contains("/upload") || tok.contains("/files/") || tok.contains("/media/") {
                if tok.starts_with("http") {
                    out.push(tok.to_string());
                } else if tok.starts_with('/') {
                    out.push(resolve_url(base, tok));
                }
            }
        }
        if !out.is_empty() {
            out.sort_unstable();
            out.dedup();
            return out;
        }
    }
    vec![]
}

async fn probe_upload_cors(
    client: &Client,
    url: &str,
    field: &str,
    canary: &str,
    extra_headers: &[(String, String)],
    timeout_ms: u64,
    target: &str,
    ep: &Endpoint,
) -> Option<Value> {
    let evil = "https://evil-upload-probe.example.com";
    let mut headers: Vec<(String, String)> = extra_headers.to_vec();
    headers.push(("Origin".to_string(), evil.to_string()));
    let resp = post_multipart(
        client,
        url,
        field,
        "cors-probe.txt",
        "text/plain",
        canary,
        &headers,
        timeout_ms,
        DispositionMode::Standard,
    )
    .await?;
    let acao = header_value(&resp.headers, "access-control-allow-origin").unwrap_or_default();
    if acao == "*" || acao == evil {
        let exposure = UploadExposure {
            combo: "upload-cors".into(),
            category: "upload_cors".into(),
            accepted: matches!(resp.status, 200 | 201 | 202),
            ..Default::default()
        };
        return Some(make_finding(
            "Permissive CORS on upload endpoint",
            "high",
            &format!(
                "POST {} with Origin {} returned Access-Control-Allow-Origin: {} (HTTP {}) — cross-origin upload from attacker origin may be possible.",
                resp.final_url, evil, acao, resp.status
            ),
            target,
            "upload_cors",
            0.91,
            &exposure,
            ep,
            "Never reflect Origin on upload; disallow credentialed cross-origin POST to upload APIs.",
        ));
    }
    None
}

async fn probe_rate_limit_absence(
    client: &Client,
    url: &str,
    field: &str,
    canary: &str,
    extra_headers: &[(String, String)],
    timeout_ms: u64,
    target: &str,
    _ep: &Endpoint,
) -> Option<Value> {
    let mut saw_429 = false;
    let mut accepts = 0u32;
    for i in 0..6 {
        if let Some(r) = post_multipart(
            client,
            url,
            field,
            &format!("rate-{i}.txt"),
            "text/plain",
            canary,
            extra_headers,
            timeout_ms,
            DispositionMode::Standard,
        )
        .await
        {
            if r.status == 429 {
                saw_429 = true;
                break;
            }
            if matches!(r.status, 200 | 201 | 202 | 400 | 422) {
                accepts += 1;
            }
        }
    }
    if !saw_429 && accepts >= 5 {
        return Some(finding_rich(
            ENGINE_ID,
            "No upload rate limit observed (6 rapid POSTs)",
            "medium",
            MITRE,
            &format!(
                "Endpoint {} accepted/windowed {} rapid uploads without HTTP 429 — brute-force upload / DoS surface.",
                url, accepts
            ),
            target,
            0.8,
            Evidence::new()
                .with("url", url)
                .with("accepts", accepts)
                .with("category", "rate_limit_absence"),
        ));
    }
    None
}

async fn probe_error_disclosure(
    client: &Client,
    url: &str,
    field: &str,
    extra_headers: &[(String, String)],
    timeout_ms: u64,
    target: &str,
) -> Option<Value> {
    let boundary = "----WZBrokenBoundary";
    let broken = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"broken.bin\"\r\nContent-Type: application/octet-stream\r\n\r\nBROKEN"
    );
    let mut req = client
        .post(url)
        .header(
            "Content-Type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(broken)
        .timeout(Duration::from_millis(timeout_ms));
    for (k, v) in extra_headers {
        req = req.header(k.as_str(), v.as_str());
    }
    let resp = send_probe(req).await?;
    if !matches!(resp.status, 400 | 422 | 500 | 502) {
        return None;
    }
    let body_lc = resp.body.to_ascii_lowercase();
    if ERROR_DISCLOSURE_MARKERS
        .iter()
        .any(|m| body_lc.contains(&m.to_ascii_lowercase()))
    {
        let mut f = finding_rich(
            ENGINE_ID,
            "Verbose error on malformed multipart upload",
            "medium",
            MITRE,
            &format!(
                "Malformed upload to {} returned HTTP {} with stack/path disclosure in body — aids attacker mapping.",
                resp.final_url, resp.status
            ),
            target,
            0.87,
            Evidence::new()
                .with("url", resp.final_url)
                .with("status", resp.status)
                .with("body_excerpt", &resp.body[..resp.body.len().min(512)]),
        );
        if let Some(obj) = f.as_object_mut() {
            obj.insert("category".to_string(), json!("error_disclosure"));
        }
        return Some(f);
    }
    None
}

async fn probe_delete_without_auth(
    client: &Client,
    url: &str,
    target: &str,
    ep: &Endpoint,
) -> Option<Value> {
    let req = client.delete(url).timeout(Duration::from_millis(8000));
    let resp = send_probe(req).await?;
    if matches!(resp.status, 200 | 204) {
        let exposure = UploadExposure {
            combo: "delete-unauth".into(),
            category: "delete_without_auth".into(),
            accepted: true,
            ..Default::default()
        };
        return Some(make_finding(
            "Unauthenticated DELETE on stored upload URL",
            "high",
            &format!(
                "DELETE {} returned HTTP {} without operator credentials — objects may be removable by anyone.",
                resp.final_url, resp.status
            ),
            target,
            "delete_without_auth",
            0.88,
            &exposure,
            ep,
            "Require authorization on DELETE; use opaque non-guessable object keys.",
        ));
    }
    None
}

async fn probe_range_retrieval(
    client: &Client,
    url: &str,
    canary: &str,
    target: &str,
    ep: &Endpoint,
) -> Option<Value> {
    let req = client
        .get(url)
        .header("Range", "bytes=0-32")
        .timeout(Duration::from_millis(8000));
    let resp = send_probe(req).await?;
    if matches!(resp.status, 206)
        && (resp.body.contains(canary) || resp.body.contains("GIF89a") || resp.body.len() > 4)
    {
        let exposure = UploadExposure {
            combo: "range-leak".into(),
            category: "range_retrieval_leak".into(),
            retrieved: true,
            retrieve_url: Some(resp.final_url.clone()),
            ..Default::default()
        };
        return Some(make_finding(
            "Partial content (Range) leak on uploaded object",
            "medium",
            &format!(
                "GET {} with Range: bytes=0-32 returned HTTP 206 with body bytes — confirms byte-level read of user upload.",
                resp.final_url
            ),
            target,
            "range_retrieval_leak",
            0.85,
            &exposure,
            ep,
            "Authorize Range requests; return 416 or 403 for unauthorized partial reads.",
        ));
    }
    None
}

// ── Discovery ───────────────────────────────────────────────────────────────────

fn extract_upload_forms(html: &str, base: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let html_lc = html.to_ascii_lowercase();
    if !html_lc.contains("type=\"file\"") && !html_lc.contains("type='file'") {
        return out;
    }
    for chunk in html.split("<form").skip(1) {
        let action = chunk
            .split_once('>')
            .and_then(|(attrs, _)| {
                attrs.split_whitespace().find_map(|a| {
                    if a.starts_with("action=") {
                        Some(
                            a.trim_start_matches("action=")
                                .trim_matches('"')
                                .trim_matches('\'')
                                .to_string(),
                        )
                    } else {
                        None
                    }
                })
            })
            .unwrap_or_else(|| "/".to_string());
        let field = chunk
            .split("type=\"file\"")
            .nth(1)
            .or_else(|| chunk.split("type='file'").nth(1))
            .and_then(|rest| {
                rest.split("name=").nth(1).map(|n| {
                    n.trim_start_matches('"')
                        .trim_start_matches('\'')
                        .split(&['"', '\''][..])
                        .next()
                        .unwrap_or("file")
                        .to_string()
                })
            })
            .unwrap_or_else(|| "file".to_string());
        let url = resolve_url(base, &action);
        out.push((url, field));
    }
    out
}

fn resolve_url(base: &str, path: &str) -> String {
    if path.starts_with("http") {
        path.to_string()
    } else if path.starts_with('/') {
        format!("{}{}", base.trim_end_matches('/'), path)
    } else {
        format!("{}/{}", base.trim_end_matches('/'), path)
    }
}

fn extract_js_upload_urls(body: &str, base: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    for marker in [
        "/upload",
        "/api/upload",
        "/files/upload",
        "/media/upload",
        "presigned",
        "signedUrl",
        "signed_url",
        "multipart/form-data",
    ] {
        if !body.contains(marker) {
            continue;
        }
        for tok in body.split(|c: char| !c.is_ascii_graphic() && c != '/' && c != '_' && c != '-') {
            if tok.starts_with('/') && tok.len() > 3 && tok.len() < 120 {
                if tok.contains("upload") || tok.contains("file") || tok.contains("media") {
                    out.insert(resolve_url(base, tok));
                }
            }
            if tok.starts_with("http") && (tok.contains("upload") || tok.contains("s3")) {
                out.insert(tok.to_string());
            }
        }
    }
    out
}

fn parse_openapi_upload_endpoints(spec: &Value, base: &str) -> Vec<Endpoint> {
    let mut out = Vec::new();
    let paths = spec.get("paths").and_then(Value::as_object);
    let Some(paths) = paths else {
        return out;
    };
    for (path, methods) in paths {
        let Some(methods) = methods.as_object() else {
            continue;
        };
        for (method, op) in methods {
            if !matches!(method.as_str(), "post" | "put" | "patch") {
                continue;
            }
            let rb = op.get("requestBody").and_then(|rb| rb.get("content"));
            let Some(content) = rb.and_then(Value::as_object) else {
                continue;
            };
            let is_multipart = content.contains_key("multipart/form-data");
            let is_json_b64 = content.get("application/json").is_some();
            if !is_multipart && !is_json_b64 {
                continue;
            }
            let url = resolve_url(base, path);
            let field = op
                .get("operationId")
                .and_then(Value::as_str)
                .unwrap_or("file")
                .to_string();
            out.push(Endpoint {
                url,
                field,
                source: format!("openapi_{method}"),
                protocol: if is_multipart {
                    EndpointProtocol::Multipart
                } else {
                    EndpointProtocol::Base64Json
                },
            });
        }
    }
    out
}

fn fingerprint_stack(page_headers: &[(String, String)], body: &str) -> StackHint {
    let mut s = StackHint::default();
    let server = header_value(page_headers, "server")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let powered = header_value(page_headers, "x-powered-by")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let body_lc = body.to_ascii_lowercase();

    if server.contains("nginx") {
        s.nginx = true;
        s.labels.push("nginx".into());
    }
    if server.contains("apache") {
        s.apache = true;
        s.labels.push("apache".into());
    }
    if powered.contains("php") || body_lc.contains("php/") {
        s.php = true;
        s.labels.push("php".into());
    }
    if server.contains("microsoft-iis") || powered.contains("asp.net") {
        s.iis = true;
        s.dotnet = true;
        s.labels.push("iis".into());
        s.labels.push("dotnet".into());
    }
    if body_lc.contains("wp-content") || body_lc.contains("wordpress") {
        s.wordpress = true;
        s.labels.push("wordpress".into());
    }
    if body_lc.contains("react") || body_lc.contains("__next") || body_lc.contains("node") {
        s.node = true;
        s.labels.push("node".into());
    }
    if body_lc.contains("jsp") || body_lc.contains("jsessionid") || server.contains("tomcat") {
        s.java = true;
        s.labels.push("java".into());
    }
    s
}

fn stack_paths(stack: &StackHint) -> Vec<&'static str> {
    let mut paths = Vec::new();
    if stack.wordpress {
        paths.extend(["/wp-admin/async-upload.php", "/wp-json/wp/v2/media"]);
    }
    if stack.php {
        paths.extend(["/index.php/upload", "/upload.php"]);
    }
    if stack.java {
        paths.extend(["/upload/file", "/api/upload/file"]);
    }
    paths
}

fn extract_retrieval_urls(body: &str, base: &str, canary: &str) -> Vec<String> {
    let mut urls = HashSet::new();
    if let Ok(v) = serde_json::from_str::<Value>(body) {
        collect_json_urls(&v, base, &mut urls);
    }
    for prefix in ["http://", "https://", "/"] {
        let mut search_from = 0;
        while let Some(rel) = body[search_from..].find(prefix) {
            let idx = search_from + rel;
            let slice = &body[idx..];
            let end = slice
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '<' || c == ',')
                .unwrap_or(slice.len().min(512));
            let candidate = &slice[..end];
            if candidate.len() > 4 && (candidate.contains('/') || candidate.starts_with("http")) {
                let full = if candidate.starts_with("http") {
                    candidate.to_string()
                } else {
                    resolve_url(base, candidate)
                };
                urls.insert(full);
            }
            search_from = idx + 1;
            if search_from >= body.len() {
                break;
            }
        }
    }
    if body.contains(canary) {
        urls.insert(base.to_string());
    }
    urls.into_iter().collect()
}

fn collect_json_urls(v: &Value, base: &str, out: &mut HashSet<String>) {
    match v {
        Value::Object(map) => {
            for (k, val) in map {
                if matches!(
                    k.as_str(),
                    "url"
                        | "path"
                        | "location"
                        | "fileUrl"
                        | "downloadUrl"
                        | "src"
                        | "href"
                        | "key"
                        | "uri"
                ) {
                    if let Some(s) = val.as_str() {
                        if s.starts_with("http") || s.starts_with('/') {
                            out.insert(if s.starts_with("http") {
                                s.to_string()
                            } else {
                                resolve_url(base, s)
                            });
                        }
                    }
                }
                collect_json_urls(val, base, out);
            }
        }
        Value::Array(arr) => {
            for item in arr {
                collect_json_urls(item, base, out);
            }
        }
        _ => {}
    }
}

fn storage_path_oracle(base: &str, filename: &str) -> Vec<String> {
    let base = base.trim_end_matches('/');
    let fname = filename.rsplit('/').next().unwrap_or(filename);
    let mut paths = vec![
        format!("{base}/uploads/{fname}"),
        format!("{base}/upload/{fname}"),
        format!("{base}/files/{fname}"),
        format!("{base}/media/{fname}"),
        format!("{base}/storage/{fname}"),
        format!("{base}/assets/uploads/{fname}"),
        format!("{base}/public/uploads/{fname}"),
        format!("{base}/static/uploads/{fname}"),
        format!("{base}/wp-content/uploads/{fname}"),
        format!("{base}/content/uploads/{fname}"),
    ];
    paths.sort_unstable();
    paths.dedup();
    paths
}

fn minimal_zip(name: &str, content: &str) -> Vec<u8> {
    let name_bytes = name.as_bytes();
    let content_bytes = content.as_bytes();
    let crc: u32 = content_bytes
        .iter()
        .fold(0u32, |a, &b| a.wrapping_add(u32::from(b)));
    let mut out = Vec::new();
    // Local file header
    out.extend_from_slice(b"PK\x03\x04");
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&(content_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&(content_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(name_bytes);
    out.extend_from_slice(content_bytes);
    let cd_offset = out.len();
    // Central directory
    out.extend_from_slice(b"PK\x01\x02");
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&(content_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&(content_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(name_bytes);
    // End of central directory
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&(cd_offset as u32).to_le_bytes());
    out.extend_from_slice(&(cd_offset as u32).to_le_bytes());
    out.extend_from_slice(&((name_bytes.len() + content_bytes.len() + 30) as u16).to_le_bytes());
    out
}

// ── Bypass matrix ───────────────────────────────────────────────────────────────

fn bypass_matrix(canary: &str, stack: &StackHint, pack: &str, max_tier: u8) -> Vec<BypassCombo> {
    let gif = benign_gif_str().to_string();
    let svg =
        format!("<svg xmlns=\"http://www.w3.org/2000/svg\"><script>/*{canary}*/</script></svg>");
    let htaccess = format!("# Weissman benign marker\n# {canary}\n");
    let webconfig = format!("<!-- {canary} -->\n<configuration></configuration>");
    let pdf = format!("%PDF-1.4\n% {canary}\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF");
    let html_poly = format!("<!-- {canary} -->\n<html><body>WZ</body></html>");

    let mut combos = vec![
        combo(
            "test.jpg",
            "image/jpeg",
            &gif,
            "gif-as-jpeg",
            "mime_spoof",
            "high",
            "medium",
            1,
            DispositionMode::Standard,
        ),
        combo(
            "x.php.jpg",
            "image/jpeg",
            &gif,
            "double-extension-php",
            "double_extension",
            "critical",
            "high",
            1,
            DispositionMode::Standard,
        ),
        combo(
            "x.asp.jpg",
            "image/jpeg",
            &gif,
            "double-extension-asp",
            "double_extension",
            "critical",
            "high",
            2,
            DispositionMode::Standard,
        ),
        combo(
            "x.phtml",
            "image/jpeg",
            &gif,
            "phtml-mime-spoof",
            "mime_spoof",
            "critical",
            "high",
            2,
            DispositionMode::Standard,
        ),
        combo(
            "x.html",
            "image/gif",
            &gif,
            "html-mime-spoof",
            "mime_spoof",
            "high",
            "medium",
            1,
            DispositionMode::Standard,
        ),
        combo(
            "x.svg",
            "image/svg+xml",
            &svg,
            "svg-stored-xss-surface",
            "svg_xss",
            "critical",
            "high",
            1,
            DispositionMode::Standard,
        ),
        combo(
            "../../wztest.txt",
            "text/plain",
            canary,
            "path-traversal",
            "path_traversal",
            "high",
            "medium",
            1,
            DispositionMode::Standard,
        ),
        combo(
            "....//....//wztest.txt",
            "text/plain",
            canary,
            "path-traversal-encoded",
            "path_traversal",
            "high",
            "medium",
            2,
            DispositionMode::Standard,
        ),
        combo(
            "x.PhP",
            "application/octet-stream",
            &gif,
            "case-extension",
            "case_bypass",
            "critical",
            "high",
            2,
            DispositionMode::Standard,
        ),
        combo(
            "shell.php%00.jpg",
            "image/jpeg",
            &gif,
            "null-byte-legacy",
            "null_byte",
            "critical",
            "high",
            3,
            DispositionMode::Standard,
        ),
        combo(
            "test.php.",
            "image/jpeg",
            &gif,
            "trailing-dot-windows",
            "trailing_dot",
            "critical",
            "high",
            3,
            DispositionMode::Standard,
        ),
        combo(
            "test.php ",
            "image/jpeg",
            &gif,
            "trailing-space-windows",
            "trailing_dot",
            "critical",
            "high",
            3,
            DispositionMode::Standard,
        ),
        combo(
            ".htaccess",
            "text/plain",
            &htaccess,
            "htaccess-config",
            "config_upload",
            "critical",
            "high",
            2,
            DispositionMode::Standard,
        ),
        combo(
            "web.config",
            "text/xml",
            &webconfig,
            "webconfig-upload",
            "config_upload",
            "critical",
            "high",
            2,
            DispositionMode::Standard,
        ),
        combo(
            ".env",
            "text/plain",
            canary,
            "dotenv-upload",
            "config_upload",
            "critical",
            "high",
            2,
            DispositionMode::Standard,
        ),
        combo(
            "polyglot.gif",
            "image/gif",
            &gif,
            "polyglot-gif",
            "polyglot",
            "high",
            "medium",
            2,
            DispositionMode::Standard,
        ),
        combo(
            "doc.pdf",
            "application/pdf",
            &pdf,
            "pdf-polyglot",
            "polyglot",
            "high",
            "medium",
            2,
            DispositionMode::Standard,
        ),
        combo(
            "page.html",
            "text/html",
            &html_poly,
            "html-upload",
            "polyglot",
            "critical",
            "high",
            2,
            DispositionMode::Standard,
        ),
        combo(
            "shell.php",
            "image/jpeg",
            &gif,
            "rfc5987-filename-star",
            "disposition_bypass",
            "high",
            "medium",
            2,
            DispositionMode::Rfc5987Utf8,
        ),
        combo(
            "x.php.jpg",
            "",
            &gif,
            "empty-content-type",
            "disposition_bypass",
            "high",
            "medium",
            2,
            DispositionMode::EmptyMime,
        ),
        combo(
            "x.php.jpg",
            "application/octet-stream",
            &gif,
            "octet-stream-mime",
            "mime_spoof",
            "high",
            "medium",
            2,
            DispositionMode::OctetStream,
        ),
        combo(
            ".user.ini",
            "text/plain",
            &format!("; {canary}\nauto_prepend_file=\n"),
            "user-ini-php-fpm",
            "config_upload",
            "critical",
            "high",
            2,
            DispositionMode::Standard,
        ),
        combo(
            "crossdomain.xml",
            "text/xml",
            &format!("<cross-domain-policy><!-- {canary} --></cross-domain-policy>"),
            "crossdomain-policy",
            "config_upload",
            "high",
            "medium",
            2,
            DispositionMode::Standard,
        ),
        combo(
            "shell.p\u{0430}hp",
            "image/jpeg",
            &gif,
            "unicode-homoglyph-cyrillic",
            "unicode_homoglyph",
            "critical",
            "high",
            2,
            DispositionMode::Standard,
        ),
        combo(
            "shell.%70hp",
            "image/jpeg",
            &gif,
            "url-encoded-extension-p",
            "url_encoded_ext",
            "critical",
            "high",
            2,
            DispositionMode::Standard,
        ),
        combo(
            "shell.p%68p",
            "image/jpeg",
            &gif,
            "url-encoded-extension-h",
            "url_encoded_ext",
            "critical",
            "high",
            2,
            DispositionMode::Standard,
        ),
        combo(
            &format!("{}.php.jpg", "a".repeat(180)),
            "image/jpeg",
            &gif,
            "long-filename-parser",
            "long_filename",
            "high",
            "medium",
            2,
            DispositionMode::Standard,
        ),
        combo(
            "photo.jpg.php",
            "image/jpeg",
            &gif,
            "reverse-double-ext-jpg-php",
            "reverse_double_extension",
            "critical",
            "high",
            2,
            DispositionMode::Standard,
        ),
        combo(
            "image.gif.php",
            "image/gif",
            &gif,
            "reverse-double-ext-gif-php",
            "reverse_double_extension",
            "critical",
            "high",
            2,
            DispositionMode::Standard,
        ),
        combo(
            "....%252f....%252fwztest.txt",
            "text/plain",
            canary,
            "double-url-encoding-traversal",
            "path_traversal",
            "high",
            "medium",
            2,
            DispositionMode::Standard,
        ),
        combo(
            ".htpasswd",
            "text/plain",
            &format!("wzuser:$apr1$benign${canary}\n"),
            "htpasswd-credential-file",
            "config_upload",
            "critical",
            "high",
            2,
            DispositionMode::Standard,
        ),
        combo(
            "{{7*7}}.txt",
            "text/plain",
            canary,
            "ssti-filename-oracle",
            "template_injection",
            "high",
            "medium",
            2,
            DispositionMode::Standard,
        ),
        combo(
            "shell.php;.jpg",
            "image/jpeg",
            &gif,
            "semicolon-mid-extension",
            "semicolon_bypass",
            "critical",
            "high",
            2,
            DispositionMode::Standard,
        ),
        combo(
            "shell.php.foo",
            "image/jpeg",
            &gif,
            "apache-php-foo-suffix",
            "apache_multisuffix",
            "critical",
            "high",
            2,
            DispositionMode::Standard,
        ),
        combo(
            &format!("shell\u{202E}gpj.php"),
            "image/jpeg",
            &gif,
            "rtlo-filename-bidi",
            "rtlo_bypass",
            "critical",
            "high",
            2,
            DispositionMode::Standard,
        ),
        combo(
            "shell.ｐｈｐ",
            "image/jpeg",
            &gif,
            "nfkc-fullwidth-php",
            "nfkc_bypass",
            "critical",
            "high",
            2,
            DispositionMode::Standard,
        ),
        combo(
            "shell.php%0a.jpg",
            "image/jpeg",
            &gif,
            "newline-in-extension",
            "newline_extension",
            "high",
            "medium",
            3,
            DispositionMode::Standard,
        ),
    ];

    let use_php = pack == "all" || pack == "php" || (pack == "auto" && stack.php);
    let use_iis = pack == "all" || pack == "iis" || (pack == "auto" && stack.iis);
    let use_dotnet = pack == "all" || pack == "dotnet" || (pack == "auto" && stack.dotnet);
    let use_java = pack == "all" || pack == "java" || (pack == "auto" && stack.java);
    let use_node = pack == "all" || pack == "node" || (pack == "auto" && stack.node);

    if use_php {
        combos.extend([
            combo(
                "shell.php5",
                "image/jpeg",
                &gif,
                "php5-extension",
                "platform_php",
                "critical",
                "high",
                2,
                DispositionMode::Standard,
            ),
            combo(
                "shell.phar",
                "application/octet-stream",
                &gif,
                "phar-extension",
                "platform_php",
                "critical",
                "high",
                2,
                DispositionMode::Standard,
            ),
            combo(
                "shell.php7",
                "image/jpeg",
                &gif,
                "php7-extension",
                "platform_php",
                "critical",
                "high",
                2,
                DispositionMode::Standard,
            ),
        ]);
    }
    if use_iis {
        combos.extend([
            combo(
                "shell.aspx;.jpg",
                "image/jpeg",
                &gif,
                "iis-semicolon-aspx",
                "platform_iis",
                "critical",
                "high",
                2,
                DispositionMode::Standard,
            ),
            combo(
                "shell.asp;.gif",
                "image/gif",
                &gif,
                "iis-semicolon-asp",
                "platform_iis",
                "critical",
                "high",
                2,
                DispositionMode::Standard,
            ),
            combo(
                "shell.ashx",
                "image/jpeg",
                &gif,
                "iis-ashx-handler",
                "iis_handlers",
                "critical",
                "high",
                2,
                DispositionMode::Standard,
            ),
            combo(
                "shell.asmx",
                "text/xml",
                &format!("<!-- {canary} -->\n"),
                "iis-asmx-handler",
                "iis_handlers",
                "critical",
                "high",
                2,
                DispositionMode::Standard,
            ),
            combo(
                "shell.shtml",
                "text/html",
                &format!("<!-- {canary} -->\n"),
                "iis-shtml-handler",
                "iis_handlers",
                "critical",
                "high",
                2,
                DispositionMode::Standard,
            ),
        ]);
    }
    if use_dotnet {
        combos.extend([
            combo(
                "shell.aspx",
                "image/jpeg",
                &gif,
                "aspx-mime-spoof",
                "platform_dotnet",
                "critical",
                "high",
                2,
                DispositionMode::Standard,
            ),
            combo(
                "shell.cer",
                "application/pkix-cert",
                &gif,
                "cer-extension",
                "platform_dotnet",
                "critical",
                "high",
                3,
                DispositionMode::Standard,
            ),
        ]);
    }
    if use_java {
        combos.extend([
            combo(
                "shell.jsp",
                "image/jpeg",
                &gif,
                "jsp-mime-spoof",
                "platform_java",
                "critical",
                "high",
                2,
                DispositionMode::Standard,
            ),
            combo(
                "shell.jspx",
                "image/jpeg",
                &gif,
                "jspx-mime-spoof",
                "platform_java",
                "critical",
                "high",
                2,
                DispositionMode::Standard,
            ),
        ]);
    }
    if use_node {
        combos.extend([
            combo(
                "shell.js",
                "image/jpeg",
                &gif,
                "js-static-exec-surface",
                "platform_node",
                "high",
                "medium",
                2,
                DispositionMode::Standard,
            ),
            combo(
                "shell.mjs",
                "application/javascript",
                &gif,
                "mjs-module-surface",
                "platform_node",
                "high",
                "medium",
                2,
                DispositionMode::Standard,
            ),
        ]);
    }
    if max_tier >= 3 {
        combos.push(combo(
            "shell.php::$DATA",
            "image/jpeg",
            &gif,
            "ntfs-ads-stream",
            "platform_iis",
            "critical",
            "high",
            3,
            DispositionMode::Standard,
        ));
    }

    combos.retain(|c| c.tier <= max_tier);
    combos
}

fn combo(
    filename: &str,
    content_type: &str,
    content: &str,
    label: &str,
    category: &str,
    sev_ret: &'static str,
    sev_acc: &'static str,
    tier: u8,
    disposition: DispositionMode,
) -> BypassCombo {
    BypassCombo {
        filename: filename.to_string(),
        content_type: content_type.to_string(),
        content: content.to_string(),
        label: label.to_string(),
        category: category.to_string(),
        severity_if_retrieved: sev_ret,
        severity_if_accepted: sev_acc,
        tier,
        disposition,
    }
}

// ── Findings / posture ──────────────────────────────────────────────────────────

async fn verify_retrieval(
    client: &Client,
    urls: &[String],
    canary: &str,
    gif_marker: bool,
) -> Option<(String, String, bool, bool, bool, bool)> {
    for url in urls {
        if let Some(stored) = http_get(client, url).await {
            let ct = header_value(&stored.headers, "content-type").unwrap_or_default();
            let nosniff = header_value(&stored.headers, "x-content-type-options")
                .map(|v| v.to_ascii_lowercase().contains("nosniff"))
                .unwrap_or(false);
            let cd = header_value(&stored.headers, "content-disposition").unwrap_or_default();
            let inline = !cd.to_ascii_lowercase().contains("attachment");
            let cors = header_value(&stored.headers, "access-control-allow-origin")
                .map(|v| v == "*" || v.contains("null"))
                .unwrap_or(false);
            let has_canary = stored.body.contains(canary)
                || (gif_marker && stored.body.contains("GIF89a"))
                || stored.body.contains("<svg")
                || stored.body.contains("%PDF");
            if has_canary && matches!(stored.status, 200 | 201 | 206) {
                let exec_hint = ct.contains("html")
                    || ct.contains("svg")
                    || ct.contains("php")
                    || ct.contains("x-httpd")
                    || ct.contains("octet-stream")
                    || ct.contains("javascript")
                    || url.to_ascii_lowercase().ends_with(".php")
                    || url.to_ascii_lowercase().ends_with(".phtml")
                    || url.to_ascii_lowercase().ends_with(".aspx")
                    || url.to_ascii_lowercase().ends_with(".jsp");
                return Some((stored.final_url, ct, exec_hint, !nosniff, cors, inline));
            }
        }
    }
    None
}

fn make_finding(
    title: &str,
    severity: &str,
    description: &str,
    target: &str,
    category: &str,
    confidence: f64,
    exposure: &UploadExposure,
    endpoint: &Endpoint,
    remediation: &str,
) -> Value {
    let mut ev = Evidence::new()
        .with("endpoint", endpoint.url.clone())
        .with("field", endpoint.field.clone())
        .with("source", endpoint.source.clone())
        .with("combo", exposure.combo.clone())
        .with("category", exposure.category.clone())
        .with("accepted", json!(exposure.accepted))
        .with("retrieved", json!(exposure.retrieved));
    if let Some(u) = &exposure.retrieve_url {
        ev = ev.with("retrieve_url", u.clone());
    }
    if let Some(ct) = &exposure.retrieve_content_type {
        ev = ev.with("retrieve_content_type", ct.clone());
    }
    if exposure.execution_hint {
        ev = ev.with("execution_context_hint", json!(true));
    }
    if exposure.nosniff_missing {
        ev = ev.with("x_content_type_options_missing", json!(true));
    }
    if exposure.cors_permissive {
        ev = ev.with("permissive_cors_on_upload", json!(true));
    }
    if exposure.inline_served {
        ev = ev.with("content_disposition_inline", json!(true));
    }
    let mut f = finding_rich(
        ENGINE_ID,
        title,
        severity,
        MITRE,
        description,
        target,
        confidence,
        ev,
    );
    if let Some(obj) = f.as_object_mut() {
        obj.insert("category".to_string(), json!(category));
        obj.insert("exposure".to_string(), json!("present"));
        obj.insert("remediation".to_string(), json!(remediation));
        obj.insert(
            "controls".to_string(),
            json!(["CWE-434", "CWE-73", "OWASP-A04:2021", "WSTG-INPV-012"]),
        );
    }
    f
}

fn synthesize_attack_paths(exposures: &[UploadExposure]) -> Vec<Value> {
    let mut paths = Vec::new();
    let exec = exposures
        .iter()
        .filter(|e| e.retrieved && e.execution_hint)
        .collect::<Vec<_>>();
    if !exec.is_empty() {
        paths.push(json!({
            "title": "Unrestricted upload → remote code execution chain",
            "severity": "critical",
            "stages": ["Bypass accepted", "File retrievable from web", "Executable MIME or script extension served"],
            "combos": exec.iter().map(|e| &e.combo).collect::<Vec<_>>(),
            "mitre": ["T1190", "T1204.002", "T1059"],
        }));
    }
    let config = exposures
        .iter()
        .filter(|e| e.retrieved && e.category == "config_upload")
        .count();
    if config > 0 {
        paths.push(json!({
            "title": "Config file upload → server rewrite / handler takeover",
            "severity": "critical",
            "stages": [".htaccess / web.config / .env written", "Server honors attacker-controlled config"],
            "mitre": ["T1190", "T1505"],
        }));
    }
    if exposures
        .iter()
        .any(|e| e.retrieved && e.category == "svg_xss")
    {
        paths.push(json!({
            "title": "SVG upload → stored cross-site scripting",
            "severity": "critical",
            "stages": ["SVG accepted", "SVG served inline to victims"],
            "mitre": ["T1189", "T1059.007"],
        }));
    }
    if exposures
        .iter()
        .any(|e| e.retrieved && e.nosniff_missing && e.inline_served)
    {
        paths.push(json!({
            "title": "MIME sniffing + inline disposition → browser execution",
            "severity": "high",
            "stages": ["Upload retrievable", "No nosniff", "Content-Disposition inline"],
            "mitre": ["T1189"],
        }));
    }
    if exposures
        .iter()
        .any(|e| e.category == "upload_idor" && e.retrieved)
    {
        paths.push(json!({
            "title": "Upload IDOR → cross-user file access",
            "severity": "critical",
            "stages": ["Predictable object ID in upload response", "Adjacent ID returns same user's upload", "Any authenticated user may fetch others' files"],
            "mitre": ["T1190", "T1530"],
        }));
    }
    if exposures
        .iter()
        .any(|e| e.category == "eicar_surface" && e.accepted)
    {
        paths.push(json!({
            "title": "AV pipeline absent → malware staging",
            "severity": "high",
            "stages": ["EICAR test string accepted without AV block", "Attacker can stage real malware via same channel"],
            "mitre": ["T1204.002", "T1105"],
        }));
    }
    if exposures
        .iter()
        .any(|e| e.category == "batch_upload" && e.accepted)
    {
        paths.push(json!({
            "title": "Batch upload → spray payloads at scale",
            "severity": "high",
            "stages": ["Multi-file single request accepted", "Rate limits may not count per inner file"],
            "mitre": ["T1499", "T1190"],
        }));
    }
    paths
}

fn compute_posture_dimensions(exposures: &[UploadExposure]) -> Value {
    let dim = |cat: &str| -> u32 {
        if exposures.iter().any(|e| e.category == cat && e.retrieved) {
            12
        } else if exposures.iter().any(|e| e.category == cat && e.accepted) {
            42
        } else {
            96
        }
    };
    json!({
        "extension_validation": dim("double_extension").min(dim("platform_php")).min(dim("platform_iis")),
        "mime_validation": dim("mime_spoof").min(dim("disposition_bypass")),
        "content_inspection": dim("polyglot"),
        "storage_isolation": if exposures.iter().any(|e| e.retrieved) { 15 } else { 92 },
        "config_upload_resistance": dim("config_upload"),
        "path_traversal_resistance": dim("path_traversal"),
        "platform_hardening": dim("platform_php").min(dim("platform_java")).min(dim("platform_dotnet")),
        "delivery_hardening": if exposures.iter().any(|e| e.nosniff_missing) { 25 } else { 90 },
        "cors_isolation": if exposures.iter().any(|e| e.cors_permissive) { 20 } else { 95 },
        "authz_boundary": if exposures.iter().any(|e| e.category == "upload_idor") { 10 } else if exposures.iter().any(|e| e.accepted) { 50 } else { 95 },
        "object_id_entropy": if exposures.iter().any(|e| e.category == "upload_idor") { 15 } else { 92 },
        "resumable_protocol_hygiene": dim("tus_surface"),
        "anonymous_download": if exposures.iter().any(|e| e.category == "unauth_retrieval") { 8 } else { 94 },
        "cache_isolation": if exposures.iter().any(|e| e.category == "cdn_cache_exposure") { 18 } else { 91 },
        "abuse_resilience": if exposures.iter().any(|e| e.category == "rate_limit_absence" || e.category == "upload_cors") { 22 } else { 93 },
        "error_hygiene": if exposures.iter().any(|e| e.category == "error_disclosure") { 28 } else { 94 },
        "template_injection_surface": dim("template_injection"),
        "av_pipeline": if exposures.iter().any(|e| e.category == "eicar_surface" && e.accepted) { 18 } else { 94 },
        "batch_upload_control": if exposures.iter().any(|e| e.category == "batch_upload" && e.accepted) { 25 } else { 93 },
        "parser_robustness": if exposures.iter().any(|e| {
            e.category == "boundary_smuggling" || e.category == "double_disposition" || e.category == "filename_mismatch"
        }) {
            20
        } else {
            92
        },
        "path_entropy_quality": aggregate_path_entropy(exposures),
        "overwrite_protection": if exposures.iter().any(|e| e.category == "overwrite_oracle" && e.retrieved) {
            18
        } else {
            91
        },
        "host_header_isolation": if exposures.iter().any(|e| e.category == "x_forwarded_host") {
            22
        } else {
            93
        },
    })
}

fn build_hardening_roadmap(findings: &[Value], stack: &StackHint) -> Vec<String> {
    let mut steps = Vec::new();
    let cats: BTreeSet<String> = findings
        .iter()
        .filter_map(|f| f.get("category").and_then(Value::as_str))
        .filter(|c| *c != "posture_summary" && *c != "endpoint_discovery")
        .map(str::to_string)
        .collect();
    if cats
        .iter()
        .any(|c| c.contains("platform_") || c == "double_extension")
    {
        steps.push("Server-side allow-list extensions; strip trailing dots/spaces/null bytes; reject multi-dot executable suffixes.".into());
    }
    if cats.contains("mime_spoof")
        || cats.contains("polyglot")
        || cats.contains("disposition_bypass")
    {
        steps.push("Validate magic bytes; re-encode images server-side; ignore client Content-Type and RFC5987 filename* unless strictly validated.".into());
    }
    if cats.contains("svg_xss") || cats.contains("polyglot") {
        steps.push("Block SVG/HTML uploads or sanitize via dedicated pipeline; serve from isolated CDN with strict CSP.".into());
    }
    if cats.contains("config_upload") {
        steps.push("Deny .htaccess, web.config, .env, .user.ini; store uploads outside webroot with random object keys.".into());
    }
    if cats.contains("path_traversal") {
        steps.push("Canonicalize filenames; reject .. and encoded traversal; never use user filename on disk.".into());
    }
    if cats.contains("upload_idor") {
        steps.push("Use opaque UUID object keys; authorize every download; never expose sequential file IDs in API responses.".into());
    }
    if cats.contains("unicode_homoglyph") {
        steps.push("Normalize Unicode filenames (NFKC); reject mixed-script extensions and homoglyph attacks.".into());
    }
    if cats.contains("tus_surface") {
        steps.push("If using Tus/resumable uploads, require auth on creation + PATCH; bind Upload-Metadata to session.".into());
    }
    if cats.contains("directory_listing") {
        steps.push(
            "Disable directory listing on all storage roots; use opaque object keys in CDN URLs."
                .into(),
        );
    }
    if cats.contains("upload_cors") {
        steps.push("Never echo Access-Control-Allow-Origin on upload routes; block cross-origin POST without explicit allow-list.".into());
    }
    if cats.contains("rate_limit_absence") {
        steps.push("Apply per-IP and per-session rate limits on upload creation; return 429 with Retry-After.".into());
    }
    if cats.contains("error_disclosure") {
        steps.push("Return generic upload errors; log stack traces server-side only.".into());
    }
    if cats.contains("template_injection")
        || cats.contains("iis_handlers")
        || cats.contains("reverse_double_extension")
    {
        steps.push("Reject template-like filenames and reverse double-extensions; normalize to server-generated keys.".into());
    }
    if cats.contains("delete_without_auth") {
        steps.push(
            "Require authorization on DELETE for all stored objects; audit object lifecycle APIs."
                .into(),
        );
    }
    if cats.contains("eicar_surface") {
        steps.push(
            "Integrate AV/AMSI scanning on upload; block EICAR and quarantine before persistence."
                .into(),
        );
    }
    if cats.contains("batch_upload") || cats.contains("json_multi_file") {
        steps.push(
            "Allow only one file per request; cap JSON files[] array length and total bytes."
                .into(),
        );
    }
    if cats.contains("filename_mismatch")
        || cats.contains("double_disposition")
        || cats.contains("boundary_smuggling")
    {
        steps.push("Use strict multipart parser; reject duplicate Content-Disposition and metadata/body filename conflicts.".into());
    }
    if findings.iter().any(|f| {
        f.get("evidence")
            .and_then(|e| e.get("x_content_type_options_missing"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }) {
        steps.push("Serve uploads with X-Content-Type-Options: nosniff and Content-Disposition: attachment.".into());
    }
    if stack.wordpress {
        steps.push("WordPress: restrict upload capabilities; scan wp-content/uploads; disable XML-RPC if unused.".into());
    }
    if steps.is_empty() {
        steps.push("Maintain deny-by-default upload policy with out-of-webroot storage and virus scanning.".into());
    }
    steps
}

fn build_summary(
    target: &str,
    base: &str,
    findings: &[Value],
    endpoints_found: usize,
    exposures: &[UploadExposure],
    intensity: Intensity,
    stack: &StackHint,
    coverage: Value,
) -> Value {
    let mut crit = 0u32;
    let mut high = 0u32;
    let mut med = 0u32;
    let mut low = 0u32;
    let mut worst = "info";
    let mut categories: BTreeSet<String> = BTreeSet::new();
    for f in findings {
        let sev = f.get("severity").and_then(Value::as_str).unwrap_or("");
        match sev {
            "critical" => crit += 1,
            "high" => high += 1,
            "medium" => med += 1,
            "low" => low += 1,
            _ => {}
        }
        if severity_rank(sev) > severity_rank(worst) {
            worst = sev;
        }
        if let Some(c) = f.get("category").and_then(Value::as_str) {
            if c != "posture_summary" {
                categories.insert(c.to_string());
            }
        }
    }
    let penalty = crit * 30 + high * 13 + med * 5 + low * 2;
    let score = 100u32
        .saturating_sub(penalty)
        .max(if crit > 0 { 0 } else { 5 });
    let grade = match score {
        92..=100 => "A",
        80..=91 => "B",
        65..=79 => "C",
        45..=64 => "D",
        _ => "F",
    };
    let cats: Vec<String> = categories.iter().cloned().collect();
    let posture_dimensions = compute_posture_dimensions(exposures);
    let attack_paths = synthesize_attack_paths(exposures);
    let roadmap = build_hardening_roadmap(findings, stack);
    let retrieved = exposures.iter().filter(|e| e.retrieved).count();
    let blast_radius = compute_blast_radius(exposures, endpoints_found);
    let toxic = synthesize_toxic_combinations(exposures);
    let enterprise_tier = enterprise_risk_tier(blast_radius, crit);
    let path_entropy = aggregate_path_entropy(exposures);
    let remediation_urgency = compute_remediation_urgency(blast_radius, crit, high, score);

    let description = if crit == 0 && high == 0 && med == 0 {
        format!(
            "No unrestricted upload primitive verified on {} ({} live endpoint(s), stack: {}). Score {}/100 ({}).",
            base,
            endpoints_found,
            if stack.labels.is_empty() {
                "unknown".to_string()
            } else {
                stack.labels.join(", ")
            },
            score,
            grade
        )
    } else {
        format!(
            "File upload posture {} — {}/100 ({}). {} endpoint(s), {} retrievable. {} critical / {} high / {} medium. Stack: {}.",
            base,
            score,
            grade,
            endpoints_found,
            retrieved,
            crit,
            high,
            med,
            if stack.labels.is_empty() {
                "unknown".to_string()
            } else {
                stack.labels.join(", ")
            }
        )
    };

    let ev = Evidence::new()
        .with("base_url", base.to_string())
        .with("posture_score", json!(score))
        .with("grade", grade)
        .with("endpoints_discovered", json!(endpoints_found))
        .with("intensity", intensity.as_str())
        .with("stack_fingerprint", json!(stack.labels.clone()))
        .with(
            "severity_breakdown",
            json!({ "critical": crit, "high": high, "medium": med, "low": low }),
        )
        .with("weak_categories", json!(cats.clone()))
        .with("posture_dimensions", posture_dimensions.clone())
        .with("attack_paths", json!(attack_paths.clone()))
        .with("blast_radius_score", json!(blast_radius))
        .with("enterprise_risk_tier", json!(enterprise_tier))
        .with("path_entropy_score", json!(path_entropy))
        .with("remediation_urgency", json!(remediation_urgency))
        .with("toxic_combinations", json!(toxic.clone()))
        .with("probe_coverage", coverage.clone());

    let mut summary = finding_rich(
        ENGINE_ID,
        &format!("File upload posture score {}/100 (grade {})", score, grade),
        "info",
        MITRE,
        &description,
        target,
        0.99,
        ev,
    );
    if let Some(obj) = summary.as_object_mut() {
        obj.insert("category".to_string(), json!("posture_summary"));
        obj.insert("summary".to_string(), json!(true));
        obj.insert("posture_score".to_string(), json!(score));
        obj.insert("grade".to_string(), json!(grade));
        obj.insert("worst_severity".to_string(), json!(worst));
        obj.insert("weak_categories".to_string(), json!(cats));
        obj.insert("posture_dimensions".to_string(), posture_dimensions);
        obj.insert("attack_paths".to_string(), json!(attack_paths));
        obj.insert("hardening_roadmap".to_string(), json!(roadmap));
        obj.insert("blast_radius_score".to_string(), json!(blast_radius));
        obj.insert("enterprise_risk_tier".to_string(), json!(enterprise_tier));
        obj.insert("path_entropy_score".to_string(), json!(path_entropy));
        obj.insert(
            "remediation_urgency".to_string(),
            json!(remediation_urgency),
        );
        obj.insert("toxic_combinations".to_string(), json!(toxic));
        obj.insert("probe_coverage".to_string(), coverage);
        obj.insert("stack_fingerprint".to_string(), json!(stack.labels));
        obj.insert(
            "remediation".to_string(),
            json!("Deny-by-default upload: allow-list + magic bytes + random keys + out-of-webroot storage + nosniff + attachment disposition + isolated CDN origin."),
        );
    }
    summary
}

// ── Main runner ─────────────────────────────────────────────────────────────────

pub async fn run_file_upload_result_ctx(target: &str, ctx: &EngineRunContext) -> EngineResult {
    if target.trim().is_empty() {
        return EngineResult::error("target required");
    }
    let cfg = ArsenalConfig::from_ctx(ctx);
    let intensity = cfg.intensity();
    let max_tier = match intensity {
        Intensity::Light => 1,
        Intensity::Normal => 2,
        Intensity::Aggressive => 3,
    };
    let timeout_ms = cfg.timeout_ms(8000);
    let concurrency = cfg.concurrency().clamp(1, 48);
    let include_info = cfg.bool_or("include_info_findings", true);
    let verify_storage = cfg.bool_or("verify_storage", true);
    let check_put = cfg.bool_or("check_put_upload", true);
    let check_patch = cfg.bool_or("check_patch_upload", true);
    let check_graphql = cfg.bool_or("check_graphql_upload", true);
    let check_base64 = cfg.bool_or("check_base64_json", true);
    let check_zip = cfg.bool_or("check_zip_upload", true);
    let check_js_discovery = cfg.bool_or("check_js_discovery", true);
    let check_openapi = cfg.bool_or("check_openapi_discovery", true);
    let check_upload_idor = cfg.bool_or("check_upload_idor", true);
    let check_tus = cfg.bool_or("check_tus_upload", true);
    let check_webdav = cfg.bool_or("check_webdav_discovery", true);
    let check_auth_diff = cfg.bool_or("check_auth_differential", true);
    let check_hpp = cfg.bool_or("check_multipart_hpp", true);
    let check_size_oracle = cfg.bool_or("check_size_limit_oracle", false);
    let check_dir_listing = cfg.bool_or("check_directory_listing", true);
    let check_presigned = cfg.bool_or("check_presigned_probe", true);
    let check_content_range = cfg.bool_or("check_content_range", true);
    let check_cms_paths = cfg.bool_or("check_cms_paths", true);
    let check_unauth_retrieval = cfg.bool_or("check_unauth_retrieval", true);
    let check_cdn_cache = cfg.bool_or("check_cdn_cache_isolation", true);
    let check_waf_fp = cfg.bool_or("check_waf_fingerprint", true);
    let check_robots = cfg.bool_or("check_robots_discovery", true);
    let check_jpeg_com = cfg.bool_or("check_jpeg_com_polyglot", true);
    let check_docx = cfg.bool_or("check_docx_surface", true);
    let check_crlf_reflection = cfg.bool_or("check_crlf_filename_reflection", true);
    let storage_oracle = cfg.bool_or("storage_path_oracle", true);
    let check_upload_cors = cfg.bool_or("check_upload_cors", true);
    let check_rate_limit = cfg.bool_or("check_rate_limit_absence", true);
    let check_error_disclosure = cfg.bool_or("check_error_disclosure", true);
    let check_delete_unauth = cfg.bool_or("check_delete_without_auth", true);
    let check_range_retrieval = cfg.bool_or("check_range_retrieval", true);
    let check_sitemap = cfg.bool_or("check_sitemap_discovery", true);
    let check_template = cfg.bool_or("check_template_injection_filename", true);
    let check_spring_paths = cfg.bool_or("check_spring_paths", true);
    let check_sharepoint = cfg.bool_or("check_sharepoint_paths", true);
    let check_eicar = cfg.bool_or("check_eicar_surface", true);
    let check_batch = cfg.bool_or("check_batch_upload", true);
    let check_webp_png = cfg.bool_or("check_webp_png_surface", true);
    let check_filename_mismatch = cfg.bool_or("check_filename_field_mismatch", true);
    let check_double_disp = cfg.bool_or("check_double_content_disposition", true);
    let check_boundary_smuggle = cfg.bool_or("check_boundary_smuggling", true);
    let check_json_multi = cfg.bool_or("check_json_multi_file", true);
    let check_imagemagick = cfg.bool_or("check_imagemagick_surface", true);
    let check_svg_foreign = cfg.bool_or("check_svg_foreign_object", true);
    let check_internal_urls = cfg.bool_or("check_internal_url_disclosure", true);
    let check_cloud_native = cfg.bool_or("check_cloud_native_paths", true);
    let check_security_txt = cfg.bool_or("check_security_txt_discovery", true);
    let check_gzip_upload = cfg.bool_or("check_gzip_upload", true);
    let check_expect_continue = cfg.bool_or("check_expect_continue", true);
    let check_x_forwarded_host = cfg.bool_or("check_x_forwarded_host", true);
    let check_location_leak = cfg.bool_or("check_location_header_leak", true);
    let check_overwrite = cfg.bool_or("check_overwrite_oracle", true);
    let check_head_meta = cfg.bool_or("check_head_metadata_leak", true);
    let check_xlsm = cfg.bool_or("check_xlsm_surface", true);
    let check_pdf_js = cfg.bool_or("check_pdf_js_surface", true);
    let max_endpoints = cfg.usize_or("max_endpoints", 32).clamp(1, 96);
    let max_combos = cfg.usize_or("max_combos_per_endpoint", 28).clamp(1, 80);
    let stack_pack = cfg.string_or("stack_pack", "auto");

    let canary = cfg.string_or("canary_token", DEFAULT_CANARY);
    let canary_b = format!("{canary}_OVERWRITE_B");

    let category_enabled = |cat: &str| -> bool {
        match cat {
            "mime_spoof" | "disposition_bypass" => cfg.bool_or("check_mime_spoof", true),
            "double_extension" => cfg.bool_or("check_double_extension", true),
            "polyglot" => cfg.bool_or("check_polyglot", true),
            "path_traversal" => cfg.bool_or("check_path_traversal", true),
            "case_bypass" => cfg.bool_or("check_case_bypass", true),
            "null_byte" => cfg.bool_or("check_null_byte", false),
            "trailing_dot" => cfg.bool_or("check_trailing_dot", false),
            "svg_xss" => cfg.bool_or("check_svg_xss", true),
            "config_upload" => cfg.bool_or("check_config_upload", true),
            "platform_php" => cfg.bool_or("check_php_bypass", true),
            "platform_iis" => cfg.bool_or("check_iis_bypass", true),
            "platform_dotnet" => cfg.bool_or("check_dotnet_bypass", true),
            "platform_java" => cfg.bool_or("check_java_bypass", true),
            "platform_node" => cfg.bool_or("check_node_bypass", true),
            "unicode_homoglyph" => cfg.bool_or("check_unicode_homoglyph", true),
            "url_encoded_ext" => cfg.bool_or("check_url_encoded_extension", true),
            "long_filename" => cfg.bool_or("check_long_filename", true),
            "reverse_double_extension" => cfg.bool_or("check_reverse_double_extension", true),
            "iis_handlers" => cfg.bool_or("check_iis_handlers", true),
            "template_injection" => cfg.bool_or("check_template_injection_filename", true),
            "semicolon_bypass" => cfg.bool_or("check_semicolon_bypass", true),
            "apache_multisuffix" => cfg.bool_or("check_apache_multisuffix", true),
            "rtlo_bypass" => cfg.bool_or("check_rtlo_bypass", true),
            "nfkc_bypass" => cfg.bool_or("check_nfkc_bypass", true),
            "newline_extension" => cfg.bool_or("check_newline_extension", false),
            "oast_filename" => cfg.string("oast_host").is_some(),
            _ => true,
        }
    };

    let mut extra_headers: Vec<(String, String)> = Vec::new();
    if let Some(cookie) = cfg.string("auth_cookie") {
        extra_headers.push(("Cookie".to_string(), cookie));
    }
    if let Some(auth) = cfg.string("auth_header") {
        extra_headers.push(("Authorization".to_string(), auth));
    }

    let client = http_client().await;
    let base = base_url(target);
    let paths = cfg.string_list_or("upload_paths", DEFAULT_UPLOAD_PATHS);
    let extra_eps = cfg.string_list("extra_endpoints");
    let field_names = cfg.string_list_or("field_names", DEFAULT_FIELD_NAMES);

    let mut endpoints: Vec<Endpoint> = Vec::new();
    let mut findings: Vec<Value> = Vec::new();
    let mut all_exposures: Vec<UploadExposure> = Vec::new();
    let mut stack = StackHint::default();

    if let Some(page) = http_get(&client, &base).await {
        stack = fingerprint_stack(&page.headers, &page.body);
        for (url, field) in extract_upload_forms(&page.body, &base) {
            endpoints.push(Endpoint {
                url: url.clone(),
                field,
                source: "html_form".into(),
                protocol: EndpointProtocol::Multipart,
            });
            if include_info {
                findings.push(finding_rich(
                    ENGINE_ID,
                    "File upload form discovered in HTML",
                    "info",
                    MITRE,
                    &format!(
                        "HTML at {} exposes multipart upload → {}",
                        page.final_url, url
                    ),
                    target,
                    0.95,
                    Evidence::new().with("url", url).with("source", "html_form"),
                ));
            }
        }
        for u in extract_js_upload_urls(&page.body, &base) {
            endpoints.push(Endpoint {
                url: u.clone(),
                field: "file".into(),
                source: "js_inline".into(),
                protocol: EndpointProtocol::Multipart,
            });
        }
        if check_openapi {
            for hint in OPENAPI_HINTS {
                let spec_url = format!("{}{}", base.trim_end_matches('/'), hint);
                if let Some(spec) = http_get(&client, &spec_url).await {
                    if spec.status == 200 {
                        if let Ok(json_spec) = serde_json::from_str::<Value>(&spec.body) {
                            endpoints.extend(parse_openapi_upload_endpoints(&json_spec, &base));
                        }
                    }
                }
            }
        }
        if check_js_discovery && max_tier >= 2 {
            for js_path in JS_PATH_HINTS {
                let js_url = resolve_url(&base, js_path);
                if let Some(js) = http_get(&client, &js_url).await {
                    if js.status == 200 {
                        for u in extract_js_upload_urls(&js.body, &base) {
                            endpoints.push(Endpoint {
                                url: u,
                                field: "file".into(),
                                source: format!("js:{js_path}"),
                                protocol: EndpointProtocol::Multipart,
                            });
                        }
                    }
                }
            }
        }
        if page.body.to_ascii_lowercase().contains("presigned")
            || page.body.contains("X-Amz-Signature")
        {
            if include_info {
                findings.push(finding_rich(
                    ENGINE_ID,
                    "Presigned upload URL pattern in page source",
                    "info",
                    MITRE,
                    "Target HTML/JS references presigned/S3-style direct upload — verify bucket policy and content-type enforcement on PUT.",
                    target,
                    0.7,
                    Evidence::new().with("signal", "presigned"),
                ));
            }
            if check_presigned {
                for url in extract_presigned_urls(&page.body).into_iter().take(3) {
                    if let Some(head) = http_get(&client, &url).await {
                        if matches!(head.status, 200 | 204 | 403) {
                            findings.push(finding_rich(
                                ENGINE_ID,
                                "Presigned cloud storage URL reachable",
                                "medium",
                                MITRE,
                                &format!(
                                    "Extracted presigned URL {} responded HTTP {} — validate signature TTL, content-type conditions, and bucket ACL.",
                                    head.final_url, head.status
                                ),
                                target,
                                0.85,
                                Evidence::new()
                                    .with("url", head.final_url)
                                    .with("category", "presigned_url"),
                            ));
                        }
                    }
                }
            }
        }
    }

    if check_cms_paths {
        for p in CMS_UPLOAD_PATHS {
            endpoints.push(Endpoint {
                url: resolve_url(&base, p),
                field: "file".into(),
                source: "cms_wordlist".into(),
                protocol: EndpointProtocol::Multipart,
            });
        }
    }

    if check_robots {
        for u in discover_robots_upload_paths(&client, &base).await {
            endpoints.push(Endpoint {
                url: u,
                field: "file".into(),
                source: "robots_txt".into(),
                protocol: EndpointProtocol::Multipart,
            });
        }
    }

    if check_sitemap {
        for u in discover_sitemap_upload_paths(&client, &base).await {
            endpoints.push(Endpoint {
                url: u,
                field: "file".into(),
                source: "sitemap".into(),
                protocol: EndpointProtocol::Multipart,
            });
        }
    }

    if check_spring_paths && (stack.java || stack_pack == "java" || stack_pack == "all") {
        for p in SPRING_UPLOAD_PATHS {
            endpoints.push(Endpoint {
                url: resolve_url(&base, p),
                field: "file".into(),
                source: "spring_path".into(),
                protocol: EndpointProtocol::Multipart,
            });
        }
    }

    if check_sharepoint && max_tier >= 2 {
        for p in SHAREPOINT_UPLOAD_PATHS {
            endpoints.push(Endpoint {
                url: resolve_url(&base, p),
                field: "file".into(),
                source: "sharepoint_path".into(),
                protocol: EndpointProtocol::Multipart,
            });
        }
    }

    if check_cloud_native && max_tier >= 2 {
        for p in CLOUD_NATIVE_UPLOAD_PATHS {
            endpoints.push(Endpoint {
                url: resolve_url(&base, p),
                field: "file".into(),
                source: "cloud_native_path".into(),
                protocol: EndpointProtocol::Multipart,
            });
        }
    }

    if check_security_txt {
        for u in discover_security_txt_hints(&client, &base).await {
            endpoints.push(Endpoint {
                url: u,
                field: "file".into(),
                source: "security_txt".into(),
                protocol: EndpointProtocol::Multipart,
            });
        }
    }

    if check_dir_listing {
        if let Some(f) = probe_directory_listing(&client, &base, &canary, target).await {
            findings.push(f);
        }
    }

    for p in stack_paths(&stack) {
        endpoints.push(Endpoint {
            url: resolve_url(&base, p),
            field: "file".into(),
            source: "stack_path".into(),
            protocol: EndpointProtocol::Multipart,
        });
    }

    for path in paths {
        let url = resolve_url(&base, path.as_str());
        for field in &field_names {
            endpoints.push(Endpoint {
                url: url.clone(),
                field: field.clone(),
                source: "path_wordlist".into(),
                protocol: EndpointProtocol::Multipart,
            });
        }
    }
    for ep in extra_eps {
        endpoints.push(Endpoint {
            url: ep,
            field: "file".into(),
            source: "operator".into(),
            protocol: EndpointProtocol::Multipart,
        });
    }

    let mut seen = HashSet::new();
    endpoints.retain(|e| seen.insert((e.url.clone(), e.field.clone(), e.protocol.clone())));

    let probe_endpoints: Vec<Endpoint> = stream::iter(endpoints.into_iter().take(max_endpoints))
        .map(|ep| {
            let client = client.clone();
            let headers = extra_headers.clone();
            let canary = canary.clone();
            async move {
                let accepted = match ep.protocol {
                    EndpointProtocol::GraphqlUpload => post_graphql_upload(
                        &client,
                        &ep.url,
                        &canary,
                        "probe.txt",
                        &headers,
                        timeout_ms,
                    )
                    .await
                    .map(|p| matches!(p.status, 200 | 201 | 202 | 400))
                    .unwrap_or(false),
                    EndpointProtocol::Base64Json => post_base64_json_upload(
                        &client,
                        &ep.url,
                        &ep.field,
                        "probe.txt",
                        &canary,
                        &headers,
                        timeout_ms,
                    )
                    .await
                    .map(|p| matches!(p.status, 200 | 201 | 202 | 400))
                    .unwrap_or(false),
                    EndpointProtocol::Put | EndpointProtocol::Multipart => post_multipart(
                        &client,
                        &ep.url,
                        &ep.field,
                        "probe.txt",
                        "text/plain",
                        &canary,
                        &headers,
                        timeout_ms,
                        DispositionMode::Standard,
                    )
                    .await
                    .map(|p| {
                        matches!(p.status, 200 | 201 | 202 | 400 | 422 | 415)
                            && p.status != 404
                            && p.status != 405
                    })
                    .unwrap_or(false),
                };
                if accepted {
                    let mut alive = ep;
                    alive.source = format!("{}_live", alive.source);
                    Some(alive)
                } else {
                    None
                }
            }
        })
        .buffer_unordered(concurrency)
        .filter_map(|x| async move { x })
        .collect()
        .await;

    let mut combos: Vec<BypassCombo> = bypass_matrix(&canary, &stack, &stack_pack, max_tier)
        .into_iter()
        .filter(|c| category_enabled(&c.category))
        .collect();
    if let Some(host) = cfg.string("oast_host") {
        let host = host.trim();
        if !host.is_empty() {
            combos.push(combo(
                &format!("{canary}.{host}.png"),
                "image/png",
                benign_gif_str(),
                "oast-filename-token",
                "oast_filename",
                "info",
                "info",
                1,
                DispositionMode::Standard,
            ));
        }
    }
    combos.truncate(max_combos);

    for ep in &probe_endpoints {
        if check_webdav && max_tier >= 2 {
            if let Some(opt) = options_probe(&client, &ep.url, &extra_headers, timeout_ms).await {
                let allow = header_value(&opt.headers, "allow").unwrap_or_default();
                let dav = header_value(&opt.headers, "dav").unwrap_or_default();
                if allow.to_ascii_uppercase().contains("PUT")
                    || allow.to_ascii_uppercase().contains("DELETE")
                    || !dav.is_empty()
                {
                    let mut f = finding_rich(
                        ENGINE_ID,
                        "WebDAV-capable upload surface (OPTIONS)",
                        "medium",
                        MITRE,
                        &format!(
                            "OPTIONS {} returned Allow: {:?} DAV: {:?} — WebDAV write may bypass application upload controls.",
                            opt.final_url, allow, dav
                        ),
                        target,
                        0.83,
                        Evidence::new()
                            .with("url", opt.final_url)
                            .with("allow", allow),
                    );
                    if let Some(obj) = f.as_object_mut() {
                        obj.insert("category".to_string(), json!("webdav_surface"));
                    }
                    findings.push(f);
                }
            }
        }

        if check_tus && max_tier >= 2 {
            for suffix in TUS_PATH_SUFFIXES {
                let tus_url = if suffix.is_empty() {
                    ep.url.clone()
                } else {
                    format!("{}{}", base.trim_end_matches('/'), suffix)
                };
                if let Some(t) =
                    post_tus_create(&client, &tus_url, &canary, &extra_headers, timeout_ms).await
                {
                    if matches!(t.status, 201 | 204 | 412) {
                        let exposure = UploadExposure {
                            combo: "tus-create".into(),
                            category: "tus_surface".into(),
                            accepted: true,
                            ..Default::default()
                        };
                        all_exposures.push(exposure.clone());
                        findings.push(make_finding(
                            "Tus/resumable upload endpoint responded",
                            if t.status == 201 { "high" } else { "medium" },
                            &format!(
                                "POST {} with Tus-Resumable headers returned HTTP {} (Location may enable unauthenticated chunked upload).",
                                t.final_url, t.status
                            ),
                            target,
                            "tus_surface",
                            0.88,
                            &exposure,
                            ep,
                            "Require authentication on Tus creation; validate Upload-Metadata; rate-limit PATCH chunks.",
                        ));
                        break;
                    }
                }
            }
        }

        if check_auth_diff && !extra_headers.is_empty() && max_tier >= 2 {
            if let Some(unauth) = post_multipart(
                &client,
                &ep.url,
                &ep.field,
                "unauth-probe.txt",
                "text/plain",
                &canary,
                &[],
                timeout_ms,
                DispositionMode::Standard,
            )
            .await
            {
                if matches!(unauth.status, 200 | 201 | 202) {
                    findings.push(make_finding(
                        "Upload accepted without provided session credentials",
                        "high",
                        &format!(
                            "Endpoint {} accepted upload without operator Cookie/Authorization (HTTP {}) while authenticated context was supplied — missing auth boundary.",
                            unauth.final_url, unauth.status
                        ),
                        target,
                        "auth_boundary",
                        0.9,
                        &UploadExposure {
                            combo: "auth-differential".into(),
                            category: "auth_boundary".into(),
                            accepted: true,
                            ..Default::default()
                        },
                        ep,
                        "Require authentication on all upload routes; reject anonymous multipart when session expected.",
                    ));
                }
            }
        }

        if check_hpp && max_tier >= 2 {
            if let Some(h) = post_multipart_hpp(
                &client,
                &ep.url,
                &ep.field,
                "file",
                "hpp-probe.txt",
                &canary,
                &extra_headers,
                timeout_ms,
            )
            .await
            {
                if matches!(h.status, 200 | 201 | 202) {
                    findings.push(make_finding(
                        "Multipart HPP — dual file fields accepted",
                        "medium",
                        &format!(
                            "Endpoint {} accepted request with two file form fields (HTTP {}) — parser may use unintended field.",
                            h.final_url, h.status
                        ),
                        target,
                        "multipart_hpp",
                        0.81,
                        &UploadExposure {
                            combo: "multipart-hpp".into(),
                            category: "multipart_hpp".into(),
                            accepted: true,
                            ..Default::default()
                        },
                        ep,
                        "Accept only one file field; reject duplicate Content-Disposition parts.",
                    ));
                }
            }
        }

        if check_upload_cors && max_tier >= 2 {
            if let Some(f) = probe_upload_cors(
                &client,
                &ep.url,
                &ep.field,
                &canary,
                &extra_headers,
                timeout_ms,
                target,
                ep,
            )
            .await
            {
                all_exposures.push(UploadExposure {
                    combo: "upload-cors".into(),
                    category: "upload_cors".into(),
                    accepted: true,
                    ..Default::default()
                });
                findings.push(f);
            }
        }

        if check_rate_limit && max_tier >= 2 {
            if let Some(f) = probe_rate_limit_absence(
                &client,
                &ep.url,
                &ep.field,
                &canary,
                &extra_headers,
                timeout_ms,
                target,
                ep,
            )
            .await
            {
                all_exposures.push(UploadExposure {
                    combo: "rate-limit".into(),
                    category: "rate_limit_absence".into(),
                    accepted: true,
                    ..Default::default()
                });
                findings.push(f);
            }
        }

        if check_error_disclosure && max_tier >= 2 {
            if let Some(f) = probe_error_disclosure(
                &client,
                &ep.url,
                &ep.field,
                &extra_headers,
                timeout_ms,
                target,
            )
            .await
            {
                all_exposures.push(UploadExposure {
                    combo: "error-disclosure".into(),
                    category: "error_disclosure".into(),
                    accepted: true,
                    ..Default::default()
                });
                findings.push(f);
            }
        }

        if check_template && max_tier >= 2 {
            if let Some(r) = post_multipart(
                &client,
                &ep.url,
                &ep.field,
                "{{7*7}}.txt",
                "text/plain",
                &canary,
                &extra_headers,
                timeout_ms,
                DispositionMode::Standard,
            )
            .await
            {
                if matches!(r.status, 200 | 201 | 202)
                    && r.body.contains("49")
                    && !r.body.contains("{{7*7}}")
                {
                    let exposure = UploadExposure {
                        combo: "ssti-filename".into(),
                        category: "template_injection".into(),
                        accepted: true,
                        ..Default::default()
                    };
                    all_exposures.push(exposure.clone());
                    findings.push(make_finding(
                        "Template injection reflected from upload filename",
                        "critical",
                        &format!(
                            "Upload at {} with filename '{{{{7*7}}}}.txt' returned body containing '49' (HTTP {}) — server-side template evaluation on filename.",
                            r.final_url, r.status
                        ),
                        target,
                        "template_injection",
                        0.94,
                        &exposure,
                        ep,
                        "Never evaluate user filenames as templates; sanitize and use server-generated names.",
                    ));
                }
            }
        }

        if check_eicar && max_tier >= 2 {
            if let Some(e) = post_multipart(
                &client,
                &ep.url,
                &ep.field,
                "eicar.com",
                "application/octet-stream",
                EICAR,
                &extra_headers,
                timeout_ms,
                DispositionMode::Standard,
            )
            .await
            {
                if matches!(e.status, 200 | 201 | 202) {
                    let exposure = UploadExposure {
                        combo: "eicar-test".into(),
                        category: "eicar_surface".into(),
                        accepted: true,
                        ..Default::default()
                    };
                    all_exposures.push(exposure.clone());
                    findings.push(make_finding(
                        "EICAR anti-virus test file accepted (AV pipeline absent or bypassed)",
                        "high",
                        &format!(
                            "Endpoint {} accepted industry-standard EICAR test string as eicar.com (HTTP {}) — no AV rejection observed.",
                            e.final_url, e.status
                        ),
                        target,
                        "eicar_surface",
                        0.93,
                        &exposure,
                        ep,
                        "Scan all uploads with AV/AMSI; block EICAR and quarantine before storage.",
                    ));
                }
            }
        }

        if check_batch && max_tier >= 2 {
            let files: Vec<(&str, &str, &[u8])> = vec![
                ("batch-a.txt", "text/plain", canary.as_bytes()),
                ("batch-b.txt", "text/plain", canary.as_bytes()),
                ("batch-c.txt", "text/plain", canary.as_bytes()),
            ];
            if let Some(b) = post_multipart_batch(
                &client,
                &ep.url,
                &ep.field,
                &files,
                &extra_headers,
                timeout_ms,
            )
            .await
            {
                if matches!(b.status, 200 | 201 | 202) {
                    let exposure = UploadExposure {
                        combo: "batch-3-files".into(),
                        category: "batch_upload".into(),
                        accepted: true,
                        ..Default::default()
                    };
                    all_exposures.push(exposure.clone());
                    findings.push(make_finding(
                        "Batch multi-file upload accepted (3 files)",
                        "medium",
                        &format!(
                            "Endpoint {} accepted single request with 3 file parts (HTTP {}) — spray/quota bypass surface.",
                            b.final_url, b.status
                        ),
                        target,
                        "batch_upload",
                        0.88,
                        &exposure,
                        ep,
                        "Limit files per request to 1; enforce cumulative size and count quotas.",
                    ));
                }
            }
        }

        if check_webp_png && max_tier >= 2 {
            let webp = minimal_webp();
            if let Some(w) = post_multipart_raw(
                &client,
                &ep.url,
                &ep.field,
                "photo.webp",
                "image/webp",
                &webp,
                &extra_headers,
                timeout_ms,
                DispositionMode::Standard,
            )
            .await
            {
                if matches!(w.status, 200 | 201 | 202) {
                    findings.push(make_finding(
                        "WebP upload surface accepted",
                        "medium",
                        &format!(
                            "Endpoint {} accepted WebP container (HTTP {}) — modern format validation gap.",
                            w.final_url, w.status
                        ),
                        target,
                        "webp_surface",
                        0.84,
                        &UploadExposure {
                            combo: "webp-upload".into(),
                            category: "modern_format".into(),
                            accepted: true,
                            ..Default::default()
                        },
                        ep,
                        "Re-encode WebP/AVIF server-side; validate RIFF structure.",
                    ));
                }
            }
            let png = minimal_png();
            if let Some(p) = post_multipart_raw(
                &client,
                &ep.url,
                &ep.field,
                "photo.png",
                "image/png",
                &png,
                &extra_headers,
                timeout_ms,
                DispositionMode::Standard,
            )
            .await
            {
                if matches!(p.status, 200 | 201 | 202) {
                    findings.push(make_finding(
                        "PNG upload surface accepted",
                        "info",
                        &format!(
                            "Endpoint {} accepted minimal PNG (HTTP {}).",
                            p.final_url, p.status
                        ),
                        target,
                        "png_surface",
                        0.78,
                        &UploadExposure {
                            combo: "png-upload".into(),
                            category: "modern_format".into(),
                            accepted: true,
                            ..Default::default()
                        },
                        ep,
                        "Validate PNG chunks; strip metadata server-side.",
                    ));
                }
            }
        }

        if check_filename_mismatch && max_tier >= 2 {
            if let Some(m) = post_multipart_filename_mismatch(
                &client,
                &ep.url,
                &ep.field,
                "safe.jpg",
                "shell.php",
                "image/jpeg",
                benign_gif_str().as_bytes(),
                &extra_headers,
                timeout_ms,
            )
            .await
            {
                if matches!(m.status, 200 | 201 | 202) {
                    let exposure = UploadExposure {
                        combo: "filename-mismatch".into(),
                        category: "filename_mismatch".into(),
                        accepted: true,
                        ..Default::default()
                    };
                    all_exposures.push(exposure.clone());
                    findings.push(make_finding(
                        "Filename metadata/body mismatch accepted",
                        "high",
                        &format!(
                            "Endpoint {} accepted upload with filename field 'safe.jpg' but multipart filename 'shell.php' (HTTP {}).",
                            m.final_url, m.status
                        ),
                        target,
                        "filename_mismatch",
                        0.9,
                        &exposure,
                        ep,
                        "Ignore client-supplied filename metadata fields; use single canonical filename source.",
                    ));
                }
            }
        }

        if check_double_disp && max_tier >= 2 {
            if let Some(d) = post_multipart_double_disposition(
                &client,
                &ep.url,
                &ep.field,
                "safe.jpg",
                "shell.php",
                "image/jpeg",
                benign_gif_str().as_bytes(),
                &extra_headers,
                timeout_ms,
            )
            .await
            {
                if matches!(d.status, 200 | 201 | 202) {
                    let exposure = UploadExposure {
                        combo: "double-disposition".into(),
                        category: "double_disposition".into(),
                        accepted: true,
                        ..Default::default()
                    };
                    all_exposures.push(exposure.clone());
                    findings.push(make_finding(
                        "Double Content-Disposition headers accepted",
                        "high",
                        &format!(
                            "Endpoint {} accepted multipart part with two Content-Disposition headers (HTTP {}) — parser uses last/wfirst wins.",
                            d.final_url, d.status
                        ),
                        target,
                        "double_disposition",
                        0.89,
                        &exposure,
                        ep,
                        "Reject multipart parts with duplicate Content-Disposition; use strict RFC2231 parser.",
                    ));
                }
            }
        }

        if check_boundary_smuggle && max_tier >= 3 {
            if let Some(s) = post_multipart_boundary_smuggle(
                &client,
                &ep.url,
                &ep.field,
                "smuggle-probe.txt",
                &canary,
                &extra_headers,
                timeout_ms,
            )
            .await
            {
                if matches!(s.status, 200 | 201 | 202) && s.body.contains("Injected") {
                    let exposure = UploadExposure {
                        combo: "boundary-smuggle".into(),
                        category: "boundary_smuggling".into(),
                        accepted: true,
                        ..Default::default()
                    };
                    all_exposures.push(exposure.clone());
                    findings.push(make_finding(
                        "Multipart boundary smuggling reflected",
                        "high",
                        &format!(
                            "Upload at {} reflected injected boundary fragment in response (HTTP {}) — parser confusion.",
                            s.final_url, s.status
                        ),
                        target,
                        "boundary_smuggling",
                        0.87,
                        &exposure,
                        ep,
                        "Use strict multipart parser; reject embedded boundary sequences in part bodies.",
                    ));
                }
            }
        }

        if check_json_multi && max_tier >= 2 {
            if let Some(j) =
                post_json_multi_file(&client, &ep.url, &canary, &extra_headers, timeout_ms).await
            {
                if matches!(j.status, 200 | 201 | 202) {
                    let exposure = UploadExposure {
                        combo: "json-multi-file".into(),
                        category: "json_multi_file".into(),
                        accepted: true,
                        ..Default::default()
                    };
                    all_exposures.push(exposure.clone());
                    findings.push(make_finding(
                        "JSON multi-file array upload API responded",
                        "high",
                        &format!(
                            "Endpoint {} accepted JSON {{files:[...]}} multi-file envelope (HTTP {}).",
                            j.final_url, j.status
                        ),
                        target,
                        "json_multi_file",
                        0.86,
                        &exposure,
                        ep,
                        "Apply same validation to JSON-wrapped uploads as multipart; limit array length.",
                    ));
                }
            }
        }

        if check_imagemagick && max_tier >= 2 {
            let svg = format!(
                r#"<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><!-- {canary} --></svg>"#
            );
            if let Some(im) = post_multipart(
                &client,
                &ep.url,
                &ep.field,
                "policy-probe.svg",
                "image/svg+xml",
                &svg,
                &extra_headers,
                timeout_ms,
                DispositionMode::Standard,
            )
            .await
            {
                if imagemagick_error_in_body(&im.body) {
                    findings.push(finding_rich(
                        ENGINE_ID,
                        "ImageMagick/policy error fingerprint in upload response",
                        "info",
                        MITRE,
                        &format!(
                            "SVG upload at {} returned body referencing ImageMagick/policy/delegate (HTTP {}) — image pipeline fingerprinted.",
                            im.final_url, im.status
                        ),
                        target,
                        0.82,
                        Evidence::new()
                            .with("url", im.final_url)
                            .with("category", "imagemagick_surface"),
                    ));
                }
            }
        }

        if check_svg_foreign && max_tier >= 2 {
            let svg = minimal_svg_foreign_object(&canary);
            if let Some(f) = post_multipart(
                &client,
                &ep.url,
                &ep.field,
                "foreign.svg",
                "image/svg+xml",
                &svg,
                &extra_headers,
                timeout_ms,
                DispositionMode::Standard,
            )
            .await
            {
                if matches!(f.status, 200 | 201 | 202) {
                    let exposure = UploadExposure {
                        combo: "svg-foreignobject".into(),
                        category: "svg_foreign_object".into(),
                        accepted: true,
                        ..Default::default()
                    };
                    all_exposures.push(exposure.clone());
                    findings.push(make_finding(
                        "SVG foreignObject upload surface accepted",
                        "high",
                        &format!(
                            "Endpoint {} accepted SVG with foreignObject/XHTML body (HTTP {}) — XSS/HTML injection surface.",
                            f.final_url, f.status
                        ),
                        target,
                        "svg_foreign_object",
                        0.88,
                        &exposure,
                        ep,
                        "Block SVG foreignObject; sanitize or convert to raster server-side.",
                    ));
                }
            }
        }

        if check_gzip_upload && max_tier >= 2 {
            if let Some(gz) = post_gzip_multipart(
                &client,
                &ep.url,
                &ep.field,
                "gzip-probe.txt",
                "text/plain",
                &canary,
                &extra_headers,
                timeout_ms,
            )
            .await
            {
                if matches!(gz.status, 200 | 201 | 202) {
                    findings.push(make_finding(
                        "Gzip Content-Encoding multipart upload accepted",
                        "medium",
                        &format!(
                            "Endpoint {} accepted gzip-compressed multipart body (HTTP {}) — compression bomb / parser differential surface.",
                            gz.final_url, gz.status
                        ),
                        target,
                        "gzip_upload",
                        0.85,
                        &UploadExposure {
                            combo: "gzip-encoding".into(),
                            category: "gzip_upload".into(),
                            accepted: true,
                            ..Default::default()
                        },
                        ep,
                        "Reject Content-Encoding on multipart unless strictly bounded; decompress with size caps.",
                    ));
                }
            }
        }

        if check_expect_continue && max_tier >= 2 {
            if let Some(ec) = post_multipart_expect_continue(
                &client,
                &ep.url,
                &ep.field,
                "expect-probe.txt",
                &canary,
                &extra_headers,
                timeout_ms,
            )
            .await
            {
                if matches!(ec.status, 200 | 201 | 202) {
                    findings.push(make_finding(
                        "Expect: 100-continue upload flow accepted",
                        "info",
                        &format!(
                            "Endpoint {} completed upload with Expect: 100-continue (HTTP {}).",
                            ec.final_url, ec.status
                        ),
                        target,
                        "expect_continue",
                        0.8,
                        &UploadExposure {
                            combo: "expect-100".into(),
                            category: "expect_continue".into(),
                            accepted: true,
                            ..Default::default()
                        },
                        ep,
                        "Validate Content-Length before 100 Continue; cap body size early.",
                    ));
                }
            }
        }

        if check_x_forwarded_host && max_tier >= 2 {
            if let Some(f) = probe_x_forwarded_host(
                &client,
                &ep.url,
                &ep.field,
                &canary,
                &extra_headers,
                timeout_ms,
                target,
                ep,
            )
            .await
            {
                all_exposures.push(UploadExposure {
                    combo: "xfh-reflection".into(),
                    category: "x_forwarded_host".into(),
                    accepted: true,
                    ..Default::default()
                });
                findings.push(f);
            }
        }

        if check_xlsm && max_tier >= 2 {
            let xlsm = minimal_xlsm(&canary);
            if let Some(x) = post_multipart_raw(
                &client,
                &ep.url,
                &ep.field,
                "report.xlsm",
                "application/vnd.ms-excel.sheet.macroEnabled.12",
                &xlsm,
                &extra_headers,
                timeout_ms,
                DispositionMode::Standard,
            )
            .await
            {
                if matches!(x.status, 200 | 201 | 202) {
                    findings.push(make_finding(
                        "XLSM macro-enabled workbook upload accepted",
                        "high",
                        &format!(
                            "Endpoint {} accepted macro-enabled OOXML XLSM (HTTP {}) — macro malware staging surface.",
                            x.final_url, x.status
                        ),
                        target,
                        "xlsm_surface",
                        0.87,
                        &UploadExposure {
                            combo: "xlsm-upload".into(),
                            category: "xlsm_surface".into(),
                            accepted: true,
                            ..Default::default()
                        },
                        ep,
                        "Block XLSM/XLSB; strip macros; scan with AMSI pipeline.",
                    ));
                }
            }
        }

        if check_pdf_js && max_tier >= 2 {
            let pdf = minimal_pdf_js_marker(&canary);
            if let Some(p) = post_multipart(
                &client,
                &ep.url,
                &ep.field,
                "doc.pdf",
                "application/pdf",
                &pdf,
                &extra_headers,
                timeout_ms,
                DispositionMode::Standard,
            )
            .await
            {
                if matches!(p.status, 200 | 201 | 202) {
                    findings.push(make_finding(
                        "PDF upload surface (JS action marker accepted)",
                        "medium",
                        &format!(
                            "Endpoint {} accepted PDF container (HTTP {}) — verify JavaScript/action stripping.",
                            p.final_url, p.status
                        ),
                        target,
                        "pdf_js_surface",
                        0.83,
                        &UploadExposure {
                            combo: "pdf-js-surface".into(),
                            category: "pdf_js_surface".into(),
                            accepted: true,
                            ..Default::default()
                        },
                        ep,
                        "Strip PDF JavaScript/OpenAction; render to safe format server-side.",
                    ));
                }
            }
        }

        if check_overwrite && max_tier >= 2 {
            if let Some(of) = probe_overwrite_oracle(
                &client,
                &ep.url,
                &ep.field,
                &base,
                &canary,
                &canary_b,
                &extra_headers,
                timeout_ms,
                target,
                ep,
                include_info,
            )
            .await
            {
                all_exposures.push(UploadExposure {
                    combo: "overwrite-oracle".into(),
                    category: "overwrite_oracle".into(),
                    accepted: true,
                    ..Default::default()
                });
                findings.push(of);
            }
        }

        if check_content_range && max_tier >= 2 {
            if let Some(cr) = put_content_range(
                &client,
                &ep.url,
                "wz-range-probe.txt",
                &canary,
                &extra_headers,
                timeout_ms,
            )
            .await
            {
                if matches!(cr.status, 200 | 201 | 204) {
                    findings.push(make_finding(
                        "Content-Range partial PUT accepted",
                        "high",
                        &format!(
                            "Partial upload via Content-Range at {} returned HTTP {} — resumable write without multipart controls.",
                            cr.final_url, cr.status
                        ),
                        target,
                        "content_range",
                        0.86,
                        &UploadExposure {
                            combo: "content-range-put".into(),
                            category: "content_range".into(),
                            accepted: true,
                            ..Default::default()
                        },
                        ep,
                        "Disable partial PUT unless tied to authenticated resumable sessions.",
                    ));
                }
            }
        }

        if check_size_oracle && max_tier >= 2 {
            for kb in [16usize, 64, 256] {
                let payload = "W".repeat(kb * 1024);
                if let Some(sz) = post_multipart(
                    &client,
                    &ep.url,
                    &ep.field,
                    &format!("size-probe-{kb}k.bin"),
                    "application/octet-stream",
                    &payload,
                    &extra_headers,
                    timeout_ms,
                    DispositionMode::Standard,
                )
                .await
                {
                    if sz.status == 413 {
                        if include_info {
                            findings.push(finding_rich(
                                ENGINE_ID,
                                &format!("Upload size limit oracle — 413 at ~{kb}KB"),
                                "info",
                                MITRE,
                                &format!(
                                    "Endpoint {} returned 413 Payload Too Large at ~{kb}KB probe — size cap fingerprinted.",
                                    sz.final_url
                                ),
                                target,
                                0.75,
                                Evidence::new()
                                    .with("url", sz.final_url)
                                    .with("size_kb", kb)
                                    .with("category", "size_limit_oracle"),
                            ));
                        }
                        break;
                    }
                }
            }
        }

        if check_graphql
            && (ep.url.contains("graphql") || ep.source.contains("graphql"))
            && max_tier >= 2
        {
            if let Some(g) = post_graphql_upload(
                &client,
                &ep.url,
                &canary,
                "wz.gif",
                &extra_headers,
                timeout_ms,
            )
            .await
            {
                if matches!(g.status, 200 | 201 | 202 | 400) && !g.body.contains("Must provide") {
                    if include_info {
                        findings.push(finding_rich(
                            ENGINE_ID,
                            "GraphQL multipart upload transport responded",
                            "info",
                            MITRE,
                            &format!(
                                "GraphQL endpoint {} accepted multipart upload envelope (HTTP {}). Verify Upload scalar authz.",
                                g.final_url, g.status
                            ),
                            target,
                            0.82,
                            Evidence::new().with("url", g.final_url).with("transport", "graphql-multipart"),
                        ));
                    }
                }
            }
        }

        if check_base64 && ep.protocol == EndpointProtocol::Base64Json {
            if let Some(b) = post_base64_json_upload(
                &client,
                &ep.url,
                &ep.field,
                "probe.b64",
                &canary,
                &extra_headers,
                timeout_ms,
            )
            .await
            {
                if matches!(b.status, 200 | 201 | 202) {
                    let exposure = UploadExposure {
                        combo: "base64-json".into(),
                        category: "base64_api".into(),
                        accepted: true,
                        ..Default::default()
                    };
                    all_exposures.push(exposure.clone());
                    findings.push(make_finding(
                        "Base64 JSON upload API accepted payload",
                        "high",
                        &format!("JSON/base64 upload at {} returned HTTP {}.", b.final_url, b.status),
                        target,
                        "base64_api",
                        0.88,
                        &exposure,
                        ep,
                        "Validate decoded bytes; never trust client filename or MIME in JSON wrappers.",
                    ));
                }
            }
        }

        if check_jpeg_com && max_tier >= 2 {
            let jpeg = minimal_jpeg_comment(&canary);
            if let Some(j) = post_multipart_raw(
                &client,
                &ep.url,
                &ep.field,
                "photo.jpg",
                "image/jpeg",
                &jpeg,
                &extra_headers,
                timeout_ms,
                DispositionMode::Standard,
            )
            .await
            {
                if matches!(j.status, 200 | 201 | 202) {
                    findings.push(make_finding(
                        "JPEG COM-marker polyglot accepted",
                        "medium",
                        &format!(
                            "Endpoint {} accepted JPEG with COM comment canary (HTTP {}) — magic-byte-only validation likely.",
                            j.final_url, j.status
                        ),
                        target,
                        "jpeg_com_polyglot",
                        0.84,
                        &UploadExposure {
                            combo: "jpeg-com".into(),
                            category: "jpeg_com_polyglot".into(),
                            accepted: true,
                            ..Default::default()
                        },
                        ep,
                        "Re-encode all images server-side; strip COM/EXIF; validate structure.",
                    ));
                }
            }
        }

        if check_docx && max_tier >= 2 {
            let docx = minimal_docx_bytes(&canary);
            if let Some(d) = post_multipart_raw(
                &client,
                &ep.url,
                &ep.field,
                "report.docx",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                &docx,
                &extra_headers,
                timeout_ms,
                DispositionMode::Standard,
            )
            .await
            {
                if matches!(d.status, 200 | 201 | 202) {
                    findings.push(make_finding(
                        "Office Open XML (DOCX) upload surface accepted",
                        "high",
                        &format!(
                            "Endpoint {} accepted ZIP-based DOCX container (HTTP {}) — macro-enabled variants may follow.",
                            d.final_url, d.status
                        ),
                        target,
                        "docx_surface",
                        0.86,
                        &UploadExposure {
                            combo: "docx-mini".into(),
                            category: "docx_surface".into(),
                            accepted: true,
                            ..Default::default()
                        },
                        ep,
                        "Block OOXML uploads or strip macros; scan with AMSI/antivirus pipeline.",
                    ));
                }
            }
        }

        if check_crlf_reflection && max_tier >= 3 {
            if let Some(c) = post_multipart(
                &client,
                &ep.url,
                &ep.field,
                "probe\r\nX-WZ-Injected: 1.jpg",
                "image/jpeg",
                benign_gif_str(),
                &extra_headers,
                timeout_ms,
                DispositionMode::Standard,
            )
            .await
            {
                if c.body.contains("X-WZ-Injected") || c.body.contains("WZ-Injected") {
                    findings.push(make_finding(
                        "CRLF reflected from upload filename",
                        "high",
                        &format!(
                            "Upload at {} reflected CRLF-derived content from filename — log/cache header injection surface.",
                            c.final_url
                        ),
                        target,
                        "crlf_reflection",
                        0.89,
                        &UploadExposure {
                            combo: "crlf-filename".into(),
                            category: "crlf_reflection".into(),
                            accepted: true,
                            ..Default::default()
                        },
                        ep,
                        "Strip CR/LF from filenames; never reflect raw filenames into headers or logs.",
                    ));
                }
            }
        }

        if check_zip && max_tier >= 2 {
            let zip_bytes = minimal_zip("canary.txt", &canary);
            if let Some(z) = post_multipart_raw(
                &client,
                &ep.url,
                &ep.field,
                "archive.zip",
                "application/zip",
                &zip_bytes,
                &extra_headers,
                timeout_ms,
                DispositionMode::Standard,
            )
            .await
            {
                if matches!(z.status, 200 | 201 | 202)
                    && (z.body.contains("canary.txt") || z.body.contains(".."))
                {
                    findings.push(make_finding(
                        "ZIP upload response references inner path (extraction surface)",
                        "high",
                        &format!(
                            "Archive upload at {} returned body referencing inner file paths — verify zip-slip controls.",
                            z.final_url
                        ),
                        target,
                        "zip_slip_surface",
                        0.86,
                        &UploadExposure {
                            combo: "zip-upload".into(),
                            category: "zip_slip_surface".into(),
                            accepted: true,
                            ..Default::default()
                        },
                        ep,
                        "Extract archives outside webroot; canonicalize paths; reject .. entries.",
                    ));
                }
            }
        }

        for combo in &combos {
            let Some(resp) = post_multipart(
                &client,
                &ep.url,
                &ep.field,
                &combo.filename,
                &combo.content_type,
                &combo.content,
                &extra_headers,
                timeout_ms,
                combo.disposition,
            )
            .await
            else {
                continue;
            };
            if resp.status == 403 && check_waf_fp {
                if let Some(vendor) = waf_vendor_from_headers(&resp.headers) {
                    if include_info {
                        let mut f = finding_rich(
                            ENGINE_ID,
                            &format!("WAF blocked upload probe ({vendor})"),
                            "info",
                            MITRE,
                            &format!(
                                "Upload to {} returned 403 with {vendor} edge signals — WAF may be only control (verify bypass class coverage).",
                                resp.final_url
                            ),
                            target,
                            0.72,
                            Evidence::new().with("url", resp.final_url).with("waf", vendor),
                        );
                        if let Some(obj) = f.as_object_mut() {
                            obj.insert("category".to_string(), json!("waf_fingerprint"));
                        }
                        findings.push(f);
                    }
                }
                continue;
            }
            if !matches!(resp.status, 200 | 201 | 202) {
                continue;
            }

            let mut exposure = UploadExposure {
                combo: combo.label.clone(),
                category: combo.category.clone(),
                accepted: true,
                ..Default::default()
            };

            if check_internal_urls {
                let signals = extract_internal_url_signals(&resp.body);
                if !signals.is_empty() {
                    findings.push(finding_rich(
                        ENGINE_ID,
                        "Internal/cloud URL disclosed in upload response",
                        "medium",
                        MITRE,
                        &format!(
                            "Upload at {} returned JSON/body referencing internal endpoints {:?} (HTTP {}) — aids SSRF/lateral mapping.",
                            resp.final_url, signals, resp.status
                        ),
                        target,
                        0.86,
                        Evidence::new()
                            .with("url", resp.final_url.clone())
                            .with("signals", json!(signals))
                            .with("category", "internal_url_disclosure"),
                    ));
                }
            }

            if check_location_leak {
                if let Some(lf) = probe_location_header_leak(&resp, target, ep).await {
                    findings.push(lf);
                }
            }

            if combo.category == "path_traversal"
                && (resp.body.contains("../")
                    || resp.body.contains("..%2F")
                    || resp.body.contains("wztest"))
            {
                all_exposures.push(exposure.clone());
                findings.push(make_finding(
                    "Path traversal filename reflected in response",
                    "high",
                    &format!(
                        "Upload at {} reflected traversal from '{}' (HTTP {}).",
                        resp.final_url, combo.filename, resp.status
                    ),
                    target,
                    "path_traversal",
                    0.93,
                    &exposure,
                    ep,
                    "Reject .. in filenames; use server-generated names.",
                ));
                continue;
            }

            if verify_storage {
                let mut urls = extract_retrieval_urls(&resp.body, &base, &canary);
                if storage_oracle {
                    urls.extend(storage_path_oracle(&base, &combo.filename));
                }
                urls.sort_unstable();
                urls.dedup();
                if let Some((retrieve_url, ct, exec_hint, nosniff_missing, cors, inline)) =
                    verify_retrieval(&client, &urls, &canary, combo.content.contains("GIF89a"))
                        .await
                {
                    exposure.retrieved = true;
                    exposure.retrieve_url = Some(retrieve_url.clone());
                    exposure.retrieve_content_type = Some(ct.clone());
                    exposure.execution_hint = exec_hint;
                    exposure.nosniff_missing = nosniff_missing;
                    exposure.cors_permissive = cors;
                    exposure.inline_served = inline;
                    all_exposures.push(exposure.clone());
                    let mut sev = if exec_hint {
                        "critical".to_string()
                    } else {
                        combo.severity_if_retrieved.to_string()
                    };
                    if nosniff_missing && inline {
                        sev = "critical".to_string();
                    }
                    findings.push(make_finding(
                        &format!(
                            "Upload bypass '{}' — retrievable{}",
                            combo.label,
                            if exec_hint { " (execution context)" } else { "" }
                        ),
                        &sev,
                        &format!(
                            "Bypass '{}' accepted at {} — canary at {} (Content-Type: {}). nosniff_missing={} inline={}",
                            combo.label, resp.final_url, retrieve_url, ct, nosniff_missing, inline
                        ),
                        target,
                        &combo.category,
                        0.97,
                        &exposure,
                        ep,
                        "Block extension/MIME class; store outside webroot; serve with attachment + nosniff.",
                    ));
                    if check_upload_idor {
                        if let Some(idor_f) =
                            probe_upload_idor(&client, &resp, &base, &canary, target, ep).await
                        {
                            all_exposures.push(UploadExposure {
                                combo: "upload-idor".into(),
                                category: "upload_idor".into(),
                                accepted: true,
                                retrieved: true,
                                ..Default::default()
                            });
                            findings.push(idor_f);
                        }
                    }
                    if check_cdn_cache {
                        if let Some(stored) = http_get(&client, &retrieve_url).await {
                            if let Some(cc) = probe_cdn_cache_headers(&stored.headers) {
                                let exp = UploadExposure {
                                    combo: "cdn-public-cache".into(),
                                    category: "cdn_cache_exposure".into(),
                                    accepted: true,
                                    retrieved: true,
                                    retrieve_url: Some(stored.final_url.clone()),
                                    ..Default::default()
                                };
                                all_exposures.push(exp.clone());
                                findings.push(make_finding(
                                    "Uploaded object may be publicly cached at CDN edge",
                                    "high",
                                    &format!(
                                        "Retrieved upload at {} carries Cache-Control: {} — user-controlled content in shared cache.",
                                        stored.final_url, cc
                                    ),
                                    target,
                                    "cdn_cache_exposure",
                                    0.9,
                                    &exp,
                                    ep,
                                    "Set Cache-Control: private, no-store on all user uploads; isolate upload CDN origin.",
                                ));
                            }
                        }
                    }
                    if check_unauth_retrieval && !extra_headers.is_empty() {
                        if let Some(uf) =
                            probe_unauth_retrieval(&client, &retrieve_url, &canary, target, ep)
                                .await
                        {
                            all_exposures.push(UploadExposure {
                                combo: "unauth-retrieval".into(),
                                category: "unauth_retrieval".into(),
                                accepted: true,
                                retrieved: true,
                                ..Default::default()
                            });
                            findings.push(uf);
                        }
                    }
                    if check_delete_unauth {
                        if let Some(df) =
                            probe_delete_without_auth(&client, &retrieve_url, target, ep).await
                        {
                            all_exposures.push(UploadExposure {
                                combo: "delete-unauth".into(),
                                category: "delete_without_auth".into(),
                                accepted: true,
                                retrieved: true,
                                ..Default::default()
                            });
                            findings.push(df);
                        }
                    }
                    if check_range_retrieval {
                        if let Some(rf) =
                            probe_range_retrieval(&client, &retrieve_url, &canary, target, ep).await
                        {
                            all_exposures.push(UploadExposure {
                                combo: "range-leak".into(),
                                category: "range_retrieval_leak".into(),
                                retrieved: true,
                                retrieve_url: Some(retrieve_url.clone()),
                                ..Default::default()
                            });
                            findings.push(rf);
                        }
                    }
                    if check_head_meta {
                        if let Some(hf) =
                            probe_head_metadata_leak(&client, &retrieve_url, target, ep).await
                        {
                            findings.push(hf);
                        }
                    }
                    if combo.category == "mime_spoof" || combo.label.contains("jpeg") {
                        if let Some(stored) = http_get(&client, &retrieve_url).await {
                            if stored.body.contains("GIF89a")
                                && ct.to_ascii_lowercase().contains("jpeg")
                            {
                                findings.push(make_finding(
                                    "MIME persistence bypass — GIF served as image/jpeg",
                                    "high",
                                    &format!(
                                        "Retrieved upload at {} declares Content-Type: {} but body contains GIF89a — magic-byte-only validation with MIME trust.",
                                        stored.final_url, ct
                                    ),
                                    target,
                                    "mime_persistence",
                                    0.92,
                                    &exposure,
                                    ep,
                                    "Re-encode images server-side; never trust client Content-Type on delivery.",
                                ));
                            }
                        }
                    }
                    continue;
                }
            }

            if check_upload_idor && resp.body.contains(&canary) {
                if let Some(idor_f) =
                    probe_upload_idor(&client, &resp, &base, &canary, target, ep).await
                {
                    findings.push(idor_f);
                }
            }

            if resp.body.contains(&combo.filename)
                || resp.body.contains(&canary)
                || resp.body.to_ascii_lowercase().contains("upload")
            {
                all_exposures.push(exposure.clone());
                findings.push(make_finding(
                    &format!("Upload bypass accepted: {}", combo.label),
                    combo.severity_if_accepted,
                    &format!(
                        "{} accepted '{}' as {} (HTTP {}). Confirm storage manually.",
                        resp.final_url, combo.filename, combo.content_type, resp.status
                    ),
                    target,
                    &combo.category,
                    0.8,
                    &exposure,
                    ep,
                    "Enforce allow-list extensions and magic-byte validation.",
                ));
            }
        }

        if check_put && max_tier >= 2 {
            if let Some(put_resp) = put_upload(
                &client,
                &ep.url,
                "wz-upload-probe.txt",
                "text/plain",
                &canary,
                &extra_headers,
                timeout_ms,
            )
            .await
            {
                if matches!(put_resp.status, 200 | 201 | 204) {
                    let exposure = UploadExposure {
                        combo: "put-upload".into(),
                        category: "put_method".into(),
                        accepted: true,
                        ..Default::default()
                    };
                    all_exposures.push(exposure.clone());
                    findings.push(make_finding(
                        "PUT upload accepted",
                        "high",
                        &format!(
                            "PUT {} → HTTP {} (direct write bypass).",
                            put_resp.final_url, put_resp.status
                        ),
                        target,
                        "put_method",
                        0.87,
                        &exposure,
                        ep,
                        "Disable PUT on upload paths; require authenticated multipart.",
                    ));
                }
            }
        }

        if check_patch && max_tier >= 3 {
            if let Some(patch_resp) = patch_upload(
                &client,
                &ep.url,
                "wz-patch-probe.txt",
                &canary,
                &extra_headers,
                timeout_ms,
            )
            .await
            {
                if matches!(patch_resp.status, 200 | 201 | 204) {
                    let exposure = UploadExposure {
                        combo: "patch-upload".into(),
                        category: "patch_method".into(),
                        accepted: true,
                        ..Default::default()
                    };
                    all_exposures.push(exposure.clone());
                    findings.push(make_finding(
                        "PATCH upload accepted",
                        "high",
                        &format!(
                            "PATCH {} → HTTP {}.",
                            patch_resp.final_url, patch_resp.status
                        ),
                        target,
                        "patch_method",
                        0.84,
                        &exposure,
                        ep,
                        "Disable PATCH object writes on public upload routes.",
                    ));
                }
            }
        }
    }

    let endpoints_found = probe_endpoints.len();
    if findings.is_empty() && endpoints_found == 0 {
        return empty_ok(ENGINE_ID, target);
    }

    let toxic_list = synthesize_toxic_combinations(&all_exposures);
    if !toxic_list.is_empty() {
        let names: Vec<_> = toxic_list
            .iter()
            .filter_map(|t| t.get("name").and_then(Value::as_str))
            .collect();
        findings.push(finding_rich(
            ENGINE_ID,
            &format!(
                "Toxic upload combination detected ({} chain(s))",
                toxic_list.len()
            ),
            "critical",
            MITRE,
            &format!(
                "Multiple upload weaknesses chain into enterprise-grade impact: {}.",
                names.join("; ")
            ),
            target,
            0.99,
            Evidence::new().with("toxic_combinations", json!(toxic_list)),
        ));
    }

    let real_count = findings.len();
    let coverage = probe_coverage_manifest(&cfg, max_tier);
    let summary = build_summary(
        target,
        &base,
        &findings,
        endpoints_found,
        &all_exposures,
        intensity,
        &stack,
        coverage,
    );
    let score = summary
        .get("posture_score")
        .and_then(Value::as_u64)
        .unwrap_or(100);
    findings.insert(0, summary);

    EngineResult::ok(
        findings,
        format!(
            "File upload posture {}/100 — {} finding(s) — stack [{}]",
            score,
            real_count,
            if stack.labels.is_empty() {
                "unknown".to_string()
            } else {
                stack.labels.join(",")
            }
        ),
    )
}

pub async fn run_file_upload_result(target: &str) -> EngineResult {
    run_file_upload_result_ctx(target, &EngineRunContext::default()).await
}

pub async fn run_file_upload(target: &str) {
    print_result(run_file_upload_result(target).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_form_finds_file_input() {
        let html = r#"<form action="/upload" method="post" enctype="multipart/form-data"><input type="file" name="doc"/></form>"#;
        let forms = extract_upload_forms(html, "https://example.com");
        assert_eq!(forms.len(), 1);
        assert!(forms[0].0.contains("/upload"));
    }

    #[test]
    fn openapi_finds_multipart_post() {
        let spec = json!({
            "paths": {
                "/api/upload": {
                    "post": {
                        "requestBody": {
                            "content": { "multipart/form-data": {} }
                        }
                    }
                }
            }
        });
        let eps = parse_openapi_upload_endpoints(&spec, "https://x.test");
        assert_eq!(eps.len(), 1);
        assert!(eps[0].url.contains("/api/upload"));
    }

    #[test]
    fn minimal_zip_starts_with_pk() {
        let z = minimal_zip("t.txt", "CANARY");
        assert_eq!(&z[0..2], b"PK");
    }

    #[test]
    fn bypass_matrix_has_platform_combos() {
        let stack = StackHint {
            php: true,
            ..Default::default()
        };
        let m = bypass_matrix("C", &stack, "auto", 3);
        assert!(m.iter().any(|c| c.category == "platform_php"));
    }

    #[test]
    fn extract_numeric_ids_from_json() {
        let body = r#"{"id":42,"file":{"fileId":1001}}"#;
        let ids = extract_numeric_ids(body);
        assert!(ids.contains(&42));
        assert!(ids.contains(&1001));
    }

    #[test]
    fn presigned_url_extractor_finds_s3() {
        let html = "uploadUrl: https://bucket.s3.amazonaws.com/x?X-Amz-Signature=abc";
        let u = extract_presigned_urls(html);
        assert!(!u.is_empty());
    }

    #[test]
    fn minimal_jpeg_has_soi_eoi() {
        let j = minimal_jpeg_comment("CANARY");
        assert_eq!(j[0..2], [0xFF, 0xD8]);
        assert!(j.ends_with(&[0xFF, 0xD9]));
    }

    #[test]
    fn toxic_combo_when_idor_and_unauth() {
        let exp = vec![
            UploadExposure {
                category: "upload_idor".into(),
                retrieved: true,
                ..Default::default()
            },
            UploadExposure {
                category: "unauth_retrieval".into(),
                retrieved: true,
                ..Default::default()
            },
        ];
        assert!(!synthesize_toxic_combinations(&exp).is_empty());
    }

    #[test]
    fn bypass_matrix_includes_ultra_wave_combos() {
        let stack = StackHint {
            iis: true,
            ..Default::default()
        };
        let m = bypass_matrix("C", &stack, "auto", 3);
        assert!(m.iter().any(|c| c.category == "reverse_double_extension"));
        assert!(m.iter().any(|c| c.category == "iis_handlers"));
        assert!(m.iter().any(|c| c.label.contains("htpasswd")));
    }

    #[test]
    fn enterprise_risk_tier_escalates_with_blast() {
        assert_eq!(enterprise_risk_tier(80, 0), "Catastrophic");
        assert_eq!(enterprise_risk_tier(55, 0), "Severe");
        assert_eq!(enterprise_risk_tier(10, 0), "Low");
    }

    #[test]
    fn minimal_png_starts_with_magic() {
        let p = minimal_png();
        assert_eq!(&p[0..4], &[0x89, 0x50, 0x4E, 0x47]);
    }

    #[test]
    fn internal_url_signals_detect_localhost() {
        let s = extract_internal_url_signals(r#"{"url":"http://127.0.0.1:9000/uploads/x"}"#);
        assert!(s.iter().any(|x| x.contains("127.0.0.1")));
    }

    #[test]
    fn bypass_matrix_has_semicolon_and_apache_combos() {
        let m = bypass_matrix("C", &StackHint::default(), "all", 3);
        assert!(m.iter().any(|c| c.category == "semicolon_bypass"));
        assert!(m.iter().any(|c| c.category == "apache_multisuffix"));
    }

    #[test]
    fn bypass_matrix_has_apex_rtlo_nfkc() {
        let m = bypass_matrix("C", &StackHint::default(), "all", 3);
        assert!(m.iter().any(|c| c.category == "rtlo_bypass"));
        assert!(m.iter().any(|c| c.category == "nfkc_bypass"));
    }

    #[test]
    fn path_entropy_scores_sequential_low() {
        assert!(score_storage_path_entropy("https://x.test/uploads/42") < 40);
        assert!(
            score_storage_path_entropy("https://x.test/files/a1b2c3d4-e5f6-7890-abcd-ef1234567890")
                > 80
        );
    }

    #[test]
    fn minimal_xlsm_is_zip() {
        let z = minimal_xlsm("CANARY");
        assert_eq!(&z[0..2], b"PK");
    }

    #[test]
    fn remediation_urgency_escalates() {
        assert!(
            compute_remediation_urgency(80, 2, 3, 30) > compute_remediation_urgency(10, 0, 0, 95)
        );
    }
}
