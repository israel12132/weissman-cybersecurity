// njs HMAC for stock nginx with ngx_http_js_module.
// js_import hmac from /etc/nginx/njs/weissman_proxy_hmac.js;
// js_set $weissman_proxy_ts hmac.ts;
// js_set $weissman_proxy_hmac hmac.mac;
// Canonical must match fingerprint_engine::proxy_hmac::ProxyTlsHeaders::canonical_v1.

function ts(r) {
    return Math.floor(Date.now() / 1000).toString();
}

function mac(r) {
    var secret = process.env.WEISSMAN_PROXY_HMAC_SECRET || "";
    if (!secret) {
        return "";
    }
    var crypto = require("crypto");
    var t = ts(r);
    var hello = r.variables.ssl_client_hello_b64 || "";
    var protocol = r.variables.ssl_protocol || "";
    var cipher = r.variables.ssl_cipher || "";
    var ciphers = r.variables.ssl_ciphers || "";
    var curves = r.variables.ssl_curves || "";
    var ja3 = "";
    var ja4 = "";
    var canonical = ["v1", t, hello, protocol, cipher, ciphers, curves, ja3, ja4].join("\n");
    return crypto.createHmac("sha256", secret).update(canonical).digest("hex");
}

export default { ts, mac };
