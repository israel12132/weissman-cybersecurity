/**
 * Optional nginx njs signer for X-Weissman-Proxy-Signature.
 *
 * Enable only on nginx builds with njs:
 *   load_module modules/ngx_http_js_module.so;
 *   js_import proxy_sign from /etc/nginx/njs/nginx-proxy-sign.njs;
 *   js_set $weissman_proxy_sig proxy_sign.signature;
 *   proxy_set_header X-Weissman-Proxy-Signature $weissman_proxy_sig;
 *
 * The HMAC key is env WEISSMAN_PROXY_SIGNING_SECRET (must be declared with
 * `env WEISSMAN_PROXY_SIGNING_SECRET;` in nginx.conf).
 *
 * Canonical (must match fingerprint_engine::http::dual_control_proxy):
 *   v1:{unix}\n{METHOD}\n{path}\n{confirm}\n{approve}
 */
function signature(r) {
    var secret = process.env.WEISSMAN_PROXY_SIGNING_SECRET || "";
    if (secret.length < 32) {
        return "";
    }
    var confirm = r.headersIn["X-Weissman-Destructive-Confirm"] || "";
    var approve = r.headersIn["X-Weissman-Dual-Approve"] || "";
    if (!confirm && !approve) {
        return "";
    }
    var ts = Math.floor(Date.now() / 1000);
    var canonical =
        "v1:" +
        ts +
        "\n" +
        r.method +
        "\n" +
        r.uri.split("?")[0] +
        "\n" +
        confirm.trim() +
        "\n" +
        approve.trim();
    var hex = require("crypto").createHmac("sha256", secret).update(canonical).digest("hex");
    return "t=" + ts + ",v1=" + hex;
}

export default { signature };
