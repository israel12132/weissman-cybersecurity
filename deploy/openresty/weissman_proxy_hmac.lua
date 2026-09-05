-- OpenResty access-phase HMAC over TLS fingerprint headers forwarded to Axum.
-- Canonical string MUST match fingerprint_engine::proxy_hmac::ProxyTlsHeaders::canonical_v1:
--   v1\n{ts}\n{hello_b64}\n{protocol}\n{cipher}\n{ciphers}\n{curves}\n{ja3}\n{ja4}
--
-- nginx:
--   env WEISSMAN_PROXY_HMAC_SECRET;
--   set $weissman_proxy_ts '';
--   set $weissman_proxy_hmac '';
--   access_by_lua_file /etc/nginx/lua/weissman_proxy_hmac.lua;
--   proxy_set_header X-Weissman-Proxy-Ts $weissman_proxy_ts;
--   proxy_set_header X-Weissman-Proxy-Hmac $weissman_proxy_hmac;
--
-- If the secret is missing, leave headers empty — Axum refuses to parse ClientHello.

local function hex(bin)
    if not bin then
        return ""
    end
    local ok, str = pcall(require, "resty.string")
    if ok and str and str.to_hex then
        return str.to_hex(bin)
    end
    return (bin:gsub(".", function(c)
        return string.format("%02x", string.byte(c))
    end))
end

local function hmac_sha256(secret, msg)
    local ok_ossl, hmac = pcall(require, "resty.openssl.hmac")
    if ok_ossl and hmac then
        local h, err = hmac.new(secret, "sha256")
        if h then
            h:update(msg)
            return h:final()
        end
        ngx.log(ngx.WARN, "weissman proxy hmac openssl: ", err or "new failed")
    end
    local ok_resty, resty_hmac = pcall(require, "resty.hmac")
    if ok_resty and resty_hmac then
        local h = resty_hmac:new(secret, resty_hmac.ALGOS and resty_hmac.ALGOS.SHA256 or "sha256")
        if h then
            h:update(msg)
            return h:final()
        end
    end
    return nil
end

local secret = os.getenv("WEISSMAN_PROXY_HMAC_SECRET") or ""
if secret == "" then
    return
end

local ts = tostring(ngx.time())
local hello = ngx.var.ssl_client_hello_b64 or ""
local protocol = ngx.var.ssl_protocol or ""
local cipher = ngx.var.ssl_cipher or ""
local ciphers = ngx.var.ssl_ciphers or ""
local curves = ngx.var.ssl_curves or ""
local ja3 = ngx.var.http_x_tls_ja3 or ""
local ja4 = ngx.var.http_x_tls_ja4 or ""

local canonical = table.concat({
    "v1", ts, hello, protocol, cipher, ciphers, curves, ja3, ja4
}, "\n")

local digest = hmac_sha256(secret, canonical)
if not digest then
    ngx.log(ngx.WARN, "weissman proxy hmac: no HMAC backend (install resty.openssl or lua-resty-string)")
    return
end

ngx.var.weissman_proxy_ts = ts
ngx.var.weissman_proxy_hmac = hex(digest)
