-- OpenResty ssl_client_hello_by_lua_file hook.
-- Captures raw ClientHello bytes into $ssl_client_hello_b64 so Axum can compute JA3/JA4.
--
-- nginx:
--   set $ssl_client_hello_b64 '';
--   ssl_client_hello_by_lua_file /etc/nginx/lua/weissman_ssl_client_hello.lua;
--   proxy_set_header X-SSL-Client-Hello $ssl_client_hello_b64;
--
-- Stock nginx has no this callback — leave the header empty; tls_client_hello.rs
-- then records source=not_terminated_in_app_layer or nginx_ssl_ciphers_incomplete.
-- Never invent a hash here.

local function b64(s)
    if not s or s == "" then
        return ""
    end
    return ngx.encode_base64(s)
end

-- Tengine / nginx-ssl-hello: $ssl_client_raw_hello
local raw = ngx.var.ssl_client_raw_hello
if raw and raw ~= "" then
    ngx.var.ssl_client_hello_b64 = b64(raw)
    return
end

-- OpenResty resty.openssl / custom module may expose the hello on the SSL object.
local ok_ssl, ssl = pcall(require, "ngx.ssl")
if ok_ssl and ssl and type(ssl.raw_client_hello) == "function" then
    local hello, err = ssl.raw_client_hello()
    if hello then
        ngx.var.ssl_client_hello_b64 = b64(hello)
        return
    end
    if err then
        ngx.log(ngx.WARN, "weissman ssl_client_hello: ", err)
    end
end
