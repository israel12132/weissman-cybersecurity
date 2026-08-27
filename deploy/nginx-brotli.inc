# Brotli at quality 4 — include from the TLS site after installing the module:
#   Debian/Ubuntu: apt install libnginx-mod-http-brotli   (package name varies)
#   Then: include /path/to/repo/deploy/nginx-brotli.inc;
#
# Do NOT include this file on nginxinc/nginx-unprivileged (no ngx_brotli) —
# weissman-server already applies Brotli-4 via tower-http for API + SSE.

brotli on;
brotli_comp_level 4;
brotli_min_length 256;
brotli_proxied any;
brotli_types
    text/plain text/css text/xml text/javascript text/event-stream
    application/javascript application/json application/xml
    application/xml+rss application/wasm
    image/svg+xml;
