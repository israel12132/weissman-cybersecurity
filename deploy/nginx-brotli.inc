# Brotli at quality 4 — include from the TLS site after installing the module:
#   Debian/Ubuntu: apt install libnginx-mod-http-brotli   (package name varies)
#   Then: sudo cp deploy/nginx-brotli.inc /etc/nginx/snippets/weissman-brotli.conf
#         include /etc/nginx/snippets/weissman-brotli.conf;   # in the TLS server{}
#
# Production JSON compression lives HERE, not in Axum. In-process Brotli on
# /api JSON is a CPU-exhaustion DoS (Tokio worker starvation). The Docker
# gateway image has no ngx_brotli — it uses gzip instead (deploy/nginx-gateway.conf).
# Never list text/event-stream: Brotli buffering delays SOC alerts.

brotli on;
brotli_comp_level 4;
brotli_min_length 256;
brotli_proxied any;
brotli_types
    text/plain text/css text/xml text/javascript
    application/javascript application/json application/xml
    application/xml+rss application/wasm
    image/svg+xml;
