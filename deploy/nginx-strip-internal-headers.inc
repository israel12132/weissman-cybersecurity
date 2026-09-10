# Strip client-supplied dual-control / internal privilege headers at the public
# edge so they cannot be smuggled from the internet into destructive APIs.
#
# nginx has no wildcard `proxy_set_header X-Weissman-* ""`. Blank only the
# headers that *grant* destructive capability. Do NOT blank:
#   - X-Weissman-Tenant-Id     (CI/CD hooks, authenticated separately)
#   - X-Weissman-Signature     (inbound HMAC on /hooks/)
#   - X-Weissman-Digest        (outbound attestation; harmless inbound)
#
# Also blank X-Weissman-Proxy-Hmac so a client cannot mint a dual-control
# signature through the public edge. Axum accepts privilege headers only when
# that HMAC verifies (WEISSMAN_PROXY_SIGNING_SECRET). Command Center sends
# JSON `destructive_confirm` / `dual_approve` instead.
proxy_set_header X-Weissman-Destructive-Confirm "";
proxy_set_header X-Weissman-Dual-Approve "";
proxy_set_header X-Weissman-Llm-Handshake "";
proxy_set_header X-Weissman-Proxy-Hmac "";
