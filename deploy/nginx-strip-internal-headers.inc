# Strip client-supplied dual-control / internal privilege headers at the public
# edge so they cannot be smuggled from the internet into destructive APIs.
#
# nginx has no wildcard `proxy_set_header X-Weissman-* ""`. Blank only the
# headers that *grant* destructive capability. Do NOT blank:
#   - X-Weissman-Tenant-Id     (CI/CD hooks, authenticated separately)
#   - X-Weissman-Signature     (inbound HMAC on /hooks/)
#   - X-Weissman-Digest        (outbound attestation; harmless inbound)
#
# Command Center sends the same dual-control tokens in the JSON body
# (`destructive_confirm` / `dual_approve`). The app accepts header OR body and
# requires a constant-time match when both are present.
proxy_set_header X-Weissman-Destructive-Confirm "";
proxy_set_header X-Weissman-Dual-Approve "";
proxy_set_header X-Weissman-Llm-Handshake "";
