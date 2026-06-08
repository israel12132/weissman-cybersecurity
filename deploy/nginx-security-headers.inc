# Production security headers — included from EVERY `location` block in nginx-gateway.conf.
#
# Why include and not server-level only? In nginx, `add_header` at parent scope is
# *replaced* (not merged) by any `add_header` defined inside a child `location`. To get
# defence-in-depth headers on every response — including 404s, /api/, /assets/, /install/
# — they must be added inside each location's own block.

add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: blob: https:; connect-src 'self' wss: https:; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; object-src 'none'; upgrade-insecure-requests" always;
add_header X-Content-Type-Options       "nosniff"                            always;
add_header X-Frame-Options              "DENY"                               always;
add_header Referrer-Policy              "strict-origin-when-cross-origin"    always;
add_header Permissions-Policy           "geolocation=(), microphone=(), camera=(), payment=(), usb=(), bluetooth=(), accelerometer=(), gyroscope=(), magnetometer=(), midi=()" always;
add_header Cross-Origin-Opener-Policy   "same-origin"                        always;
add_header Cross-Origin-Resource-Policy "same-origin"                        always;
