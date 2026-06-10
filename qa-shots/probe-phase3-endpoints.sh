#!/usr/bin/env bash
# End-to-end probe of all phase-1/2/3 endpoints with a real admin JWT.
# Exits non-zero if any endpoint returns an unexpected status code.
set -uo pipefail

BASE="${BASE:-http://localhost}"
TENANT="${TENANT:-default}"
EMAIL="${EMAIL:-admin@localhost}"
PASSWORD="${PASSWORD:-QaTest2026!}"

PASS=0
FAIL=0
FAILED_NAMES=()

probe() {
    local name="$1" method="$2" path="$3" expected="$4" body="${5:-}"
    local args=(-s -o /dev/null -w '%{http_code}' -X "$method" "$BASE$path"
                -H "Authorization: Bearer $TOKEN")
    if [ -n "$body" ]; then
        args+=(-H 'Content-Type: application/json' -d "$body")
    fi
    local code; code=$(curl "${args[@]}")
    if [[ ",$expected," == *",$code,"* ]]; then
        printf '  ✓ %-50s → HTTP %s (expected: %s)\n' "$name" "$code" "$expected"
        PASS=$((PASS+1))
    else
        printf '  ✗ %-50s → HTTP %s (expected: %s)\n' "$name" "$code" "$expected"
        FAIL=$((FAIL+1))
        FAILED_NAMES+=("$name [$code]")
    fi
}

echo "=== Login ==="
TOKEN=$(curl -s -X POST "$BASE/api/login" -H 'Content-Type: application/json' \
    -d "{\"tenant_slug\":\"$TENANT\",\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" \
    | python3 -c 'import json,sys;print(json.load(sys.stdin).get("access_token",""))')
if [ -z "$TOKEN" ] || [ "${#TOKEN}" -lt 100 ]; then
    echo "✗ Could not obtain JWT — refusing to continue."
    exit 1
fi
echo "  ✓ Got JWT (len=${#TOKEN})"
echo ""

echo "=== Phase 1: Threat intel + dedup + FP feedback ==="
probe "GET  /api/findings (paginated+EPSS+KEV)" GET "/api/findings?limit=3"        200
probe "GET  /api/findings/clusters"             GET "/api/findings/clusters?limit=5" 200
probe "GET  /api/intel/status"                  GET "/api/intel/status"            200
probe "GET  /api/intel/suppressions"            GET "/api/intel/suppressions"      200

echo ""
echo "=== Phase 2: pgvector RAG + attack-paths + SOAR ==="
probe "GET  /api/attack-paths/1"                GET "/api/attack-paths/1"          200
probe "GET  /api/playbooks"                     GET "/api/playbooks"               200
probe "POST /api/playbooks (create)"            POST "/api/playbooks"              200,201 \
    '{"name":"Phase3 probe playbook","enabled":false,"trigger":{"severity":["critical"]},"actions":[]}'

echo ""
echo "=== Phase 3: Financial risk + UEBA + NL→SQL ==="
probe "GET  /api/financial-risk/1"              GET "/api/financial-risk/1"        200
probe "POST /api/financial-risk/1/apply-tags"   POST "/api/financial-risk/1/apply-tags" 200
probe "GET  /api/ueba/anomalies"                GET "/api/ueba/anomalies?limit=5"  200
probe "POST /api/ask (no read-only pool yet)"   POST "/api/ask"                    200,503 \
    '{"question":"top 5 critical findings"}'

echo ""
echo "=== Original cockpit + auth still healthy ==="
probe "GET  /api/health"                        GET "/api/health"                  200
probe "GET  /api/dashboard/stats"               GET "/api/dashboard/stats"         200
probe "GET  /api/dashboard/exec-kpis"           GET "/api/dashboard/exec-kpis"     200
probe "GET  /api/clients"                       GET "/api/clients"                 200
probe "GET  /api/jobs?limit=5"                  GET "/api/jobs?limit=5"            200
probe "GET  /api/audit-logs?limit=5"            GET "/api/audit-logs?limit=5"      200
probe "GET  /api/openapi.json"                  GET "/api/openapi.json"            200

echo ""
echo "=== Summary ==="
echo "  PASSED: $PASS"
echo "  FAILED: $FAIL"
if [ "$FAIL" -gt 0 ]; then
    printf '  Failures:\n'
    for n in "${FAILED_NAMES[@]}"; do printf '    - %s\n' "$n"; done
    exit 1
fi
echo "  → all probes returned expected status codes"
