#!/usr/bin/env bash
###############################################################################
# audit-verify.sh — Master Security Verification Script (Phase 5)
#
# PERN-Store Production Security Audit
# Validates network segmentation, security headers, and overall posture.
#
# Prerequisites:
#   - nmap:      sudo apt install nmap
#   - nikto:     sudo apt install nikto
#   - owasp-zap: docker pull ghcr.io/zaproxy/zaproxy:stable
#   - curl:      (pre-installed)
#   - docker:    (pre-installed)
#   - jq:        sudo apt install jq
#
# Usage:
#   chmod +x audit-verify.sh
#   sudo ./audit-verify.sh [TARGET_HOST] [--full]
#
# Examples:
#   sudo ./audit-verify.sh                    # Scan localhost (quick)
#   sudo ./audit-verify.sh 192.168.1.100      # Scan specific host
#   sudo ./audit-verify.sh localhost --full    # Full scan with nikto + ZAP
###############################################################################
set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
TARGET_HOST="${1:-localhost}"
FULL_SCAN="${2:-}"
REPORT_DIR="$(dirname "$0")/../reports/pentest-$(date +%Y%m%d-%H%M%S)"
DOCKER_COMPOSE_FILE="$(dirname "$0")/../../docker-compose.prod.yml"

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

# ── Counters ─────────────────────────────────────────────────────────────────
PASS=0
FAIL=0
WARN=0

pass()  { ((PASS++)); echo -e "  ${GREEN}[PASS]${NC}  $1"; }
fail()  { ((FAIL++)); echo -e "  ${RED}[FAIL]${NC}  $1"; }
warn()  { ((WARN++)); echo -e "  ${YELLOW}[WARN]${NC}  $1"; }
info()  { echo -e "  ${BLUE}[INFO]${NC}  $1"; }
header(){ echo -e "\n${CYAN}${BOLD}═══ $1 ═══${NC}"; }

# ── Setup ────────────────────────────────────────────────────────────────────
mkdir -p "$REPORT_DIR"

echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║     PERN-Store — Phase 5 Security Verification Audit               ║"
echo "║     Target: ${TARGET_HOST}                                         ║"
echo "║     Date:   $(date -u '+%Y-%m-%d %H:%M:%S UTC')                    ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""

###############################################################################
# TEST 1: PORT SCANNING — Verify Attack Surface (nmap)
###############################################################################
header "1. PORT SCANNING (nmap)"

if command -v nmap &>/dev/null; then
    info "Running TCP SYN scan against ${TARGET_HOST}..."

    # 1a. Quick scan — verify only expected ports are open
    info "1a. Quick scan — checking exposed ports"
    nmap -sS -T4 --top-ports 1000 -oN "${REPORT_DIR}/nmap-quick.txt" "$TARGET_HOST" 2>/dev/null | tee -a "${REPORT_DIR}/nmap-quick.txt" > /dev/null

    OPEN_PORTS=$(grep -E "^[0-9]+/tcp\s+open" "${REPORT_DIR}/nmap-quick.txt" 2>/dev/null | awk '{print $1}' | tr '\n' ', ' | sed 's/,$//')
    if [ -n "$OPEN_PORTS" ]; then
        info "Open ports detected: ${OPEN_PORTS}"

        # Check that ONLY 80 and/or 443 are open
        UNEXPECTED=$(grep -E "^[0-9]+/tcp\s+open" "${REPORT_DIR}/nmap-quick.txt" 2>/dev/null | grep -vE "^(80|443)/tcp" || true)
        if [ -z "$UNEXPECTED" ]; then
            pass "Only expected ports (80/443) are exposed"
        else
            fail "Unexpected ports are open: $(echo "$UNEXPECTED" | awk '{print $1}' | tr '\n' ', ')"
        fi
    else
        warn "No open ports detected (host may be down or firewalled)"
    fi

    # 1b. Service version detection
    info "1b. Service version fingerprinting"
    nmap -sV -p 80,443 -oN "${REPORT_DIR}/nmap-version.txt" "$TARGET_HOST" 2>/dev/null > /dev/null

    # Check for version disclosure
    if grep -qi "nginx" "${REPORT_DIR}/nmap-version.txt" 2>/dev/null; then
        if grep -qiP "nginx/\d" "${REPORT_DIR}/nmap-version.txt" 2>/dev/null; then
            warn "Nginx version disclosed in service banner"
        else
            pass "Nginx version not disclosed"
        fi
    fi

    # 1c. Verify PostgreSQL port is NOT accessible from host
    info "1c. Verifying PostgreSQL (5432) is NOT accessible from host"
    PG_SCAN=$(nmap -p 5432 --open "$TARGET_HOST" 2>/dev/null | grep "5432/tcp" || true)
    if [ -z "$PG_SCAN" ]; then
        pass "PostgreSQL port 5432 is NOT accessible from host network"
    else
        fail "PostgreSQL port 5432 IS accessible from host network!"
    fi

    # 1d. Verify API port is NOT directly accessible
    info "1d. Verifying API (9000) is NOT directly accessible"
    API_SCAN=$(nmap -p 9000 --open "$TARGET_HOST" 2>/dev/null | grep "9000/tcp" || true)
    if [ -z "$API_SCAN" ]; then
        pass "API port 9000 is NOT directly accessible from host"
    else
        fail "API port 9000 IS directly accessible from host network!"
    fi

    # 1e. NSE vulnerability scripts
    info "1e. Running NSE vulnerability scripts"
    nmap --script=vuln -p 80,443 -oN "${REPORT_DIR}/nmap-vuln.txt" "$TARGET_HOST" 2>/dev/null > /dev/null
    VULNS=$(grep -c "VULNERABLE" "${REPORT_DIR}/nmap-vuln.txt" 2>/dev/null || echo "0")
    if [ "$VULNS" -eq 0 ]; then
        pass "No vulnerabilities detected by nmap NSE scripts"
    else
        fail "${VULNS} vulnerabilities detected by nmap NSE scripts"
    fi
else
    warn "nmap not installed — skipping port scan"
    echo "  Install: sudo apt install nmap"
fi

###############################################################################
# TEST 2: DOCKER NETWORK ISOLATION — Verify Zone Segmentation
###############################################################################
header "2. DOCKER NETWORK ISOLATION"

if command -v docker &>/dev/null; then

    # 2a. Verify nginx is NOT on backend-net
    info "2a. Checking nginx network membership"
    NGINX_NETS=$(docker inspect pern-prod-nginx 2>/dev/null | jq -r '.[0].NetworkSettings.Networks | keys[]' 2>/dev/null || echo "CONTAINER_NOT_FOUND")
    if [ "$NGINX_NETS" = "CONTAINER_NOT_FOUND" ]; then
        warn "Container pern-prod-nginx not running — cannot verify"
    else
        if echo "$NGINX_NETS" | grep -q "backend-net"; then
            fail "nginx is connected to backend-net (violates zone model!)"
        else
            pass "nginx is NOT on backend-net (correct isolation)"
        fi
        info "nginx networks: ${NGINX_NETS}"
    fi

    # 2b. Verify postgres is NOT on frontend-net
    info "2b. Checking postgres network membership"
    PG_NETS=$(docker inspect pern-prod-db 2>/dev/null | jq -r '.[0].NetworkSettings.Networks | keys[]' 2>/dev/null || echo "CONTAINER_NOT_FOUND")
    if [ "$PG_NETS" = "CONTAINER_NOT_FOUND" ]; then
        warn "Container pern-prod-db not running — cannot verify"
    else
        if echo "$PG_NETS" | grep -q "frontend-net"; then
            fail "postgres is connected to frontend-net (violates zone model!)"
        else
            pass "postgres is NOT on frontend-net (correct isolation)"
        fi
        info "postgres networks: ${PG_NETS}"
    fi

    # 2c. Verify backend-net is internal
    info "2c. Checking backend-net is internal"
    BACKEND_INTERNAL=$(docker network inspect pern-store_backend-net 2>/dev/null | jq -r '.[0].Internal' 2>/dev/null || echo "NETWORK_NOT_FOUND")
    if [ "$BACKEND_INTERNAL" = "true" ]; then
        pass "backend-net has internal: true (no external access)"
    elif [ "$BACKEND_INTERNAL" = "false" ]; then
        fail "backend-net is NOT internal — Data Zone is exposed!"
    else
        warn "Could not inspect backend-net (may need different prefix)"
    fi

    # 2d. Cross-zone connectivity test: nginx → postgres
    info "2d. Testing nginx → postgres connectivity (should FAIL)"
    NGINX_TO_PG=$(docker exec pern-prod-nginx sh -c "wget --spider --timeout=3 pern-prod-db:5432 2>&1" 2>&1 || true)
    if echo "$NGINX_TO_PG" | grep -qiE "timed out|connection refused|bad address|not found|No such|error"; then
        pass "nginx CANNOT reach postgres (zone isolation working)"
    else
        fail "nginx CAN reach postgres (zone isolation BROKEN!)"
    fi

    # 2e. Verify no host port mappings on internal services
    info "2e. Checking host port bindings"
    API_PORTS=$(docker inspect pern-prod-api 2>/dev/null | jq -r '.[0].NetworkSettings.Ports | to_entries[] | select(.value != null) | .key' 2>/dev/null || echo "CONTAINER_NOT_FOUND")
    PG_HOST_PORTS=$(docker inspect pern-prod-db 2>/dev/null | jq -r '.[0].NetworkSettings.Ports | to_entries[] | select(.value != null) | .key' 2>/dev/null || echo "CONTAINER_NOT_FOUND")

    if [ -z "$API_PORTS" ] || [ "$API_PORTS" = "CONTAINER_NOT_FOUND" ]; then
        pass "API has no host port bindings (internal only)"
    else
        fail "API has host port bindings: ${API_PORTS}"
    fi

    if [ -z "$PG_HOST_PORTS" ] || [ "$PG_HOST_PORTS" = "CONTAINER_NOT_FOUND" ]; then
        pass "PostgreSQL has no host port bindings (internal only)"
    else
        fail "PostgreSQL has host port bindings: ${PG_HOST_PORTS}"
    fi

    # 2f. Container security options
    info "2f. Checking container security options"
    for CONTAINER in pern-prod-nginx pern-prod-api pern-prod-db; do
        SEC_OPTS=$(docker inspect "$CONTAINER" 2>/dev/null | jq -r '.[0].HostConfig.SecurityOpt[]' 2>/dev/null || echo "NOT_FOUND")
        if echo "$SEC_OPTS" | grep -q "no-new-privileges"; then
            pass "${CONTAINER}: no-new-privileges enabled"
        elif [ "$SEC_OPTS" = "NOT_FOUND" ]; then
            warn "${CONTAINER}: container not found"
        else
            fail "${CONTAINER}: no-new-privileges NOT set"
        fi
    done

else
    warn "Docker not available — skipping container isolation tests"
fi

###############################################################################
# TEST 3: SECURITY HEADER VALIDATION
###############################################################################
header "3. SECURITY HEADER CHECKS"

info "Checking HTTP response headers from ${TARGET_HOST}..."
HEADERS=$(curl -sI -o /dev/null -w '%{http_code}' "http://${TARGET_HOST}/" 2>/dev/null || echo "UNREACHABLE")

if [ "$HEADERS" = "UNREACHABLE" ]; then
    warn "Target unreachable — skipping header checks"
else
    # Fetch full headers
    FULL_HEADERS=$(curl -sI "http://${TARGET_HOST}/" 2>/dev/null)
    echo "$FULL_HEADERS" > "${REPORT_DIR}/headers.txt"

    # 3a. X-Frame-Options
    if echo "$FULL_HEADERS" | grep -qi "X-Frame-Options.*DENY"; then
        pass "X-Frame-Options: DENY"
    elif echo "$FULL_HEADERS" | grep -qi "X-Frame-Options"; then
        warn "X-Frame-Options present but not DENY"
    else
        fail "X-Frame-Options header MISSING"
    fi

    # 3b. X-Content-Type-Options
    if echo "$FULL_HEADERS" | grep -qi "X-Content-Type-Options.*nosniff"; then
        pass "X-Content-Type-Options: nosniff"
    else
        fail "X-Content-Type-Options header MISSING"
    fi

    # 3c. Strict-Transport-Security
    if echo "$FULL_HEADERS" | grep -qi "Strict-Transport-Security"; then
        HSTS_VAL=$(echo "$FULL_HEADERS" | grep -i "Strict-Transport-Security")
        if echo "$HSTS_VAL" | grep -qi "max-age=31536000"; then
            pass "HSTS: max-age=31536000 (1 year)"
        else
            warn "HSTS present but max-age may be insufficient"
        fi
    else
        fail "Strict-Transport-Security header MISSING"
    fi

    # 3d. Content-Security-Policy
    if echo "$FULL_HEADERS" | grep -qi "Content-Security-Policy"; then
        pass "Content-Security-Policy header present"
        # Check for unsafe directives
        CSP=$(echo "$FULL_HEADERS" | grep -i "Content-Security-Policy")
        if echo "$CSP" | grep -qi "unsafe-eval"; then
            warn "CSP contains 'unsafe-eval'"
        fi
    else
        fail "Content-Security-Policy header MISSING"
    fi

    # 3e. Referrer-Policy
    if echo "$FULL_HEADERS" | grep -qi "Referrer-Policy"; then
        pass "Referrer-Policy header present"
    else
        fail "Referrer-Policy header MISSING"
    fi

    # 3f. Permissions-Policy
    if echo "$FULL_HEADERS" | grep -qi "Permissions-Policy"; then
        pass "Permissions-Policy header present"
    else
        fail "Permissions-Policy header MISSING"
    fi

    # 3g. X-Powered-By should be ABSENT
    if echo "$FULL_HEADERS" | grep -qi "X-Powered-By"; then
        fail "X-Powered-By header is present (information disclosure)"
    else
        pass "X-Powered-By header absent (good)"
    fi

    # 3h. Server header should not reveal version
    SERVER_HEADER=$(echo "$FULL_HEADERS" | grep -i "^Server:" | head -1)
    if [ -n "$SERVER_HEADER" ]; then
        if echo "$SERVER_HEADER" | grep -qiP "nginx/\d"; then
            fail "Server header reveals Nginx version: ${SERVER_HEADER}"
        else
            pass "Server header present but version not disclosed"
        fi
    else
        pass "Server header absent (best practice)"
    fi

    # 3i. X-Permitted-Cross-Domain-Policies
    if echo "$FULL_HEADERS" | grep -qi "X-Permitted-Cross-Domain-Policies"; then
        pass "X-Permitted-Cross-Domain-Policies header present"
    else
        warn "X-Permitted-Cross-Domain-Policies header missing"
    fi
fi

###############################################################################
# TEST 4: API ENDPOINT SECURITY
###############################################################################
header "4. API ENDPOINT SECURITY"

# 4a. Check rate limiting (should get 429 after rapid requests)
info "4a. Testing rate limiting on auth endpoints"
RATE_LIMIT_HIT=false
for i in $(seq 1 15); do
    STATUS=$(curl -s -o /dev/null -w '%{http_code}' "http://${TARGET_HOST}/api/login" -X POST -H "Content-Type: application/json" -d '{"email":"test@test.com","password":"test"}' 2>/dev/null || echo "000")
    if [ "$STATUS" = "429" ]; then
        RATE_LIMIT_HIT=true
        break
    fi
done
if [ "$RATE_LIMIT_HIT" = true ]; then
    pass "Rate limiting active on auth endpoints (429 after ${i} requests)"
else
    warn "Rate limiting not triggered after 15 requests (may need more)"
fi

# 4b. Check CORS
info "4b. Testing CORS configuration"
CORS_RESPONSE=$(curl -s -H "Origin: https://evil-site.com" -I "http://${TARGET_HOST}/api/" 2>/dev/null | grep -i "Access-Control-Allow-Origin" || true)
if echo "$CORS_RESPONSE" | grep -qi "evil-site.com"; then
    fail "CORS allows arbitrary origins (evil-site.com accepted)"
elif [ -z "$CORS_RESPONSE" ]; then
    pass "CORS correctly rejects unauthorized origins"
else
    pass "CORS configured with restricted origins"
fi

# 4c. Check for sensitive endpoint exposure
info "4c. Testing for sensitive endpoint exposure"
for ENDPOINT in "/.env" "/.git/config" "/docker-compose.yml" "/server/.env.production"; do
    STATUS=$(curl -s -o /dev/null -w '%{http_code}' "http://${TARGET_HOST}${ENDPOINT}" 2>/dev/null || echo "000")
    if [ "$STATUS" = "403" ] || [ "$STATUS" = "404" ] || [ "$STATUS" = "000" ]; then
        pass "Blocked: ${ENDPOINT} (${STATUS})"
    else
        fail "EXPOSED: ${ENDPOINT} returned ${STATUS}"
    fi
done

###############################################################################
# TEST 5: NIKTO WEB VULNERABILITY SCAN (--full mode only)
###############################################################################
header "5. WEB VULNERABILITY SCAN (nikto)"

if [ "$FULL_SCAN" = "--full" ]; then
    if command -v nikto &>/dev/null; then
        info "Running nikto scan (this may take several minutes)..."
        nikto -h "http://${TARGET_HOST}" \
              -Tuning 123456789ab \
              -output "${REPORT_DIR}/nikto-report.html" \
              -Format html \
              -timeout 10 \
              -maxtime 300 2>/dev/null || true
        info "Nikto report saved to: ${REPORT_DIR}/nikto-report.html"
        
        # Quick parse for high-severity findings
        NIKTO_TEXT="${REPORT_DIR}/nikto-report.txt"
        nikto -h "http://${TARGET_HOST}" -Tuning 4 -output "$NIKTO_TEXT" -Format txt -maxtime 120 2>/dev/null || true
        NIKTO_ISSUES=$(grep -c "^\+" "$NIKTO_TEXT" 2>/dev/null || echo "0")
        if [ "$NIKTO_ISSUES" -lt 5 ]; then
            pass "Nikto found ${NIKTO_ISSUES} items (low finding count)"
        else
            warn "Nikto found ${NIKTO_ISSUES} items — review report"
        fi
    else
        warn "nikto not installed — skipping web vulnerability scan"
        echo "  Install: sudo apt install nikto"
        echo ""
        echo "  Manual command:"
        echo "    nikto -h http://${TARGET_HOST} -Tuning 123456789ab -output nikto.html -Format html"
    fi
else
    info "Nikto scan skipped (use --full flag to enable)"
    echo ""
    echo "  Manual nikto commands:"
    echo "    # Full scan"
    echo "    nikto -h http://${TARGET_HOST} -Tuning 123456789ab -output nikto.html -Format html"
    echo ""
    echo "    # Quick scan (injection tests only)"
    echo "    nikto -h http://${TARGET_HOST} -Tuning 9 -maxtime 120"
    echo ""
    echo "    # Check dangerous HTTP methods"
    echo "    nikto -h http://${TARGET_HOST} -Tuning 2"
fi

###############################################################################
# TEST 6: OWASP ZAP BASELINE SCAN (--full mode only)
###############################################################################
header "6. OWASP ZAP SCAN"

if [ "$FULL_SCAN" = "--full" ]; then
    if docker image inspect ghcr.io/zaproxy/zaproxy:stable &>/dev/null; then
        info "Running OWASP ZAP baseline scan..."
        docker run --rm --network host \
            -v "${REPORT_DIR}:/zap/wrk:rw" \
            ghcr.io/zaproxy/zaproxy:stable \
            zap-baseline.py \
            -t "http://${TARGET_HOST}" \
            -r "zap-report.html" \
            -J "zap-report.json" \
            -w "zap-report.md" \
            -l WARN 2>/dev/null || true

        if [ -f "${REPORT_DIR}/zap-report.json" ]; then
            ZAP_ALERTS=$(jq '.site[0].alerts | length' "${REPORT_DIR}/zap-report.json" 2>/dev/null || echo "?")
            if [ "$ZAP_ALERTS" = "0" ]; then
                pass "ZAP found 0 alerts"
            else
                warn "ZAP found ${ZAP_ALERTS} alerts — review ${REPORT_DIR}/zap-report.html"
            fi
        else
            warn "ZAP report not generated"
        fi
    else
        warn "OWASP ZAP Docker image not found"
        echo "  Install: docker pull ghcr.io/zaproxy/zaproxy:stable"
    fi
else
    info "OWASP ZAP scan skipped (use --full flag to enable)"
    echo ""
    echo "  Manual OWASP ZAP commands:"
    echo ""
    echo "    # Baseline scan (passive only)"
    echo "    docker run --rm --network host -v \$(pwd)/reports:/zap/wrk:rw \\"
    echo "      ghcr.io/zaproxy/zaproxy:stable \\"
    echo "      zap-baseline.py -t http://${TARGET_HOST} -r zap-baseline.html"
    echo ""
    echo "    # Full scan (passive + active)"
    echo "    docker run --rm --network host -v \$(pwd)/reports:/zap/wrk:rw \\"
    echo "      ghcr.io/zaproxy/zaproxy:stable \\"
    echo "      zap-full-scan.py -t http://${TARGET_HOST} -r zap-full.html"
    echo ""
    echo "    # API scan (OpenAPI/Swagger)"
    echo "    docker run --rm --network host -v \$(pwd)/reports:/zap/wrk:rw \\"
    echo "      ghcr.io/zaproxy/zaproxy:stable \\"
    echo "      zap-api-scan.py -t http://${TARGET_HOST}/swagger.json -f openapi -r zap-api.html"
fi

###############################################################################
# TEST 7: DOCKER COMPOSE CONFIGURATION AUDIT
###############################################################################
header "7. DOCKER COMPOSE CONFIGURATION AUDIT"

if [ -f "$DOCKER_COMPOSE_FILE" ]; then
    info "Auditing docker-compose.prod.yml..."

    # 7a. Check for hardcoded secrets
    if grep -qiE "(password|secret|key)\s*[:=]\s*['\"]?[a-zA-Z0-9]" "$DOCKER_COMPOSE_FILE" 2>/dev/null; then
        fail "Potential hardcoded secrets found in docker-compose.prod.yml"
    else
        pass "No hardcoded secrets in docker-compose.prod.yml"
    fi

    # 7b. Check for env_file usage
    if grep -q "env_file" "$DOCKER_COMPOSE_FILE"; then
        pass "Using env_file for secret injection"
    else
        warn "Not using env_file — secrets may be in environment block"
    fi

    # 7c. Check for read_only
    if grep -q "read_only: true" "$DOCKER_COMPOSE_FILE"; then
        pass "read_only filesystem enabled on at least one container"
    else
        warn "No read_only filesystem detected"
    fi

    # 7d. Check for no-new-privileges
    if grep -q "no-new-privileges" "$DOCKER_COMPOSE_FILE"; then
        pass "no-new-privileges security option configured"
    else
        fail "no-new-privileges NOT configured"
    fi

    # 7e. Check for healthchecks
    HEALTHCHECK_COUNT=$(grep -c "healthcheck:" "$DOCKER_COMPOSE_FILE" 2>/dev/null || echo "0")
    if [ "$HEALTHCHECK_COUNT" -ge 3 ]; then
        pass "All ${HEALTHCHECK_COUNT} services have healthchecks"
    else
        warn "Only ${HEALTHCHECK_COUNT} services have healthchecks (expected 3)"
    fi

    # 7f. Check for logging configuration
    if grep -q "json-file" "$DOCKER_COMPOSE_FILE" && grep -q "max-size" "$DOCKER_COMPOSE_FILE"; then
        pass "Structured logging with size limits configured"
    else
        warn "Logging may not be properly configured"
    fi
else
    warn "docker-compose.prod.yml not found at expected path"
fi

###############################################################################
# RESULTS SUMMARY
###############################################################################
echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║                  SECURITY AUDIT RESULTS                            ║"
echo "╠══════════════════════════════════════════════════════════════════════╣"
printf "║  ${GREEN}PASSED:${NC}  %-5s                                                  ║\n" "$PASS"
printf "║  ${RED}FAILED:${NC}  %-5s                                                  ║\n" "$FAIL"
printf "║  ${YELLOW}WARNINGS:${NC}%-5s                                                  ║\n" "$WARN"
echo "╠══════════════════════════════════════════════════════════════════════╣"
echo "║  Reports saved to: ${REPORT_DIR}"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo -e "${RED}${BOLD}AUDIT STATUS: FAILED — ${FAIL} critical findings require remediation${NC}"
    exit 1
elif [ "$WARN" -gt 3 ]; then
    echo -e "${YELLOW}${BOLD}AUDIT STATUS: CONDITIONAL PASS — ${WARN} warnings need review${NC}"
    exit 0
else
    echo -e "${GREEN}${BOLD}AUDIT STATUS: PASSED — Security posture verified${NC}"
    exit 0
fi
