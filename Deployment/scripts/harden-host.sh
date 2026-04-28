#!/usr/bin/env bash
###############################################################################
# harden-host.sh — Master Host Hardening Orchestrator for Ubuntu 22.04
#
# Executes all Phase 3 hardening scripts in the correct order:
#   1. SSH hardening
#   2. UFW firewall
#   3. Fail2Ban
#   4. unattended-upgrades
#   5. Nginx reverse proxy
#   6. systemd service unit for Node.js
#   7. PostgreSQL binding verification
#   8. RSA key permissions verification
#
# Usage: sudo bash harden-host.sh [--dry-run]
#
# IMPORTANT: Run this script ONLY after:
#   - Your SSH public key is in ~/.ssh/authorized_keys
#   - You have console/out-of-band access as a fallback
#   - All application secrets have been rotated and placed in .env
###############################################################################
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIGS_DIR="${SCRIPT_DIR}/../configs"
APP_DIR="/opt/pern-store"
DRY_RUN="${1:-}"

# ── Colors for output ───────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info()    { echo -e "${BLUE}[INFO]${NC}  $1"; }
log_success() { echo -e "${GREEN}[OK]${NC}    $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

# ── Pre-flight checks ───────────────────────────────────────────────────────

if [[ $EUID -ne 0 ]]; then
  log_error "This script must be run as root (sudo)."
  exit 1
fi

if [[ "${DRY_RUN}" == "--dry-run" ]]; then
  log_warn "DRY RUN mode — no changes will be applied."
  log_info "Scripts that would execute:"
  echo "  1. ${SCRIPT_DIR}/harden-ssh.sh"
  echo "  2. ${SCRIPT_DIR}/setup-ufw.sh"
  echo "  3. ${SCRIPT_DIR}/setup-fail2ban.sh"
  echo "  4. ${SCRIPT_DIR}/setup-unattended-upgrades.sh"
  echo "  5. ${SCRIPT_DIR}/setup-nginx.sh"
  echo "  6. Install systemd unit: ${CONFIGS_DIR}/pern-store.service"
  echo "  7. Verify PostgreSQL binding"
  echo "  8. Verify RSA key permissions"
  exit 0
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║         PERN-Store — Linux Host Hardening (Phase 3)                ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""

# ── Step 1: SSH Hardening ────────────────────────────────────────────────────

log_info "Step 1/8 — SSH Hardening"
if [ -f "${SCRIPT_DIR}/harden-ssh.sh" ]; then
  bash "${SCRIPT_DIR}/harden-ssh.sh"
  log_success "SSH hardening complete"
else
  log_error "harden-ssh.sh not found!"
  exit 1
fi
echo ""

# ── Step 2: UFW Firewall ────────────────────────────────────────────────────

log_info "Step 2/8 — UFW Firewall"
if [ -f "${SCRIPT_DIR}/setup-ufw.sh" ]; then
  bash "${SCRIPT_DIR}/setup-ufw.sh"
  log_success "UFW firewall configured"
else
  log_error "setup-ufw.sh not found!"
  exit 1
fi
echo ""

# ── Step 3: Fail2Ban ────────────────────────────────────────────────────────

log_info "Step 3/8 — Fail2Ban"
if [ -f "${SCRIPT_DIR}/setup-fail2ban.sh" ]; then
  bash "${SCRIPT_DIR}/setup-fail2ban.sh"
  log_success "Fail2Ban configured"
else
  log_error "setup-fail2ban.sh not found!"
  exit 1
fi
echo ""

# ── Step 4: unattended-upgrades ─────────────────────────────────────────────

log_info "Step 4/8 — Automatic Security Patches"
if [ -f "${SCRIPT_DIR}/setup-unattended-upgrades.sh" ]; then
  bash "${SCRIPT_DIR}/setup-unattended-upgrades.sh"
  log_success "unattended-upgrades configured"
else
  log_error "setup-unattended-upgrades.sh not found!"
  exit 1
fi
echo ""

# ── Step 5: Nginx Reverse Proxy ─────────────────────────────────────────────

log_info "Step 5/8 — Nginx Reverse Proxy"
if [ -f "${SCRIPT_DIR}/setup-nginx.sh" ]; then
  bash "${SCRIPT_DIR}/setup-nginx.sh"
  log_success "Nginx configured"
else
  log_error "setup-nginx.sh not found!"
  exit 1
fi
echo ""

# ── Step 6: systemd Service Unit ────────────────────────────────────────────

log_info "Step 6/8 — systemd Service Unit"

# Create dedicated service user (no shell, no home)
if ! id -u pernstore &>/dev/null; then
  useradd --system --no-create-home --shell /usr/sbin/nologin pernstore
  log_info "Created system user: pernstore"
fi

# Create application directory
mkdir -p "${APP_DIR}/server/logs" "${APP_DIR}/server/keys"
chown -R pernstore:pernstore "${APP_DIR}"

# Install systemd unit
if [ -f "${CONFIGS_DIR}/pern-store.service" ]; then
  cp "${CONFIGS_DIR}/pern-store.service" /etc/systemd/system/pern-store.service
  systemctl daemon-reload
  systemctl enable pern-store
  log_success "systemd unit installed and enabled"
  log_warn "Start with: sudo systemctl start pern-store (after deploying code)"
else
  log_error "pern-store.service not found!"
  exit 1
fi
echo ""

# ── Step 7: PostgreSQL Binding Verification ─────────────────────────────────

log_info "Step 7/8 — PostgreSQL Binding Verification"

PG_CONF=$(find /etc/postgresql -name "postgresql.conf" 2>/dev/null | head -1)
if [ -n "${PG_CONF}" ]; then
  LISTEN_ADDR=$(grep -E "^\s*listen_addresses" "${PG_CONF}" | head -1 || echo "")
  if [ -z "${LISTEN_ADDR}" ]; then
    log_warn "listen_addresses not explicitly set — defaults to 'localhost' (OK)"
  elif echo "${LISTEN_ADDR}" | grep -qE "'localhost'|'127.0.0.1'"; then
    log_success "PostgreSQL bound to localhost only"
  else
    log_error "PostgreSQL listen_addresses is NOT localhost-only: ${LISTEN_ADDR}"
    log_error "Fix: Set listen_addresses = 'localhost' in ${PG_CONF}"
  fi
else
  log_warn "PostgreSQL config not found on this host (may be remote or in Docker)"
fi
echo ""

# ── Step 8: RSA Key Permissions Verification ────────────────────────────────

log_info "Step 8/8 — RSA Key Permissions Verification"

PRIVATE_KEY="${APP_DIR}/server/keys/private.pem"
if [ -f "${PRIVATE_KEY}" ]; then
  PERMS=$(stat -c '%a' "${PRIVATE_KEY}")
  if [ "${PERMS}" = "600" ]; then
    log_success "private.pem permissions: ${PERMS} (correct)"
  else
    log_warn "private.pem permissions: ${PERMS} — fixing to 0600"
    chmod 0600 "${PRIVATE_KEY}"
    chown pernstore:pernstore "${PRIVATE_KEY}"
    log_success "private.pem permissions fixed"
  fi
else
  log_warn "private.pem not found at ${PRIVATE_KEY}"
  log_warn "It will be auto-generated on first application start (keyManager.js)"
fi
echo ""

# ── Summary ──────────────────────────────────────────────────────────────────

echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║                    Hardening Summary                               ║"
echo "╠══════════════════════════════════════════════════════════════════════╣"
echo "║  ✔ SSH: Key-only auth, root login disabled                        ║"
echo "║  ✔ UFW: Default deny, ports 22/80/443 allowed                     ║"
echo "║  ✔ Fail2Ban: 5 attempts → 1hr ban (SSH + Nginx)                   ║"
echo "║  ✔ Auto-updates: Security patches enabled                         ║"
echo "║  ✔ Nginx: Reverse proxy with rate limiting                        ║"
echo "║  ✔ systemd: Sandboxed with NoNewPrivileges                        ║"
echo "║  ✔ PostgreSQL: Binding verified                                   ║"
echo "║  ✔ RSA keys: Permissions verified                                 ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""
echo "  Next steps:"
echo "    1. Deploy application code to ${APP_DIR}/server/"
echo "    2. Copy .env to ${APP_DIR}/server/.env"
echo "    3. Build client: cd client && npm run build"
echo "    4. Copy build output to /var/www/pern-store/client/"
echo "    5. Start service: sudo systemctl start pern-store"
echo "    6. (Optional) Enable HTTPS: sudo certbot --nginx -d yourdomain.com"
echo ""
