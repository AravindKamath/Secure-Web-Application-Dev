#!/usr/bin/env bash
###############################################################################
# setup-ufw.sh — UFW Firewall Configuration for Ubuntu 22.04
#
# Policy:
#   - Default deny incoming
#   - Default allow outgoing
#   - Allow: SSH (22), HTTP (80), HTTPS (443)
#   - PostgreSQL (5432) NOT opened — must remain bound to 127.0.0.1
#
# Usage: sudo bash setup-ufw.sh
###############################################################################
set -euo pipefail

echo "==> [UFW] Resetting UFW to defaults..."
ufw --force reset

echo "==> [UFW] Setting default policies..."
ufw default deny incoming
ufw default allow outgoing

echo "==> [UFW] Allowing SSH (22/tcp)..."
ufw allow 22/tcp comment 'SSH'

echo "==> [UFW] Allowing HTTP (80/tcp)..."
ufw allow 80/tcp comment 'HTTP'

echo "==> [UFW] Allowing HTTPS (443/tcp)..."
ufw allow 443/tcp comment 'HTTPS'

echo "==> [UFW] Enabling firewall..."
ufw --force enable

echo "==> [UFW] Current status:"
ufw status verbose

echo ""
echo "==> [UFW] Firewall configured ✔"
echo "    NOTE: PostgreSQL (5432) is intentionally NOT opened."
echo "    It must remain bound to 127.0.0.1 in postgresql.conf."
