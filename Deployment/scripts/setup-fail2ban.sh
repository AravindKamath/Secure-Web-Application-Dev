#!/usr/bin/env bash
###############################################################################
# setup-fail2ban.sh — Fail2Ban Configuration for Ubuntu 22.04
#
# Configuration:
#   - SSH jail: 5 failed attempts → 1-hour ban
#   - Find window: 10 minutes
#   - Nginx jails for HTTP auth and bot scanning
#
# Usage: sudo bash setup-fail2ban.sh
###############################################################################
set -euo pipefail

echo "==> [Fail2Ban] Installing fail2ban..."
apt-get update -qq
apt-get install -y -qq fail2ban

echo "==> [Fail2Ban] Creating /etc/fail2ban/jail.local..."
cat > /etc/fail2ban/jail.local << 'EOF'
# ── Fail2Ban Local Configuration ────────────────────────────────────────────
# This file overrides /etc/fail2ban/jail.conf
# Do NOT edit jail.conf — it will be overwritten on package upgrades.

[DEFAULT]
# Ban duration: 1 hour
bantime  = 3600
# Detection window: 10 minutes
findtime = 600
# Max retries before ban
maxretry = 5
# Ban action — use UFW integration
banaction = ufw

# ── SSH Jail ─────────────────────────────────────────────────────────────────
[sshd]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 5
bantime  = 3600
findtime = 600

# ── Nginx HTTP Auth Jail ─────────────────────────────────────────────────────
[nginx-http-auth]
enabled  = true
port     = http,https
filter   = nginx-http-auth
logpath  = /var/log/nginx/error.log
maxretry = 5
bantime  = 3600

# ── Nginx Bot Search (404 scanning) ─────────────────────────────────────────
[nginx-botsearch]
enabled  = true
port     = http,https
filter   = nginx-botsearch
logpath  = /var/log/nginx/access.log
maxretry = 10
bantime  = 7200
findtime = 600
EOF

echo "==> [Fail2Ban] Enabling and starting fail2ban..."
systemctl enable fail2ban
systemctl restart fail2ban

echo "==> [Fail2Ban] Status:"
fail2ban-client status

echo ""
echo "==> [Fail2Ban] Configuration complete ✔"
echo "    SSH: 5 failed attempts → 1-hour ban"
echo "    Nginx HTTP Auth: 5 attempts → 1-hour ban"
echo "    Nginx Bot Scan: 10 attempts → 2-hour ban"
