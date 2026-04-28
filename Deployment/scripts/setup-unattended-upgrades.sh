#!/usr/bin/env bash
###############################################################################
# setup-unattended-upgrades.sh — Automatic Security Patches for Ubuntu 22.04
#
# Configuration:
#   - Security updates only (Ubuntu-security origin)
#   - Automatic reboot at 04:00 if needed
#   - Email notifications (optional — configure SMTP first)
#   - Remove unused dependencies after upgrade
#
# Usage: sudo bash setup-unattended-upgrades.sh
###############################################################################
set -euo pipefail

echo "==> [Upgrades] Installing unattended-upgrades..."
apt-get update -qq
apt-get install -y -qq unattended-upgrades apt-listchanges

echo "==> [Upgrades] Configuring /etc/apt/apt.conf.d/50unattended-upgrades..."
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
// Automatically upgrade packages from these origins:
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};

// Packages to never update (add package names here if needed):
Unattended-Upgrade::Package-Blacklist {
};

// Automatically reboot if required, at 04:00
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";

// Remove unused automatically installed kernel-related packages
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";

// Remove unused dependencies after upgrade
Unattended-Upgrade::Remove-Unused-Dependencies "true";

// Remove new unused dependencies after upgrade
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";

// Enable syslog logging
Unattended-Upgrade::SyslogEnable "true";
Unattended-Upgrade::SyslogFacility "daemon";
EOF

echo "==> [Upgrades] Configuring /etc/apt/apt.conf.d/20auto-upgrades..."
cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
EOF

echo "==> [Upgrades] Enabling and starting unattended-upgrades..."
systemctl enable unattended-upgrades
systemctl restart unattended-upgrades

echo "==> [Upgrades] Verifying configuration..."
unattended-upgrades --dry-run --debug 2>&1 | tail -5

echo ""
echo "==> [Upgrades] Automatic security patches configured ✔"
echo "    Security-only updates enabled"
echo "    Auto-reboot at 04:00 if required"
