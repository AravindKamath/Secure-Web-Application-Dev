#!/usr/bin/env bash
###############################################################################
# setup-nginx.sh — Nginx Reverse Proxy Setup for Ubuntu 22.04
#
# Configuration:
#   - Reverse proxy to Node.js on http://127.0.0.1:9000
#   - Serve Vite-built client as static files
#   - Security headers (complement Helmet)
#   - Rate limiting at proxy layer
#   - Prepared for SSL/TLS via certbot
#
# Usage: sudo bash setup-nginx.sh
###############################################################################
set -euo pipefail

NGINX_CONF="/etc/nginx/sites-available/pern-store"
NGINX_ENABLED="/etc/nginx/sites-enabled/pern-store"
CLIENT_BUILD_DIR="/var/www/pern-store/client"

echo "==> [Nginx] Installing nginx..."
apt-get update -qq
apt-get install -y -qq nginx

echo "==> [Nginx] Creating client static directory..."
mkdir -p "${CLIENT_BUILD_DIR}"

echo "==> [Nginx] Removing default site..."
rm -f /etc/nginx/sites-enabled/default

echo "==> [Nginx] Deploying pern-store configuration..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIGS_DIR="${SCRIPT_DIR}/../configs"

if [ -f "${CONFIGS_DIR}/nginx-pern-store.conf" ]; then
  cp "${CONFIGS_DIR}/nginx-pern-store.conf" "${NGINX_CONF}"
else
  echo "    ERROR: ${CONFIGS_DIR}/nginx-pern-store.conf not found!"
  exit 1
fi

echo "==> [Nginx] Enabling site..."
ln -sf "${NGINX_CONF}" "${NGINX_ENABLED}"

echo "==> [Nginx] Testing configuration..."
nginx -t

echo "==> [Nginx] Restarting nginx..."
systemctl enable nginx
systemctl restart nginx

echo ""
echo "==> [Nginx] Reverse proxy configured ✔"
echo "    API:    http://localhost → http://127.0.0.1:9000/api/*"
echo "    Client: http://localhost → ${CLIENT_BUILD_DIR}"
echo ""
echo "    To enable HTTPS with Let's Encrypt:"
echo "    sudo apt install certbot python3-certbot-nginx"
echo "    sudo certbot --nginx -d yourdomain.com"
