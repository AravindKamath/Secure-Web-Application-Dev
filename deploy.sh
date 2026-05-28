#!/usr/bin/env bash
# Reminder: run "chmod +x deploy.sh" before executing this script.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"

umask 077

fetch_param() {
  local param_path="$1"
  aws ssm get-parameter --name "$param_path" --with-decryption --query "Parameter.Value" --output text
}

echo "🧪 Preparing temporary environment file..."
: > "$ENV_FILE"

# Single-mapping secrets
printf "POSTGRES_PASSWORD=%s\n" "$(fetch_param "/pernstore/prod/db/password")" >> "$ENV_FILE"
printf "JWT_SECRET=%s\n" "$(fetch_param "/pernstore/prod/auth/jwt_secret")" >> "$ENV_FILE"
printf "MFA_ENCRYPTION_KEY=%s\n" "$(fetch_param "/pernstore/prod/auth/mfa_key")" >> "$ENV_FILE"
printf "STRIPE_SECRET_KEY=%s\n" "$(fetch_param "/pernstore/prod/payment/stripe_secret")" >> "$ENV_FILE"
printf "RAZORPAY_KEY_SECRET=%s\n" "$(fetch_param "/pernstore/prod/payment/razorpay_secret")" >> "$ENV_FILE"
printf "OAUTH_CLIENT_SECRET=%s\n" "$(fetch_param "/pernstore/prod/google/oauth_client_secret")" >> "$ENV_FILE"
printf "OAUTH_REFRESH_TOKEN=%s\n" "$(fetch_param "/pernstore/prod/google/oauth_refresh_token")" >> "$ENV_FILE"
printf "CLIENT_ID=%s\n" "$(fetch_param "/pernstore/prod/smtp/client_id")" >> "$ENV_FILE"
printf "CLIENT_SECRET=%s\n" "$(fetch_param "/pernstore/prod/smtp/client_secret")" >> "$ENV_FILE"
printf "REFRESH_TOKEN=%s\n" "$(fetch_param "/pernstore/prod/smtp/refresh_token")" >> "$ENV_FILE"
printf "VITE_API_URL=%s\n" "$(fetch_param "/pernstore/prod/config/api_url")" >> "$ENV_FILE"

# Consolidated mappings
RAZORPAY_KEY_ID_VALUE="$(fetch_param "/pernstore/prod/payment/razorpay_id")"
printf "RAZORPAY_KEY_ID=%s\n" "$RAZORPAY_KEY_ID_VALUE" >> "$ENV_FILE"
printf "VITE_RAZORPAY_KEY_ID=%s\n" "$RAZORPAY_KEY_ID_VALUE" >> "$ENV_FILE"

GOOGLE_CLIENT_ID_VALUE="$(fetch_param "/pernstore/prod/google/oauth_client_id")"
printf "OAUTH_CLIENT_ID=%s\n" "$GOOGLE_CLIENT_ID_VALUE" >> "$ENV_FILE"
printf "VITE_GOOGLE_CLIENT_ID=%s\n" "$GOOGLE_CLIENT_ID_VALUE" >> "$ENV_FILE"

echo "🚀 Environment file ready. Starting Docker Compose..."
docker compose up -d --build

echo "🧹 Securely removing temporary .env file..."
shred -u "$ENV_FILE"

echo "✅ Deployment complete."
