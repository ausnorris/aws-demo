#!/usr/bin/env bash
# store-cg-credentials.sh
#
# One-time setup: write Chainguard Libraries credentials into AWS SSM
# Parameter Store as SecureStrings.  Run this BEFORE terraform apply.
#
# Usage:
#   ./scripts/store-cg-credentials.sh
#
# The script reads credentials from environment variables so they are never
# written to disk or visible in shell history.
#
# Required env vars:
#   CG_LIBRARIES_USER   – pull token username (e.g. abc123/def456)
#   CG_LIBRARIES_TOKEN  – pull token password (JWT)
#
# Optional env vars:
#   CG_API_TOKEN        – Chainguard console API token for the Sentinel
#                         near-miss panel (enable_sentinel = true in tfvars).
#                         Obtain with:
#                           chainctl auth token --audience=https://console-api.enforce.dev
#   AWS_REGION          – defaults to ap-southeast-2
#   PROJECT             – SSM path prefix project name, defaults to summit-demo
#
# Example (credentials sourced from a password manager / CI secrets):
#   export CG_LIBRARIES_USER="$(op read op://vault/cg-pull-token/username)"
#   export CG_LIBRARIES_TOKEN="$(op read op://vault/cg-pull-token/password)"
#   ./scripts/store-cg-credentials.sh

set -euo pipefail

REGION="${AWS_REGION:-ap-southeast-2}"
PROJECT="${PROJECT:-summit-demo}"
PREFIX="/${PROJECT}"

# ── Validate inputs ────────────────────────────────────────────────────────────
if [[ -z "${CG_LIBRARIES_USER:-}" ]]; then
  echo "ERROR: CG_LIBRARIES_USER is not set." >&2
  echo "  Export it before running this script — do NOT pass it as a CLI argument." >&2
  exit 1
fi

if [[ -z "${CG_LIBRARIES_TOKEN:-}" ]]; then
  echo "ERROR: CG_LIBRARIES_TOKEN is not set." >&2
  echo "  Export it before running this script — do NOT pass it as a CLI argument." >&2
  exit 1
fi

# ── Store parameters ───────────────────────────────────────────────────────────
echo "Storing credentials in SSM (${REGION}) under ${PREFIX}/ ..."

aws ssm put-parameter \
  --region "${REGION}" \
  --name   "${PREFIX}/cg-libraries-user" \
  --value  "${CG_LIBRARIES_USER}" \
  --type   "SecureString" \
  --overwrite \
  --description "Chainguard Libraries pull token username (summit-demo)" \
  --no-cli-pager

aws ssm put-parameter \
  --region "${REGION}" \
  --name   "${PREFIX}/cg-libraries-token" \
  --value  "${CG_LIBRARIES_TOKEN}" \
  --type   "SecureString" \
  --overwrite \
  --description "Chainguard Libraries pull token JWT (summit-demo)" \
  --no-cli-pager

# Sentinel console API token — optional, only needed for the near-miss panel.
if [[ -n "${CG_API_TOKEN:-}" ]]; then
  aws ssm put-parameter \
    --region "${REGION}" \
    --name   "${PREFIX}/cg-api-token" \
    --value  "${CG_API_TOKEN}" \
    --type   "SecureString" \
    --overwrite \
    --description "Chainguard console API token for Sentinel blocklist (summit-demo)" \
    --no-cli-pager
fi

echo ""
echo "✓ Credentials stored:"
echo "  ${PREFIX}/cg-libraries-user"
echo "  ${PREFIX}/cg-libraries-token"
if [[ -n "${CG_API_TOKEN:-}" ]]; then
  echo "  ${PREFIX}/cg-api-token"
else
  echo ""
  echo "  (CG_API_TOKEN not set — skipped ${PREFIX}/cg-api-token."
  echo "   The Sentinel near-miss panel needs it when enable_sentinel = true.)"
fi
echo ""
echo "Verify (value will be shown — only run in a secure terminal):"
echo "  aws ssm get-parameter --region ${REGION} --name ${PREFIX}/cg-libraries-user --with-decryption --query Parameter.Value --output text"
echo ""
echo "Now run: terraform apply"
