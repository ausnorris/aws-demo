#!/usr/bin/env bash
# ────────────────────────────────────────────────────────────────────────────
# check-findings.sh
#
# Quick CLI summary of Inspector findings for both repos.
# Useful to verify scans completed before the event.
# ────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REGION="${AWS_REGION:-ap-southeast-2}"
PROJECT="${PROJECT:-summit-demo}"
UPSTREAM_REPO="${PROJECT}-upstream"
CG_REPO="${PROJECT}-chainguard"

summarise() {
  local repo="$1"
  local label="$2"

  local total
  total=$(aws inspector2 list-findings \
    --region "${REGION}" \
    --filter-criteria "{\"ecrImageRepositoryName\":[{\"comparison\":\"EQUALS\",\"value\":\"${repo}\"}]}" \
    --query "length(findings)" \
    --output text 2>/dev/null || echo "0")

  local critical high medium low
  critical=$(aws inspector2 list-findings \
    --region "${REGION}" \
    --filter-criteria "{\"ecrImageRepositoryName\":[{\"comparison\":\"EQUALS\",\"value\":\"${repo}\"}],\"severity\":[{\"comparison\":\"EQUALS\",\"value\":\"CRITICAL\"}]}" \
    --query "length(findings)" --output text 2>/dev/null || echo "0")

  high=$(aws inspector2 list-findings \
    --region "${REGION}" \
    --filter-criteria "{\"ecrImageRepositoryName\":[{\"comparison\":\"EQUALS\",\"value\":\"${repo}\"}],\"severity\":[{\"comparison\":\"EQUALS\",\"value\":\"HIGH\"}]}" \
    --query "length(findings)" --output text 2>/dev/null || echo "0")

  medium=$(aws inspector2 list-findings \
    --region "${REGION}" \
    --filter-criteria "{\"ecrImageRepositoryName\":[{\"comparison\":\"EQUALS\",\"value\":\"${repo}\"}],\"severity\":[{\"comparison\":\"EQUALS\",\"value\":\"MEDIUM\"}]}" \
    --query "length(findings)" --output text 2>/dev/null || echo "0")

  low=$(aws inspector2 list-findings \
    --region "${REGION}" \
    --filter-criteria "{\"ecrImageRepositoryName\":[{\"comparison\":\"EQUALS\",\"value\":\"${repo}\"}],\"severity\":[{\"comparison\":\"EQUALS\",\"value\":\"LOW\"}]}" \
    --query "length(findings)" --output text 2>/dev/null || echo "0")

  echo "  ${label}"
  echo "    Total:    ${total}"
  echo "    Critical: ${critical}  High: ${high}  Medium: ${medium}  Low: ${low}"
}

echo ""
echo "═══════════════════════════════════════════════"
echo "  Inspector v2 — Finding Summary"
echo "  Region: ${REGION}"
echo "═══════════════════════════════════════════════"
summarise "${UPSTREAM_REPO}" "⚠  Upstream  (${UPSTREAM_REPO})"
echo ""
summarise "${CG_REPO}"       "✅ Chainguard (${CG_REPO})"
echo "═══════════════════════════════════════════════"
echo ""
echo "  Inspector console:"
echo "  https://${REGION}.console.aws.amazon.com/inspector/v2/home?region=${REGION}#/findings/container"
echo ""
