#!/usr/bin/env bash
# ────────────────────────────────────────────────────────────────────────────
# deploy.sh
#
# Force a fresh ECS deployment (picks up newly pushed images) and waits
# for the service to stabilise.
#
# Run AFTER build-and-push.sh
# ────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REGION="${AWS_REGION:-ap-southeast-2}"
PROJECT="${PROJECT:-summit-demo}"

echo ""
echo "▶ Forcing fresh ECS deployments…"

aws ecs update-service \
  --cluster "${PROJECT}" \
  --service  "${PROJECT}-dashboard" \
  --force-new-deployment \
  --region   "${REGION}" \
  --output    text \
  --query    "service.serviceName" \
  | xargs -I{} echo "  Triggered: {}"

aws ecs update-service \
  --cluster "${PROJECT}" \
  --service  "${PROJECT}-upstream" \
  --force-new-deployment \
  --region   "${REGION}" \
  --output    text \
  --query    "service.serviceName" \
  | xargs -I{} echo "  Triggered: {}"

echo ""
echo "▶ Waiting for dashboard service to stabilise (up to 5 min)…"
aws ecs wait services-stable \
  --cluster "${PROJECT}" \
  --services "${PROJECT}-dashboard" \
  --region   "${REGION}"

echo "  ✓ Dashboard service is stable."

echo ""
echo "▶ Fetching ALB DNS name…"
ALB_DNS=$(aws elbv2 describe-load-balancers \
  --names "${PROJECT}-alb" \
  --region "${REGION}" \
  --query "LoadBalancers[0].DNSName" \
  --output text)

echo ""
echo "════════════════════════════════════════════════════════"
echo "  ✅ Deployment complete!"
echo ""
echo "  Dashboard URL: http://${ALB_DNS}"
echo ""
echo "  The Inspector scan may still be running."
echo "  Hit the Refresh button in the app, or wait ~5 min"
echo "  for findings to appear."
echo "════════════════════════════════════════════════════════"
echo ""
