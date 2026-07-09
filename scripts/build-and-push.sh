#!/usr/bin/env bash
# ────────────────────────────────────────────────────────────────────────────
# build-and-push.sh
#
# Builds both the upstream and Chainguard images and pushes them to ECR.
# Run this from the repo root AFTER `terraform apply` has created the repos.
#
# Usage:
#   ./scripts/build-and-push.sh [--region ap-southeast-2] [--tag latest]
# ────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────────────
REGION="${AWS_REGION:-ap-southeast-2}"
TAG="${IMAGE_TAG:-latest}"
PROJECT="${PROJECT:-summit-demo}"
PLATFORM="${BUILD_PLATFORM:-linux/amd64}"  # use linux/arm64 for Graviton

# ── Parse args ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case $1 in
    --region)  REGION="$2";  shift 2 ;;
    --tag)     TAG="$2";     shift 2 ;;
    --project) PROJECT="$2"; shift 2 ;;
    --platform)PLATFORM="$2";shift 2 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

# ── Derived values ────────────────────────────────────────────────────────────
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
ECR_BASE="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"
UPSTREAM_URI="${ECR_BASE}/${PROJECT}-upstream:${TAG}"
CHAINGUARD_URI="${ECR_BASE}/${PROJECT}-chainguard:${TAG}"

echo ""
echo "════════════════════════════════════════════════════════"
echo "  Container Security Showdown — Build & Push"
echo "════════════════════════════════════════════════════════"
echo "  Region:       ${REGION}"
echo "  Account:      ${ACCOUNT_ID}"
echo "  Tag:          ${TAG}"
echo "  Platform:     ${PLATFORM}"
echo "  Upstream URI: ${UPSTREAM_URI}"
echo "  CG URI:       ${CHAINGUARD_URI}"
echo "════════════════════════════════════════════════════════"
echo ""

# ── Authenticate to cgr.dev (Chainguard private registry) ────────────────────
echo "▶ Authenticating to cgr.dev/chainguard-private…"
chainctl auth configure-docker

# ── Authenticate to ECR ───────────────────────────────────────────────────────
echo "▶ Authenticating to ECR…"
aws ecr get-login-password --region "${REGION}" \
  | docker login --username AWS --password-stdin "${ECR_BASE}"

# ── Build upstream image ──────────────────────────────────────────────────────
echo ""
echo "▶ Building UPSTREAM image (python:3.11)…"
echo "  This image will have many CVEs — that's expected for the demo."
docker build \
  --no-cache \
  --platform "${PLATFORM}" \
  --provenance=false \
  --file Dockerfile.upstream \
  --tag "${UPSTREAM_URI}" \
  --label "demo.type=upstream" \
  --label "demo.project=${PROJECT}" \
  .

echo "▶ Pushing upstream image…"
docker push "${UPSTREAM_URI}"

UPSTREAM_SIZE=$(docker image inspect "${UPSTREAM_URI}" --format='{{.Size}}' | awk '{printf "%.0f MB", $1/1048576}')
echo "  ✓ Pushed upstream  (${UPSTREAM_SIZE})"

# ── Build Chainguard image ────────────────────────────────────────────────────
echo ""
echo "▶ Building CHAINGUARD image (cgr.dev/chainguard/python)…"
echo "  This distroless image should have 0 CVEs."
docker build \
  --no-cache \
  --platform "${PLATFORM}" \
  --provenance=false \
  --file Dockerfile.chainguard \
  --tag "${CHAINGUARD_URI}" \
  --label "demo.type=chainguard" \
  --label "demo.project=${PROJECT}" \
  .

echo "▶ Pushing Chainguard image…"
docker push "${CHAINGUARD_URI}"

CG_SIZE=$(docker image inspect "${CHAINGUARD_URI}" --format='{{.Size}}' | awk '{printf "%.0f MB", $1/1048576}')
echo "  ✓ Pushed Chainguard (${CG_SIZE})"

# ── Print summary ─────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════"
echo "  ✅ Both images pushed successfully!"
echo ""
echo "  Upstream  : ${UPSTREAM_SIZE}"
echo "  Chainguard: ${CG_SIZE}"
echo ""
echo "  AWS Inspector will begin scanning within ~60 seconds."
echo "  Full results typically available within 5–15 minutes."
echo ""
echo "  View in Inspector console:"
echo "  https://${REGION}.console.aws.amazon.com/inspector/v2/home?region=${REGION}#/findings/container"
echo "════════════════════════════════════════════════════════"
echo ""
echo "  Next step: Force ECS to redeploy with the new images:"
echo "    aws ecs update-service --cluster ${PROJECT} --service ${PROJECT}-dashboard --force-new-deployment --region ${REGION}"
echo "    aws ecs update-service --cluster ${PROJECT} --service ${PROJECT}-upstream --force-new-deployment --region ${REGION}"
echo ""
