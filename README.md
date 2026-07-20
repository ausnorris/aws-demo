# 🛡️ Container Security Showdown — AWS Summit Sydney

A live, interactive demo that dramatically shows the CVE difference between a standard upstream container image and a [Chainguard](https://chainguard.dev) distroless image — all powered by AWS Inspector v2, ECR, and ECS Fargate.

---

## What it does

| Feature | Detail |
|---------|--------|
| **Side-by-side CVE dashboard** | Animated counters show upstream CVE count (typically 200–500+) vs Chainguard (typically 0) |
| **Severity breakdown** | Critical / High / Medium / Low counts with bar chart |
| **Image size comparison** | Animated bars showing how much smaller Chainguard images are |
| **QR codes** | Each card has a scannable QR code — attendees scan with their phone to see the full CVE list |
| **Auto-refresh** | Data polls AWS Inspector every 5 minutes |
| **Manual refresh** | "Refresh" button triggers a live re-fetch |
| **Mobile findings page** | `/findings/upstream` and `/findings/chainguard` — fully mobile-optimised |
| **Two live ECS services** | Both the upstream *and* Chainguard images are actually deployed and running |

---

## Architecture

```
                        ┌─────────────────────────────────────────────┐
                        │                  AWS Account                │
                        │                                             │
  Browser/Phone ──────► │  ALB (public)                               │
                        │   │                                         │
                        │   ├──► ECS: dashboard (Chainguard image) ◄──┤── Inspector v2
                        │   │         Queries Inspector for BOTH       │
                        │   │         repos and renders dashboard      │
                        │   │                                         │
                        │   └──► ECS: upstream-app (upstream image)   │
                        │                                             │
                        │  ECR:  summit-demo-upstream  ──────────────►│
                        │  ECR:  summit-demo-chainguard ─────────────►│ Inspector v2
                        │                                             │   scans both
                        └─────────────────────────────────────────────┘
```

---

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| AWS CLI | v2 | Configured with appropriate permissions |
| Terraform | ≥ 1.6 | |
| Docker | ≥ 24 | With buildx for multi-platform if needed |
| git | any | |

### Required AWS permissions

The IAM principal running Terraform needs:
- `ecr:*` on the demo repos
- `ecs:*` on the demo cluster
- `iam:*` (for creating task roles)
- `elasticloadbalancing:*`
- `ec2:*` (security groups)
- `inspector2:Enable`, `inspector2:CreateFilter`
- `logs:*` (CloudWatch log groups)

---

## Step-by-step Setup

### 1. Clone and configure

```bash
git clone <this-repo>
cd aws-summit-demo

# Copy and edit the Terraform variables
cp terraform/terraform.tfvars.example terraform/terraform.tfvars
# Edit terraform/terraform.tfvars with your VPC ID, subnet IDs, region
```

### 2. Deploy infrastructure

```bash
cd terraform
terraform init
terraform plan
terraform apply
```

Note the outputs — especially `alb_dns_name` and `ecr_upstream_uri`.

### 3. Build and push images

From the **repo root** (not the terraform directory):

```bash
# Make scripts executable
chmod +x scripts/*.sh

# Build and push both images
./scripts/build-and-push.sh

# Or with explicit options:
AWS_REGION=ap-southeast-2 PROJECT=summit-demo ./scripts/build-and-push.sh
```

This will:
1. Authenticate Docker to ECR
2. Build the upstream image (`python:3.11` base — many CVEs expected)
3. Build the Chainguard image (multi-stage distroless — 0 CVEs expected)
4. Push both to ECR
5. Inspector v2 begins scanning automatically

### 4. Deploy to ECS

```bash
./scripts/deploy.sh
```

This forces a new ECS deployment and waits for the service to stabilise.

### 5. Wait for Inspector scans

Inspector typically completes the initial scan within **5–15 minutes** of an image push.

Check progress:
```bash
./scripts/check-findings.sh
```

Or view in the [Inspector console](https://ap-southeast-2.console.aws.amazon.com/inspector/v2/home?region=ap-southeast-2#/findings/container).

### 6. Open the dashboard

```bash
# Get the ALB URL
terraform -chdir=terraform output alb_dns_name
```

Open the URL in a browser. You should see the live CVE comparison dashboard.

---

## Demo walkthrough (for the booth)

**Suggested 2-minute pitch:**

> "Both containers are running the *same Python web application* on AWS ECS Fargate, right now, behind this load balancer.
>
> The left side uses the official `python:3.11` image from Docker Hub — the default choice for most developers. AWS Inspector has found **[N] vulnerabilities** in it, including **[X] critical** ones.
>
> The right side uses Chainguard's distroless Python image. Inspector found **zero**.
>
> Same app. Same AWS infrastructure. Dramatically different security posture.
>
> Want to see the full CVE list? Scan this QR code on your phone."

**Attendee interaction:** Point them at the QR code. They scan it, see the full CVE list on their phone — something tangible to take away.

---

## Extra wow factors 🌟

### Slide deck talking points
- **Attack surface reduction**: The upstream image ships `bash`, `apt`, `curl`, system libraries your app never uses — each is a potential entry point. Chainguard ships only what Python needs to run.
- **Continuous freshness**: Chainguard rebuilds and re-releases images daily. You get CVE fixes the same day they're published, without changing your Dockerfile.
- **Signed + SBOM**: Every Chainguard image is signed with [Sigstore/cosign](https://sigstore.dev) and ships with a Software Bill of Materials. You can verify the provenance of every package.
- **Smaller = faster**: Smaller images mean faster ECR pulls, faster ECS cold starts, and lower storage costs.

### Verify the Chainguard image signature (live demo option)
```bash
# Install cosign first: brew install cosign
cosign verify cgr.dev/chainguard/python:latest \
  --certificate-identity-regexp=".*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"
```

### Pull SBOM (live demo option)
```bash
cosign download sbom cgr.dev/chainguard/python:latest
```

### Inspector console deep-dive
Show attendees the Inspector console filtered to your repos. The upstream repo will have CVEs with detailed remediation advice; the Chainguard repo will be clean.

---

## Refresh Inspector data

Inspector runs continuously, but you can force a re-evaluation:
```bash
# Via the app's refresh button (top-right of dashboard)

# Or via CLI — re-push the images to trigger a fresh scan
./scripts/build-and-push.sh && ./scripts/deploy.sh
```

---

## Configuration reference

All configuration is passed to ECS tasks as environment variables. To change them, edit `terraform/ecs.tf` or update `terraform.tfvars`:

| Variable | Default | Description |
|----------|---------|-------------|
| `AWS_REGION` | `ap-southeast-2` | AWS region |
| `UPSTREAM_REPO` | `summit-demo-upstream` | ECR repo name for upstream image |
| `CHAINGUARD_REPO` | `summit-demo-chainguard` | ECR repo name for Chainguard image |
| `UPSTREAM_IMAGE_TAG` | `latest` | Tag to query Inspector for |
| `CHAINGUARD_IMAGE_TAG` | `latest` | Tag to query Inspector for |
| `APP_URL` | ALB DNS | Base URL used in QR code generation |
| `CACHE_TTL_SECONDS` | `300` | Inspector API response cache duration |
| `PORT` | `5000` | HTTP port the Flask app listens on |
| `CHAINGUARD_API_TOKEN` | — (SSM secret) | Console API token for the Sentinel near-miss panel |
| `SENTINEL_SINCE_DAYS` | `30` | Lookback window for the ecosystem-wide near-miss list |
| `SENTINEL_APP_SINCE_DAYS` | `90` | Lookback window when matching blocks against this app's installed libraries |
| `SENTINEL_ECOSYSTEM` | `PYPI` | Ecosystem queried on the Sentinel blocklist API |
| `CG_REMEDIATED_INDEX` | `https://libraries.cgr.dev/python-remediated` | Index checked for CVE-remediated `+cgr.N` builds |

---

## Sentinel near misses panel

The dashboard's bottom panel shows **near misses** — packages that Chainguard
Sentinel blocked at the Libraries index (malware, greyware, or cooldown policy)
which your builds would otherwise have pulled from upstream. Three sections:

1. **Libraries this app uses (90 days)** — blocks cross-referenced against the
   app's own installed packages, flagging when the installed version *is* the
   blocked version
2. **CVE-remediated builds for this app's libraries** — every installed
   package checked against the `python-remediated` index; `+cgr.N` builds for
   the exact installed version are highlighted as zero-upgrade drop-in fixes
3. **All PyPI near misses (30 days)** — the ecosystem-wide view

Remediated-index lookups use the same Libraries pull token as the provenance
views; only the blocklist needs the console API token below.

To enable live data:

```bash
# 1. Store a console API token alongside the Libraries credentials
export CG_API_TOKEN="$(chainctl auth token --audience=https://console-api.enforce.dev)"
./scripts/store-cg-credentials.sh

# 2. Enable the panel and redeploy
echo 'enable_sentinel = true' >> terraform/terraform.tfvars
terraform -chdir=terraform apply
```

Without a token the panel renders clearly-labelled demo data, so the layout is
still demoable offline. Note that `chainctl auth token` returns a short-lived
token — refresh the SSM parameter (re-run the script) before a demo session,
then force a new ECS deployment to pick it up.

---

## Troubleshooting

### Inspector shows 0 findings for both repos
- Wait longer — first scan can take up to 30 minutes
- Check Inspector is enabled: AWS console → Inspector → Settings → Account management
- Confirm the image was actually pushed: `aws ecr list-images --repository-name summit-demo-upstream --region ap-southeast-2`
- Run `./scripts/check-findings.sh` to query via CLI

### ECS tasks not starting
- Check CloudWatch Logs: `/ecs/summit-demo` log group
- Common issue: ECS task can't pull from ECR → ensure tasks have public IP (or NAT GW) and the security group allows outbound 443

### Dashboard shows "No AWS credentials found"
- The ECS task role (`summit-demo-ecs-task`) needs Inspector2 permissions
- Verify: `aws iam get-role-policy --role-name summit-demo-ecs-task --policy-name summit-demo-ecs-task-policy`

### QR codes show localhost
- Set `APP_URL` environment variable to the actual ALB DNS name
- In Terraform this is handled automatically; during local dev set it manually:
  `APP_URL=http://your-alb.amazonaws.com python app/app.py`

### Chainguard Libraries build not reflected in the UI
The provenance panel decides between PyPI and Chainguard Libraries mode from
the `PIP_INDEX_URL` the container sees at runtime:
- The Chainguard Dockerfile bakes `ENV PIP_INDEX_URL=http://<nexus>:8081/...`
  into the image, and the ECS task definition must NOT override it with an
  empty value. If you deployed with an older task definition that always set
  `PIP_INDEX_URL`, run `terraform apply` to pick up the fixed definition.
- Verify what the running task actually sees:
  `aws ecs execute-command` isn't enabled here, so check instead with
  `curl http://<alb>/api/provenance | jq .mode` — it should say
  `chainguard_libraries`.
- After rebuilding the image, force a fresh deployment so ECS pulls the new
  digest: `aws ecs update-service --cluster summit-demo --service summit-demo-dashboard --force-new-deployment`

### Chainguard image build fails
- Ensure Docker has access to `cgr.dev` (outbound internet access)
- Chainguard's public images are free — no authentication needed for `latest` tags
- For production/pinned tags, sign up at [chainguard.dev](https://chainguard.dev)

---

## Local development

To run the app locally (without AWS):

```bash
cd app
pip install -r requirements.txt

# The app will use mock data if no AWS credentials are found
python app.py

# With AWS credentials — shows real Inspector data
AWS_REGION=ap-southeast-2 \
UPSTREAM_REPO=summit-demo-upstream \
CHAINGUARD_REPO=summit-demo-chainguard \
APP_URL=http://localhost:5000 \
python app.py
```

---

## Cleanup

```bash
cd terraform
terraform destroy
```

This removes all resources except the CloudWatch log group retention (deleted automatically after 7 days).

---

## Cost estimate (ap-southeast-2)

| Resource | Cost |
|----------|------|
| ECS Fargate (2 × 0.5 vCPU / 1 GB, 8h/day) | ~$0.30/day |
| ALB | ~$0.25/day |
| ECR storage (2 images ~2 GB total) | ~$0.20/month |
| Inspector v2 ECR scanning | ~$0.09/image/month |
| CloudWatch Logs | negligible |
| **Total for a 3-day event** | **~$2–3** |

---

*Built for AWS Summit Sydney · Powered by Chainguard + AWS Inspector v2*
