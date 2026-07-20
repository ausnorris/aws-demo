variable "aws_region" {
  description = "AWS region to deploy into (Sydney = ap-southeast-2)"
  type        = string
  default     = "ap-southeast-2"
}

variable "vpc_id" {
  description = "ID of your existing VPC (e.g. vpc-0abc1234)"
  type        = string
}

# ── Subnet mode ───────────────────────────────────────────────────────────────

variable "create_subnets" {
  description = <<-EOT
    true  = Terraform creates new public subnets inside your VPC using new_subnet_cidrs.
            Your VPC must already have an Internet Gateway attached.
    false = You supply existing subnet IDs via public_subnet_ids / ecs_subnet_ids.
  EOT
  type    = bool
  default = true
}

variable "subnet_offset" {
  description = "Offset for auto-computed subnet CIDRs when create_subnets = true. Increase if the default addresses (offset 200, 201) already exist in your VPC."
  type        = number
  default     = 200
}

variable "public_subnet_ids" {
  description = "Existing public subnet IDs for the ALB (min 2, different AZs). Only used when create_subnets = false."
  type        = list(string)
  default     = []
}

variable "ecs_subnet_ids" {
  description = "Existing subnet IDs for ECS Fargate tasks. Only used when create_subnets = false."
  type        = list(string)
  default     = []
}

# ── Project ───────────────────────────────────────────────────────────────────

variable "project" {
  description = "Short name prefix used for all resource names"
  type        = string
  default     = "summit-demo"
}

# ── Image tags ────────────────────────────────────────────────────────────────

variable "upstream_image_tag" {
  description = "Docker image tag for the upstream image in ECR"
  type        = string
  default     = "latest"
}

variable "chainguard_image_tag" {
  description = "Docker image tag for the Chainguard image in ECR"
  type        = string
  default     = "latest"
}

variable "upstream_image_label" {
  description = "Display name shown on the dashboard for the upstream image"
  type        = string
  default     = "python:3.13"
}

variable "chainguard_image_label" {
  description = "Display name shown on the dashboard for the Chainguard image"
  type        = string
  default     = "python:3.13"
}

# ── ECS sizing ────────────────────────────────────────────────────────────────

variable "app_cpu" {
  description = "Fargate task CPU units (256 = 0.25 vCPU, 512 = 0.5 vCPU)"
  type        = number
  default     = 512
}

variable "app_memory" {
  description = "Fargate task memory in MiB"
  type        = number
  default     = 1024
}

variable "ecs_task_desired_count" {
  description = "Number of running ECS tasks for the dashboard service"
  type        = number
  default     = 1
}

variable "ecs_tasks_use_public_subnet" {
  description = "Assign a public IP to ECS tasks so they can pull from ECR without a NAT Gateway. Set false only if using private subnets with a NAT GW."
  type        = bool
  default     = true
}

# ── App behaviour ─────────────────────────────────────────────────────────────

variable "cache_ttl_seconds" {
  description = "How long (seconds) the app caches Inspector findings before re-fetching"
  type        = number
  default     = 300
}

# ── Inspector ─────────────────────────────────────────────────────────────────

variable "enable_inspector" {
  description = "Enable AWS Inspector v2 for ECR scanning in this account. Set false if it is already enabled."
  type        = bool
  default     = true
}

# ── Chainguard Nexus library index ────────────────────────────────────────────

variable "nexus_host" {
  description = <<-EOT
    Hostname or IP of the Nexus server serving Chainguard Python packages.
    Leave empty (default) to let the app auto-detect the index from the
    PIP_INDEX_URL that was baked into the image at build time — the normal
    case when the Dockerfile already sets NEXUS_HOST/PIP_INDEX_URL.
    Set it only to force-override the runtime index detection.
  EOT
  type    = string
  default = ""
}

variable "nexus_repo" {
  description = "Nexus repository name for the Chainguard Python package group."
  type        = string
  default     = "python-group"
}

# ── Chainguard Libraries credentials ─────────────────────────────────────────
# Credentials are stored in SSM Parameter Store as SecureStrings by running
# scripts/store-cg-credentials.sh before the first terraform apply.
# Terraform reads them by path at deploy time; values never appear in state.

# ── Chainguard Sentinel near misses ──────────────────────────────────────────

variable "enable_sentinel" {
  description = <<-EOT
    Enable the "Near Misses" dashboard panel backed by the Chainguard Sentinel
    malware blocklist API. Requires a console API token stored in SSM at
    <prefix>/cg-api-token (run scripts/store-cg-credentials.sh with
    CG_API_TOKEN set). When false, the panel shows clearly-labelled demo data.
  EOT
  type    = bool
  default = false
}

variable "sentinel_since_days" {
  description = "How many days back the Sentinel near-miss panel looks for blocked packages"
  type        = number
  default     = 30
}

variable "cg_libraries_ssm_prefix" {
  description = <<-EOT
    SSM parameter path prefix for Chainguard Libraries credentials.
    Parameters are created at:
      <prefix>/cg-libraries-user
      <prefix>/cg-libraries-token
    Defaults to /<project> when left empty.
  EOT
  type    = string
  default = ""
}
