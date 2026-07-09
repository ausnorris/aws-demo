# ── AWS Inspector v2 ─────────────────────────────────────────────────────────
#
# Enables enhanced ECR scanning for this AWS account.
# Inspector v2 automatically scans images when they are pushed to ECR
# and continuously re-evaluates as new CVE data becomes available.
#
# If Inspector is already enabled in your account, set:
#   enable_inspector = false
# in your terraform.tfvars to skip this resource.

resource "aws_inspector2_enabler" "ecr" {
  count = var.enable_inspector ? 1 : 0

  account_ids    = [local.account_id]
  resource_types = ["ECR"]
}

# ── Inspector findings filter for the demo repos ──────────────────────────────
# This creates a named filter you can use in the Inspector console to quickly
# jump to just the demo-related findings.
resource "aws_inspector2_filter" "upstream_demo" {
  name   = "${var.project}-upstream-findings"
  action = "NONE"  # "NONE" = informational filter, not a suppression rule

  filter_criteria {
    ecr_image_repository_name {
      comparison = "EQUALS"
      value      = local.upstream_repo_name
    }
  }

  depends_on = [aws_inspector2_enabler.ecr]
}

resource "aws_inspector2_filter" "chainguard_demo" {
  name   = "${var.project}-chainguard-findings"
  action = "NONE"

  filter_criteria {
    ecr_image_repository_name {
      comparison = "EQUALS"
      value      = local.chainguard_repo_name
    }
  }

  depends_on = [aws_inspector2_enabler.ecr]
}
