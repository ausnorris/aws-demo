terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project
      Environment = "demo"
      ManagedBy   = "terraform"
      Event       = "AWS Summit Sydney"
    }
  }
}

# ── Data sources ──────────────────────────────────────────────────────────────
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "aws_vpc" "selected" {
  id = var.vpc_id
}

# ── Resolved subnet IDs ───────────────────────────────────────────────────────
# When create_subnets = true  → use the subnets Terraform just created
# When create_subnets = false → use the IDs supplied by the operator
locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
  ecr_base   = "${local.account_id}.dkr.ecr.${local.region}.amazonaws.com"

  upstream_repo_name   = "${var.project}-upstream"
  chainguard_repo_name = "${var.project}-chainguard"
  upstream_image_uri   = "${local.ecr_base}/${local.upstream_repo_name}:${var.upstream_image_tag}"
  chainguard_image_uri = "${local.ecr_base}/${local.chainguard_repo_name}:${var.chainguard_image_tag}"

  # Subnets — resolved depending on create_subnets flag
  alb_subnet_ids          = var.create_subnets ? aws_subnet.public[*].id : var.public_subnet_ids
  ecs_subnet_ids_resolved = var.create_subnets ? aws_subnet.public[*].id : var.ecs_subnet_ids

  # SSM path prefix for Chainguard credentials
  ssm_prefix = var.cg_libraries_ssm_prefix != "" ? var.cg_libraries_ssm_prefix : "/${var.project}"
}

# ── Input validation ──────────────────────────────────────────────────────────
locals {
  # Fail fast if the operator forgot to set subnet IDs when not creating them
  _validate_subnets = (
    var.create_subnets == false &&
    (length(var.public_subnet_ids) < 2 || length(var.ecs_subnet_ids) == 0)
  ) ? tobool("When create_subnets = false you must provide at least 2 public_subnet_ids and at least 1 ecs_subnet_id.") : true
}
