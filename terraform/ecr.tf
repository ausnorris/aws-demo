# ── ECR Repositories ─────────────────────────────────────────────────────────

resource "aws_ecr_repository" "upstream" {
  name                 = local.upstream_repo_name
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    # Basic scanning is free; Inspector v2 does enhanced scanning
    scan_on_push = false
  }

  encryption_configuration {
    encryption_type = "AES256"
  }
}

resource "aws_ecr_repository" "chainguard" {
  name                 = local.chainguard_repo_name
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = false
  }

  encryption_configuration {
    encryption_type = "AES256"
  }
}

# ── Lifecycle policies — keep last 5 tagged images ────────────────────────────
resource "aws_ecr_lifecycle_policy" "upstream" {
  repository = aws_ecr_repository.upstream.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep last 5 tagged images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 5
      }
      action = { type = "expire" }
    }]
  })
}

resource "aws_ecr_lifecycle_policy" "chainguard" {
  repository = aws_ecr_repository.chainguard.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep last 5 tagged images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 5
      }
      action = { type = "expire" }
    }]
  })
}
