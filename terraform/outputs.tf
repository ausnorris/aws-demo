output "created_subnet_ids" {
  description = "IDs of the public subnets Terraform created (empty if create_subnets = false)"
  value       = aws_subnet.public[*].id
}

output "alb_dns_name" {
  description = "Public URL of the demo dashboard"
  value       = "http://${aws_lb.main.dns_name}"
}

output "ecr_upstream_uri" {
  description = "ECR URI for the upstream image"
  value       = aws_ecr_repository.upstream.repository_url
}

output "ecr_chainguard_uri" {
  description = "ECR URI for the Chainguard image"
  value       = aws_ecr_repository.chainguard.repository_url
}

output "ecs_cluster_name" {
  description = "ECS cluster name"
  value       = aws_ecs_cluster.main.name
}

output "aws_region" {
  description = "Deployment region"
  value       = var.aws_region
}

output "inspector_console_url" {
  description = "Direct link to Inspector findings for these repos"
  value       = "https://${var.aws_region}.console.aws.amazon.com/inspector/v2/home?region=${var.aws_region}#/findings/container"
}

output "build_and_push_commands" {
  description = "Commands to build and push both images (also in scripts/build-and-push.sh)"
  value = <<-EOT
    # Authenticate Docker to ECR
    aws ecr get-login-password --region ${var.aws_region} | \
      docker login --username AWS --password-stdin ${aws_ecr_repository.upstream.registry_id}.dkr.ecr.${var.aws_region}.amazonaws.com

    # Build & push upstream
    docker build -f Dockerfile.upstream -t ${aws_ecr_repository.upstream.repository_url}:latest .
    docker push ${aws_ecr_repository.upstream.repository_url}:latest

    # Build & push chainguard
    docker build -f Dockerfile.chainguard -t ${aws_ecr_repository.chainguard.repository_url}:latest .
    docker push ${aws_ecr_repository.chainguard.repository_url}:latest
  EOT
}
