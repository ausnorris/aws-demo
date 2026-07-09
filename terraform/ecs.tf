# ── ECS Cluster ───────────────────────────────────────────────────────────────

resource "aws_ecs_cluster" "main" {
  name = var.project

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_ecs_cluster_capacity_providers" "fargate" {
  cluster_name       = aws_ecs_cluster.main.name
  capacity_providers = ["FARGATE", "FARGATE_SPOT"]

  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
    base              = 1
  }
}

# ── Dashboard Task Definition (Chainguard image) ──────────────────────────────
# The dashboard runs the Chainguard-based image and queries Inspector for data
# about BOTH images.

resource "aws_ecs_task_definition" "dashboard" {
  family                   = "${var.project}-dashboard"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = tostring(var.app_cpu)
  memory                   = tostring(var.app_memory)
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([
    {
      name      = "dashboard"
      image     = local.chainguard_image_uri
      essential = true

      portMappings = [{
        containerPort = 5000
        protocol      = "tcp"
      }]

      environment = [
        { name = "AWS_REGION",             value = var.aws_region },
        { name = "UPSTREAM_REPO",          value = local.upstream_repo_name },
        { name = "CHAINGUARD_REPO",        value = local.chainguard_repo_name },
        { name = "UPSTREAM_IMAGE_TAG",     value = var.upstream_image_tag },
        { name = "CHAINGUARD_IMAGE_TAG",   value = var.chainguard_image_tag },
        { name = "UPSTREAM_IMAGE_LABEL",   value = var.upstream_image_label },
        { name = "CHAINGUARD_IMAGE_LABEL", value = var.chainguard_image_label },
        { name = "APP_URL",                value = "http://${aws_lb.main.dns_name}" },
        { name = "CACHE_TTL_SECONDS",      value = tostring(var.cache_ttl_seconds) },
        { name = "PORT",                   value = "5000" },
        # Nexus/Chainguard index — empty string means standard PyPI was used.
        # Set nexus_host in tfvars when deploying the Chainguard-libraries build.
        { name = "NEXUS_HOST",             value = var.nexus_host },
        { name = "PIP_INDEX_URL",          value = var.nexus_host != "" ? "http://${var.nexus_host}:8081/repository/${var.nexus_repo}/simple/" : "" },
      ]

      # Chainguard Libraries credentials — injected from SSM SecureString.
      # Values are never stored in Terraform state as plaintext.
      secrets = [
        {
          name      = "CG_LIBRARIES_USER"
          valueFrom = "arn:aws:ssm:${var.aws_region}:${local.account_id}:parameter${local.ssm_prefix}/cg-libraries-user"
        },
        {
          name      = "CG_LIBRARIES_TOKEN"
          valueFrom = "arn:aws:ssm:${var.aws_region}:${local.account_id}:parameter${local.ssm_prefix}/cg-libraries-token"
        },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.app.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "dashboard"
        }
      }

      healthCheck = {
        command     = ["CMD-SHELL", "python -c \"import urllib.request; urllib.request.urlopen('http://localhost:5000/health')\" || exit 1"]
        interval    = 30
        timeout     = 10
        retries     = 3
        startPeriod = 30
      }
    }
  ])
}

# ── Dashboard ECS Service ─────────────────────────────────────────────────────

resource "aws_ecs_service" "dashboard" {
  name            = "${var.project}-dashboard"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.dashboard.arn
  desired_count   = var.ecs_task_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = local.ecs_subnet_ids_resolved
    security_groups  = [aws_security_group.ecs_tasks.id]
    assign_public_ip = var.ecs_tasks_use_public_subnet
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.app.arn
    container_name   = "dashboard"
    container_port   = 5000
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  deployment_controller {
    type = "ECS"
  }

  # Allow Terraform to manage desired_count externally (e.g. scaling)
  lifecycle {
    ignore_changes = [desired_count]
  }

  depends_on = [
    aws_lb_listener.http,
    aws_iam_role_policy_attachment.ecs_task_policy,
    aws_iam_role_policy_attachment.ecs_execution_policy,
  ]
}

# ── "Vulnerable" upstream service (optional — shows upstream image also running) ─
# Deploy the same app code on the upstream image so visitors can see BOTH are
# live services and the comparison is real.

resource "aws_lb_target_group" "upstream_app" {
  name        = "${var.project}-upstream-tg"
  port        = 5000
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    enabled             = true
    path                = "/health"
    port                = "traffic-port"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 30
    timeout             = 10
    matcher             = "200"
  }
  deregistration_delay = 30
}

resource "aws_lb_listener_rule" "upstream_path" {
  listener_arn = aws_lb_listener.http.arn
  priority     = 10

  condition {
    path_pattern { values = ["/upstream/*", "/upstream"] }
  }

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.upstream_app.arn
  }
}

resource "aws_ecs_task_definition" "upstream_app" {
  family                   = "${var.project}-upstream"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = tostring(var.app_cpu)
  memory                   = tostring(var.app_memory)
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([
    {
      name      = "upstream-app"
      image     = local.upstream_image_uri
      essential = true

      portMappings = [{ containerPort = 5000, protocol = "tcp" }]

      environment = [
        { name = "AWS_REGION",           value = var.aws_region },
        { name = "UPSTREAM_REPO",        value = local.upstream_repo_name },
        { name = "CHAINGUARD_REPO",      value = local.chainguard_repo_name },
        { name = "UPSTREAM_IMAGE_TAG",   value = var.upstream_image_tag },
        { name = "CHAINGUARD_IMAGE_TAG", value = var.chainguard_image_tag },
        { name = "APP_URL",              value = "http://${aws_lb.main.dns_name}" },
        { name = "CACHE_TTL_SECONDS",    value = tostring(var.cache_ttl_seconds) },
        { name = "PORT",                 value = "5000" },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.app.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "upstream"
        }
      }
    }
  ])
}

resource "aws_ecs_service" "upstream_app" {
  name            = "${var.project}-upstream"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.upstream_app.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = local.ecs_subnet_ids_resolved
    security_groups  = [aws_security_group.ecs_tasks.id]
    assign_public_ip = var.ecs_tasks_use_public_subnet
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.upstream_app.arn
    container_name   = "upstream-app"
    container_port   = 5000
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  lifecycle {
    ignore_changes = [desired_count]
  }

  depends_on = [
    aws_lb_listener.http,
    aws_lb_listener_rule.upstream_path,
  ]
}
