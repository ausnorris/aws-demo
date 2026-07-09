# ── ECS Task Execution Role ───────────────────────────────────────────────────
# Used by the ECS agent to pull images from ECR and send logs to CloudWatch.

resource "aws_iam_role" "ecs_execution" {
  name = "${var.project}-ecs-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_execution_policy" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Allow the execution role to read the Chainguard credentials from SSM so ECS
# can inject them as secrets into the task. The task role never sees them.
resource "aws_iam_policy" "ecs_execution_ssm" {
  name        = "${var.project}-ecs-execution-ssm"
  description = "Allow ECS execution role to read Chainguard library credentials from SSM"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "ReadCGLibrariesCredentials"
      Effect = "Allow"
      Action = [
        "ssm:GetParameters",
        "ssm:GetParameter",
      ]
      Resource = [
        "arn:aws:ssm:${var.aws_region}:${local.account_id}:parameter${local.ssm_prefix}/cg-libraries-user",
        "arn:aws:ssm:${var.aws_region}:${local.account_id}:parameter${local.ssm_prefix}/cg-libraries-token",
      ]
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_execution_ssm" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = aws_iam_policy.ecs_execution_ssm.arn
}

# ── ECS Task Role ─────────────────────────────────────────────────────────────
# Used by the running container. Needs:
#  - Inspector2: list and read findings
#  - ECR: describe images (for size info)

resource "aws_iam_role" "ecs_task" {
  name = "${var.project}-ecs-task"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "ecs_task_policy" {
  name        = "${var.project}-ecs-task-policy"
  description = "Allow the demo app to read Inspector findings and ECR image metadata"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "InspectorReadFindings"
        Effect = "Allow"
        Action = [
          "inspector2:ListFindings",
          "inspector2:GetFindingsReportStatus",
          "inspector2:ListCoverage",
        ]
        Resource = "*"
      },
      {
        Sid    = "ECRDescribeImages"
        Effect = "Allow"
        Action = [
          "ecr:DescribeImages",
          "ecr:GetRepositoryPolicy",
          "ecr:ListImages",
        ]
        Resource = [
          aws_ecr_repository.upstream.arn,
          aws_ecr_repository.chainguard.arn,
        ]
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "${aws_cloudwatch_log_group.app.arn}:*"
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_task_policy" {
  role       = aws_iam_role.ecs_task.name
  policy_arn = aws_iam_policy.ecs_task_policy.arn
}

# ── CloudWatch Log Group ──────────────────────────────────────────────────────
resource "aws_cloudwatch_log_group" "app" {
  name              = "/ecs/${var.project}"
  retention_in_days = 7
}
