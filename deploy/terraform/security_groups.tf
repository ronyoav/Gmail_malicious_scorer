# ---------------------------------------------------------------------------
# Security groups — the firewall rules between tiers.
#   internet -> ALB (80)        ALB -> EC2 (app_port)
#   EC2 -> RDS (5432)           EC2 -> Redis (6379)
# EC2 have NO inbound SSH (port 22). Admin access is via SSM Session Manager,
# which needs no inbound port at all.
# ---------------------------------------------------------------------------

resource "aws_security_group" "alb" {
  name        = "${var.project}-alb-sg"
  description = "Public HTTP in to the load balancer"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTP from anywhere"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Forward to app instances"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project}-alb-sg" }
}

resource "aws_security_group" "ec2" {
  name        = "${var.project}-ec2-sg"
  description = "App instances: inbound only from the ALB"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "App traffic from the ALB only"
    from_port       = var.app_port
    to_port         = var.app_port
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  # Outbound open: package installs, SSM, and the Claude / VirusTotal APIs.
  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project}-ec2-sg" }
}

resource "aws_security_group" "rds" {
  name        = "${var.project}-rds-sg"
  description = "Postgres: inbound only from the app instances"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Postgres from app instances"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.ec2.id]
  }

  tags = { Name = "${var.project}-rds-sg" }
}

resource "aws_security_group" "redis" {
  name        = "${var.project}-redis-sg"
  description = "Redis: inbound only from the app instances"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Redis from app instances"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.ec2.id]
  }

  tags = { Name = "${var.project}-redis-sg" }
}
