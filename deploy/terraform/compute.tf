# ---------------------------------------------------------------------------
# Compute: a launch template describing each app instance, an Auto Scaling
# Group that keeps `asg_desired_capacity` of them healthy across the AZs, and
# an Application Load Balancer in front with a /health check.
# ---------------------------------------------------------------------------

# Latest Amazon Linux 2023 AMI (published by AWS as an SSM public parameter).
data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

resource "aws_launch_template" "app" {
  name_prefix   = "${var.project}-lt-"
  image_id      = data.aws_ssm_parameter.al2023.value
  instance_type = var.instance_type

  iam_instance_profile {
    name = aws_iam_instance_profile.ec2.name
  }

  vpc_security_group_ids = [aws_security_group.ec2.id]

  # Require IMDSv2 (defends the instance metadata endpoint against SSRF).
  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  user_data = base64encode(templatefile("${path.module}/user_data.sh", {
    region    = var.region
    app_port  = var.app_port
    s3_bucket = aws_s3_bucket.app.id
    ssm_prefix = var.ssm_param_prefix
    log_group = aws_cloudwatch_log_group.app.name
  }))

  tag_specifications {
    resource_type = "instance"
    tags          = { Name = "${var.project}-app" }
  }
}

resource "aws_lb" "app" {
  name               = "${var.project}-alb"
  load_balancer_type = "application"
  internal           = false
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id

  tags = { Name = "${var.project}-alb" }
}

resource "aws_lb_target_group" "app" {
  name     = "${var.project}-tg"
  port     = var.app_port
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check {
    path                = "/health"
    matcher             = "200"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  tags = { Name = "${var.project}-tg" }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.app.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

resource "aws_autoscaling_group" "app" {
  name                      = "${var.project}-asg"
  vpc_zone_identifier       = aws_subnet.public[*].id
  desired_capacity          = var.asg_desired_capacity
  min_size                  = var.asg_desired_capacity
  max_size                  = var.asg_desired_capacity + 2
  target_group_arns         = [aws_lb_target_group.app.arn]
  health_check_type         = "ELB" # replace an instance the ALB marks unhealthy
  health_check_grace_period = 300

  launch_template {
    id      = aws_launch_template.app.id
    version = "$Latest"
  }

  # Make sure the app bundle is in S3 before instances boot and try to pull it.
  depends_on = [aws_s3_object.app_bundle]

  tag {
    key                 = "Name"
    value               = "${var.project}-app"
    propagate_at_launch = true
  }
}
