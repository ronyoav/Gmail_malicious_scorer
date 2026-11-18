# ---------------------------------------------------------------------------
# Observability (the core of this assignment). CloudWatch gives us:
#   - EC2 health            -> ALB target health + ASG
#   - CPU / memory          -> AWS/EC2 CPUUtilization + CloudWatch agent (mem)
#   - requests at the LB     -> AWS/ApplicationELB RequestCount
#   - success vs failure     -> HTTPCode_Target_2XX/4XX/5XX
#   - where logs live        -> this log group (streamed by the CloudWatch agent)
#   - app-level errors       -> log metric filter (ERROR/Exception/Traceback) + alarm
# Plus one dashboard and five alarms.
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "app" {
  name              = "/${var.project}/app"
  retention_in_days = 7
}

# SNS topic that every alarm publishes to. When alert_email is set, an email
# subscription is created (AWS sends a confirmation link that must be clicked).
# The email is passed at apply time, never committed.
resource "aws_sns_topic" "alerts" {
  name = "${var.project}-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "${var.project}-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Average CPU over 80% across the app instances."
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  dimensions          = { AutoScalingGroupName = aws_autoscaling_group.app.name }
}

resource "aws_cloudwatch_metric_alarm" "unhealthy_hosts" {
  alarm_name          = "${var.project}-unhealthy-hosts"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "UnHealthyHostCount"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Maximum"
  threshold           = 1
  alarm_description   = "At least one target is failing its health check."
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  dimensions = {
    TargetGroup  = aws_lb_target_group.app.arn_suffix
    LoadBalancer = aws_lb.app.arn_suffix
  }
}

resource "aws_cloudwatch_metric_alarm" "target_5xx" {
  alarm_name          = "${var.project}-target-5xx"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "HTTPCode_Target_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Sum"
  threshold           = 5
  alarm_description   = "App instances returning 5xx errors."
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  dimensions          = { LoadBalancer = aws_lb.app.arn_suffix }
}

resource "aws_cloudwatch_metric_alarm" "high_latency" {
  alarm_name          = "${var.project}-high-latency"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "TargetResponseTime"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Average"
  threshold           = 2
  unit                = "Seconds"
  alarm_description   = "App responses slower than 2s on average (application latency)."
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  dimensions          = { LoadBalancer = aws_lb.app.arn_suffix }
}

# Application-level errors, straight from the logs. HTTP 5xx only catches failures
# that reach the ALB as a 5xx; this catches ERROR / Exception / Traceback lines the
# app writes (e.g. a background DB insert failing, an analyzer raising) even when the
# request itself returned 200. The CloudWatch agent streams stdout/stderr into the
# app log group, so these lines are already there.
resource "aws_cloudwatch_log_metric_filter" "app_errors" {
  name           = "${var.project}-app-errors"
  log_group_name = aws_cloudwatch_log_group.app.name
  pattern        = "?ERROR ?Exception ?Traceback" # OR-match any of these terms

  metric_transformation {
    name          = "AppErrorCount"
    namespace     = "PhishingScorer" # same custom namespace as the agent's mem metric
    value         = "1"
    default_value = 0
  }
}

resource "aws_cloudwatch_metric_alarm" "app_errors" {
  alarm_name          = "${var.project}-app-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "AppErrorCount"
  namespace           = "PhishingScorer"
  period              = 60
  statistic           = "Sum"
  threshold           = 0 # any error line in a 60s window alerts; raise if too noisy
  alarm_description   = "Application-level errors in the logs (ERROR/Exception/Traceback), not just HTTP 5xx."
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}

# Root volume filling up (e.g. /var/log/app/app.log grows unbounded — no logrotate).
# disk_used_percent is a per-instance metric (InstanceId/device/fstype/path dimensions),
# and instances come and go in the ASG, so a fixed-dimension alarm would go stale. Instead
# a metric-math SEARCH gathers disk_used_percent across every instance and MAX() collapses
# it to one series — the alarm fires if ANY instance's root volume crosses the threshold.
resource "aws_cloudwatch_metric_alarm" "high_disk" {
  alarm_name          = "${var.project}-high-disk"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  threshold           = 85
  alarm_description   = "Root volume over 85% full on at least one app instance."
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]

  metric_query {
    id          = "max_disk"
    label       = "Max disk used % across instances"
    return_data = true
    expression  = "MAX(SEARCH('Namespace=\"PhishingScorer\" MetricName=\"disk_used_percent\"', 'Average', 60))"
  }
}

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "${var.project}-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric", x = 0, y = 0, width = 12, height = 6,
        properties = {
          title  = "ALB requests & errors",
          region = var.region,
          view   = "timeSeries",
          metrics = [
            ["AWS/ApplicationELB", "RequestCount", "LoadBalancer", aws_lb.app.arn_suffix, { stat = "Sum" }],
            [".", "HTTPCode_Target_2XX_Count", ".", ".", { stat = "Sum" }],
            [".", "HTTPCode_Target_4XX_Count", ".", ".", { stat = "Sum" }],
            [".", "HTTPCode_Target_5XX_Count", ".", ".", { stat = "Sum" }]
          ]
        }
      },
      {
        type = "metric", x = 12, y = 0, width = 12, height = 6,
        properties = {
          title  = "Target health & latency",
          region = var.region,
          view   = "timeSeries",
          metrics = [
            ["AWS/ApplicationELB", "HealthyHostCount", "TargetGroup", aws_lb_target_group.app.arn_suffix, "LoadBalancer", aws_lb.app.arn_suffix, { stat = "Average" }],
            [".", "UnHealthyHostCount", ".", ".", ".", ".", { stat = "Average" }],
            ["AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", aws_lb.app.arn_suffix, { stat = "Average" }]
          ]
        }
      },
      {
        type = "metric", x = 0, y = 6, width = 12, height = 6,
        properties = {
          title  = "EC2 CPU (ASG)",
          region = var.region,
          view   = "timeSeries",
          metrics = [
            ["AWS/EC2", "CPUUtilization", "AutoScalingGroupName", aws_autoscaling_group.app.name, { stat = "Average" }]
          ]
        }
      },
      {
        type = "metric", x = 12, y = 6, width = 12, height = 6,
        properties = {
          title  = "Memory & disk used % (CloudWatch agent)",
          region = var.region,
          view   = "timeSeries",
          metrics = [
            ["PhishingScorer", "mem_used_percent", { stat = "Average", label = "memory" }],
            [".", "disk_used_percent", { stat = "Average", label = "disk /" }]
          ]
        }
      },
      {
        type = "metric", x = 0, y = 12, width = 24, height = 4,
        properties = {
          title  = "App-level errors (logs)",
          region = var.region,
          view   = "timeSeries",
          metrics = [
            ["PhishingScorer", "AppErrorCount", { stat = "Sum", label = "ERROR / Exception / Traceback" }]
          ]
        }
      },
      {
        type = "log", x = 0, y = 16, width = 24, height = 6,
        properties = {
          title  = "Application logs",
          region = var.region,
          query  = "SOURCE '${aws_cloudwatch_log_group.app.name}' | fields @timestamp, @message | sort @timestamp desc | limit 50"
        }
      }
    ]
  })
}
