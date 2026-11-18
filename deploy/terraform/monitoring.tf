# ---------------------------------------------------------------------------
# Observability (the core of this assignment). CloudWatch gives us:
#   - EC2 health            -> ALB target health + ASG
#   - CPU / memory          -> AWS/EC2 CPUUtilization + CloudWatch agent (mem)
#   - requests at the LB     -> AWS/ApplicationELB RequestCount
#   - success vs failure     -> HTTPCode_Target_2XX/4XX/5XX
#   - where logs live        -> this log group (streamed by the CloudWatch agent)
#   - app-level errors       -> log metric filter (ERROR/Exception/Traceback) + alarm
# Plus one dashboard and alarms across the compute, data (RDS/Redis) and log tiers.
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
  treat_missing_data  = "missing" # CPU is emitted continuously; a gap just holds the last state
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
  treat_missing_data  = "notBreaching" # no data (e.g. no targets registered yet) shouldn't page; low_healthy_hosts covers a true outage
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  dimensions = {
    TargetGroup  = aws_lb_target_group.app.arn_suffix
    LoadBalancer = aws_lb.app.arn_suffix
  }
}

# 5xx ERROR RATE, not an absolute count. "5 errors/min" is meaningless without
# volume — noise at 10 req/s, a major incident at 10k req/s. Metric math divides
# target 5xx by total requests; evaluating over 2 periods stops a single error at
# near-zero traffic from tripping the rate. No requests -> no datapoint -> no alarm.
resource "aws_cloudwatch_metric_alarm" "target_5xx_rate" {
  alarm_name          = "${var.project}-target-5xx-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  threshold           = 5 # percent of requests
  alarm_description   = "App 5xx error rate over 5% of requests."
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]

  metric_query {
    id          = "rate"
    expression  = "100 * errors / requests"
    label       = "5xx error rate %"
    return_data = true
  }
  metric_query {
    id = "errors"
    metric {
      metric_name = "HTTPCode_Target_5XX_Count"
      namespace   = "AWS/ApplicationELB"
      period      = 60
      stat        = "Sum"
      dimensions  = { LoadBalancer = aws_lb.app.arn_suffix }
    }
  }
  metric_query {
    id = "requests"
    metric {
      metric_name = "RequestCount"
      namespace   = "AWS/ApplicationELB"
      period      = 60
      stat        = "Sum"
      dimensions  = { LoadBalancer = aws_lb.app.arn_suffix }
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "high_latency" {
  alarm_name          = "${var.project}-high-latency"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "TargetResponseTime"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  extended_statistic  = "p99" # percentile, not Average: the mean hides the slow tail
  threshold           = 2
  unit                = "Seconds"
  alarm_description   = "p99 response time over 2s — slowest 1% of requests breach the latency SLO."
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  dimensions          = { LoadBalancer = aws_lb.app.arn_suffix }
}

# ELB-generated 5xx (not the target's). This fires when the request never reached
# a healthy target — e.g. 503 when the target group is empty, or 502 on a bad/
# dropped upstream response. target_5xx stays 0 in that case, so this is the alarm
# that catches a full infrastructure failure the app logs would never show.
resource "aws_cloudwatch_metric_alarm" "elb_5xx" {
  alarm_name          = "${var.project}-elb-5xx"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "HTTPCode_ELB_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Sum"
  threshold           = 5
  alarm_description   = "ALB itself returning 5xx (502/503/504) — requests not reaching a healthy target."
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  dimensions          = { LoadBalancer = aws_lb.app.arn_suffix }
}

# Capacity safety net. unhealthy_hosts catches a target that FAILS its health
# check, but a cleanly terminated / deregistered instance just makes Healthy-
# HostCount drop while UnHealthyHostCount stays 0. This fires when fewer than the
# desired number of targets are healthy. treat_missing_data=breaching: if the
# metric disappears entirely, that is itself an outage.
resource "aws_cloudwatch_metric_alarm" "low_healthy_hosts" {
  alarm_name          = "${var.project}-low-healthy-hosts"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "HealthyHostCount"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Minimum"
  threshold           = var.asg_desired_capacity
  alarm_description   = "Fewer than ${var.asg_desired_capacity} healthy targets — lost capacity."
  treat_missing_data  = "breaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  dimensions = {
    TargetGroup  = aws_lb_target_group.app.arn_suffix
    LoadBalancer = aws_lb.app.arn_suffix
  }
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
  threshold           = 5 # more than 5 error lines in a 60s window; a single stray line shouldn't page
  alarm_description   = "More than 5 application-level errors/min in the logs (ERROR/Exception/Traceback), not just HTTP 5xx."
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
    period      = 60 # SEARCH-based math has no raw metric to derive the period from
    expression  = "MAX(SEARCH('Namespace=\"PhishingScorer\" MetricName=\"disk_used_percent\"', 'Average', 60))"
  }
}

# ---------------------------------------------------------------------------
# Data-tier alarms (RDS Postgres + ElastiCache Redis). The app depends on both,
# but neither was covered before — a saturated DB or an evicting cache degrades
# the service without ever surfacing as an ALB 5xx.
# ---------------------------------------------------------------------------

# --- RDS Postgres ---------------------------------------------------------
resource "aws_cloudwatch_metric_alarm" "rds_cpu" {
  alarm_name          = "${var.project}-rds-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 60
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "RDS CPU over 80% — queries are saturating the DB."
  treat_missing_data  = "missing"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  dimensions          = { DBInstanceIdentifier = aws_db_instance.main.identifier }
}

# FreeStorageSpace is in BYTES. Storage is 20 GB; alert when under ~2 GB (10%).
resource "aws_cloudwatch_metric_alarm" "rds_free_storage" {
  alarm_name          = "${var.project}-rds-free-storage"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "FreeStorageSpace"
  namespace           = "AWS/RDS"
  period              = 60
  statistic           = "Minimum"
  threshold           = 2 * 1024 * 1024 * 1024 # 2 GiB in bytes
  alarm_description   = "RDS free storage under 2 GB — disk is filling up."
  treat_missing_data  = "missing"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  dimensions          = { DBInstanceIdentifier = aws_db_instance.main.identifier }
}

# FreeableMemory is in BYTES. Low freeable memory -> swapping -> query latency.
resource "aws_cloudwatch_metric_alarm" "rds_low_memory" {
  alarm_name          = "${var.project}-rds-low-memory"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "FreeableMemory"
  namespace           = "AWS/RDS"
  period              = 60
  statistic           = "Average"
  threshold           = 256 * 1024 * 1024 # 256 MiB in bytes
  alarm_description   = "RDS freeable memory under 256 MB — risk of swapping."
  treat_missing_data  = "missing"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  dimensions          = { DBInstanceIdentifier = aws_db_instance.main.identifier }
}

# --- ElastiCache Redis ----------------------------------------------------
# Redis runs commands on a SINGLE thread, so host CPUUtilization (spread over
# all vCPUs) can look idle while the engine thread is maxed. EngineCPUUtilization
# measures that one thread — the real Redis bottleneck.
resource "aws_cloudwatch_metric_alarm" "redis_cpu" {
  alarm_name          = "${var.project}-redis-engine-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "EngineCPUUtilization"
  namespace           = "AWS/ElastiCache"
  period              = 60
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Redis engine thread over 80% CPU."
  treat_missing_data  = "missing"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  dimensions          = { CacheClusterId = aws_elasticache_cluster.main.cluster_id }
}

resource "aws_cloudwatch_metric_alarm" "redis_memory" {
  alarm_name          = "${var.project}-redis-memory"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "DatabaseMemoryUsagePercentage"
  namespace           = "AWS/ElastiCache"
  period              = 60
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Redis memory over 80% of maxmemory — evictions imminent."
  treat_missing_data  = "missing"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  dimensions          = { CacheClusterId = aws_elasticache_cluster.main.cluster_id }
}

# Evictions = keys dropped because Redis hit maxmemory. A few may be normal, so
# alert only on a sustained burst (>100/min for 3 min), not the first eviction.
resource "aws_cloudwatch_metric_alarm" "redis_evictions" {
  alarm_name          = "${var.project}-redis-evictions"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "Evictions"
  namespace           = "AWS/ElastiCache"
  period              = 60
  statistic           = "Sum"
  threshold           = 100
  alarm_description   = "Redis evicting keys (>100/min for 3 min) — cache undersized."
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  dimensions          = { CacheClusterId = aws_elasticache_cluster.main.cluster_id }
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
            [".", "HTTPCode_Target_5XX_Count", ".", ".", { stat = "Sum" }],
            [".", "HTTPCode_ELB_5XX_Count", ".", ".", { stat = "Sum", label = "ELB 5XX (infra)" }]
          ]
        }
      },
      {
        type = "metric", x = 12, y = 0, width = 12, height = 6,
        properties = {
          title  = "Target health & latency",
          region = var.region,
          view   = "timeSeries",
          yAxis  = { left = { label = "hosts", min = 0 }, right = { label = "seconds", min = 0 } },
          metrics = [
            ["AWS/ApplicationELB", "HealthyHostCount", "TargetGroup", aws_lb_target_group.app.arn_suffix, "LoadBalancer", aws_lb.app.arn_suffix, { stat = "Average", label = "healthy hosts" }],
            [".", "UnHealthyHostCount", ".", ".", ".", ".", { stat = "Average", label = "unhealthy hosts" }],
            ["AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", aws_lb.app.arn_suffix, { stat = "Average", label = "latency avg", yAxis = "right" }],
            [".", ".", ".", ".", { stat = "p99", label = "latency p99", yAxis = "right" }]
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
        type = "metric", x = 0, y = 16, width = 12, height = 6,
        properties = {
          title  = "RDS CPU & connections",
          region = var.region,
          view   = "timeSeries",
          yAxis  = { left = { label = "CPU %", min = 0 }, right = { label = "connections", min = 0 } },
          metrics = [
            ["AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", aws_db_instance.main.identifier, { stat = "Average", label = "CPU %" }],
            [".", "DatabaseConnections", ".", ".", { stat = "Average", label = "connections", yAxis = "right" }]
          ]
        }
      },
      {
        type = "metric", x = 12, y = 16, width = 12, height = 6,
        properties = {
          title  = "RDS free storage & memory (bytes)",
          region = var.region,
          view   = "timeSeries",
          metrics = [
            ["AWS/RDS", "FreeStorageSpace", "DBInstanceIdentifier", aws_db_instance.main.identifier, { stat = "Average", label = "free storage" }],
            [".", "FreeableMemory", ".", ".", { stat = "Average", label = "freeable memory" }]
          ]
        }
      },
      {
        type = "metric", x = 0, y = 22, width = 12, height = 6,
        properties = {
          title  = "ElastiCache Redis",
          region = var.region,
          view   = "timeSeries",
          yAxis  = { left = { label = "%", min = 0, max = 100 }, right = { label = "evictions", min = 0 } },
          metrics = [
            ["AWS/ElastiCache", "EngineCPUUtilization", "CacheClusterId", aws_elasticache_cluster.main.cluster_id, { stat = "Average", label = "engine CPU %" }],
            [".", "DatabaseMemoryUsagePercentage", ".", ".", { stat = "Average", label = "memory %" }],
            [".", "Evictions", ".", ".", { stat = "Sum", label = "evictions", yAxis = "right" }]
          ]
        }
      },
      {
        type = "metric", x = 12, y = 22, width = 12, height = 6,
        properties = {
          title  = "Redis cache hit rate %",
          region = var.region,
          view   = "timeSeries",
          yAxis  = { left = { min = 0, max = 100 } },
          metrics = [
            ["AWS/ElastiCache", "CacheHits", "CacheClusterId", aws_elasticache_cluster.main.cluster_id, { stat = "Sum", id = "hits", visible = false }],
            [".", "CacheMisses", ".", ".", { stat = "Sum", id = "misses", visible = false }],
            [{ expression = "100 * hits / (hits + misses)", label = "hit rate %", id = "hitrate" }]
          ]
        }
      },
      {
        type = "log", x = 0, y = 28, width = 24, height = 6,
        properties = {
          title  = "Application logs",
          region = var.region,
          query  = "SOURCE '${aws_cloudwatch_log_group.app.name}' | fields @timestamp, @message | sort @timestamp desc | limit 50"
        }
      }
    ]
  })
}
