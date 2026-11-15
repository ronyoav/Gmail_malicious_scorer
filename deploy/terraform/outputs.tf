output "alb_url" {
  description = "Public URL of the application (open this in a browser)."
  value       = "http://${aws_lb.app.dns_name}"
}

output "cloudwatch_dashboard_url" {
  description = "Direct link to the CloudWatch dashboard."
  value       = "https://${var.region}.console.aws.amazon.com/cloudwatch/home?region=${var.region}#dashboards:name=${aws_cloudwatch_dashboard.main.dashboard_name}"
}

output "rds_endpoint" {
  description = "Postgres endpoint (reachable only from the app instances)."
  value       = aws_db_instance.main.address
}

output "redis_endpoint" {
  description = "Redis endpoint (reachable only from the app instances)."
  value       = aws_elasticache_cluster.main.cache_nodes[0].address
}

output "app_bucket" {
  description = "S3 bucket holding the app bundle."
  value       = aws_s3_bucket.app.bucket
}

output "set_secrets_hint" {
  description = "Run these once to set the API keys (they are not stored in Terraform)."
  value       = <<-EOT
    aws ssm put-parameter --overwrite --type SecureString --region ${var.region} --name ${var.ssm_param_prefix}/claude/api-key     --value 'YOUR_CLAUDE_KEY'
    aws ssm put-parameter --overwrite --type SecureString --region ${var.region} --name ${var.ssm_param_prefix}/virustotal/api-key --value 'YOUR_VT_KEY'
  EOT
}
