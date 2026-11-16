# ---------------------------------------------------------------------------
# Config + secrets in SSM Parameter Store. The app reads these on boot.
#   - DB and Redis URLs are composed by Terraform (it knows the endpoints).
#   - The Claude / VirusTotal API keys are created as placeholders and are NOT
#     stored in Terraform/git — you fill them in once, manually (see README).
#     `ignore_changes` keeps Terraform from wiping your value on the next apply.
# ---------------------------------------------------------------------------

resource "random_password" "db" {
  length  = 24
  special = false # keep it URL-safe (no @ : / in the connection string)
}

resource "aws_ssm_parameter" "database_url" {
  name  = "${var.ssm_param_prefix}/database/url"
  type  = "SecureString"
  value = "postgresql://${var.db_username}:${random_password.db.result}@${aws_db_instance.main.address}:5432/${var.db_name}"
}

resource "aws_ssm_parameter" "redis_url" {
  name  = "${var.ssm_param_prefix}/redis/url"
  type  = "String"
  value = "redis://${aws_elasticache_cluster.main.cache_nodes[0].address}:6379/0"
}

resource "aws_ssm_parameter" "claude_api_key" {
  name  = "${var.ssm_param_prefix}/claude/api-key"
  type  = "SecureString"
  value = "REPLACE_ME"

  lifecycle {
    ignore_changes = [value] # set the real key manually; don't let apply revert it
  }
}

resource "aws_ssm_parameter" "virustotal_api_key" {
  name  = "${var.ssm_param_prefix}/virustotal/api-key"
  type  = "SecureString"
  value = "REPLACE_ME"

  lifecycle {
    ignore_changes = [value]
  }
}
