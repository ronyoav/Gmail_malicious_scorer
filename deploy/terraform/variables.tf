variable "region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "eu-central-1" # Frankfurt — closest full-featured, free-tier region to Israel
}

variable "project" {
  description = "Name prefix applied to all resources."
  type        = string
  default     = "phishing-scorer"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC."
  type        = string
  default     = "10.0.0.0/16"
}

variable "az_count" {
  description = "How many Availability Zones to spread across (HA)."
  type        = number
  default     = 2
}

variable "app_port" {
  description = "Port the FastAPI app listens on inside each EC2 instance."
  type        = number
  default     = 8000
}

variable "instance_type" {
  description = "EC2 instance type (free-tier eligible)."
  type        = string
  default     = "t3.micro"
}

variable "asg_desired_capacity" {
  description = "Number of app instances to keep running."
  type        = number
  default     = 2
}

variable "db_instance_class" {
  description = "RDS instance class."
  type        = string
  default     = "db.t3.micro"
}

variable "db_multi_az" {
  description = "Run RDS with a standby replica in a second AZ (true HA, ~2x cost)."
  type        = bool
  default     = true
}

variable "db_name" {
  description = "Initial Postgres database name."
  type        = string
  default     = "scorer"
}

variable "db_username" {
  description = "Master username for Postgres."
  type        = string
  default     = "scorer_admin"
}

variable "cache_node_type" {
  description = "ElastiCache (Redis) node type."
  type        = string
  default     = "cache.t3.micro"
}

variable "ssm_param_prefix" {
  description = "SSM Parameter Store path prefix for app config/secrets."
  type        = string
  default     = "/phishing-scorer"
}

variable "alert_email" {
  description = "Email to receive CloudWatch alarm notifications (via SNS). Leave empty to create the SNS topic with no subscriber. Supply at apply time, e.g. -var=\"alert_email=you@example.com\"; not committed."
  type        = string
  default     = ""
}
