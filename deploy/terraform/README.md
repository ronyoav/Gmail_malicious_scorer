# AWS deployment (Terraform)

Deploys the phishing scorer as a highly-available, observable web app on AWS:

```
Internet ─▶ ALB ─▶ Auto Scaling Group (2× EC2, 2 AZs) ─▶ RDS Postgres (Multi-AZ)
                                                        └▶ ElastiCache Redis
                        CloudWatch: metrics · logs · dashboard · alarms ─▶ SNS email
                        SSM: Session Manager (shell) + Parameter Store (secrets)
```

## What gets created
- **VPC** across 2 AZs — public subnets (ALB + EC2), private subnets (RDS + Redis). No NAT Gateway (cost).
- **ALB** on port 80, health check `GET /health`.
- **Auto Scaling Group** of 2 `t3.micro` running the FastAPI app (systemd `scorer.service`).
- **RDS Postgres**, Multi-AZ, private, encrypted.
- **ElastiCache Redis**, single node, private.
- **CloudWatch** dashboard + 4 alarms (CPU, unhealthy hosts, 5xx, response latency > 2s) + app log group.
- **SNS** alerts topic — every alarm publishes to it; pass `-var="alert_email=you@example.com"` at apply time to receive email notifications (confirm the subscription link AWS sends).
- **IAM** instance role: SSM Session Manager, CloudWatch agent, read app SSM params, read app S3 bundle.

## Prerequisites
- A new AWS account (the assignment grants $100 — this stack stays well under it).
- Terraform ≥ 1.5 and AWS credentials configured (`aws configure`) for that account.
- No SSH key needed — shell access is via SSM Session Manager.

## Deploy
```bash
cd deploy/terraform
terraform init
terraform apply            # ~10–15 min (RDS Multi-AZ is the slow part)
```

Then set the API keys once (they are NOT stored in Terraform or git):
```bash
# the exact commands are printed by `terraform output set_secrets_hint`
aws ssm put-parameter --overwrite --type SecureString \
  --name /phishing-scorer/claude/api-key --value 'YOUR_CLAUDE_KEY'
aws ssm put-parameter --overwrite --type SecureString \
  --name /phishing-scorer/virustotal/api-key --value 'YOUR_VT_KEY'
```
Instances read the keys on boot. If you set them after the instances launched,
refresh the app on each box (via Session Manager): `sudo systemctl restart scorer`,
or just let the ASG recycle them.

## Use & observe
- `terraform output alb_url` → open the app in a browser.
- `terraform output cloudwatch_dashboard_url` → the dashboard (requests, 5xx, host health, CPU, memory, logs).
- Shell into an instance with no SSH: AWS console → EC2 → Instances → Connect → **Session Manager**
  (or `aws ssm start-session --target <instance-id>`). Boot log: `/var/log/user-data.log`.

## Tear down (do this when done — the assignment requires it)
```bash
terraform destroy
```

## Cost notes
- Everything is free-tier-eligible except RDS **Multi-AZ** (a standby replica → ~2× the DB cost)
  and ElastiCache. For a short demo this is a few dollars. Set `db_multi_az = false` to halve the
  RDS cost while iterating.
- `NAT Gateway` is deliberately avoided (~$32/mo).

## Follow-ups
- **TLS/HTTPS**: the ALB listens on port 80 only. Production should add an ACM certificate and an
  HTTPS listener (and redirect 80 → 443) so email content isn't sent in the clear.
- **App delivery is a one-shot `apply`**: code is zipped to S3 at apply time; there is no CI/CD, so
  updating the app means re-running `apply` and recycling the instances.
