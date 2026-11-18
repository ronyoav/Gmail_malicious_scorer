#!/bin/bash
# Bootstraps an app instance on Amazon Linux 2023.
# Logs to /var/log/user-data.log for debugging (view via SSM Session Manager).
set -euxo pipefail
exec > >(tee -a /var/log/user-data.log) 2>&1

REGION="${region}"
APP_PORT="${app_port}"
S3_BUCKET="${s3_bucket}"
SSM_PREFIX="${ssm_prefix}"
LOG_GROUP="${log_group}"

dnf -y update
dnf -y install python3.11 python3.11-pip unzip amazon-cloudwatch-agent

# --- fetch the app bundle from S3 -----------------------------------------
mkdir -p /opt/app/backend /var/log/app
aws s3 cp "s3://$S3_BUCKET/app.zip" /tmp/app.zip --region "$REGION"
unzip -o /tmp/app.zip -d /opt/app/backend

# --- python environment ----------------------------------------------------
python3.11 -m venv /opt/app/venv
/opt/app/venv/bin/pip install --upgrade pip
/opt/app/venv/bin/pip install -r /opt/app/backend/requirements.txt
/opt/app/venv/bin/pip install uvicorn

# --- read config + secrets from SSM Parameter Store ------------------------
get_param() { aws ssm get-parameter --name "$1" --with-decryption --query 'Parameter.Value' --output text --region "$REGION"; }

cat > /opt/app/app.env <<EOF
DATABASE_URL=$(get_param "$SSM_PREFIX/database/url")
REDIS_URL=$(get_param "$SSM_PREFIX/redis/url")
API_KEY_CLAUDE=$(get_param "$SSM_PREFIX/claude/api-key")
VIRUSTOTAL_API_KEY=$(get_param "$SSM_PREFIX/virustotal/api-key")
EOF
chmod 600 /opt/app/app.env

# --- run the app as a systemd service --------------------------------------
cat > /etc/systemd/system/scorer.service <<EOF
[Unit]
Description=Phishing Scorer API
After=network.target

[Service]
WorkingDirectory=/opt/app
EnvironmentFile=/opt/app/app.env
ExecStart=/opt/app/venv/bin/uvicorn backend.main:app --host 0.0.0.0 --port $APP_PORT
Restart=always
StandardOutput=append:/var/log/app/app.log
StandardError=append:/var/log/app/app.log

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now scorer.service

# --- CloudWatch agent: ship app logs + memory/disk metrics -----------------
cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json <<EOF
{
  "agent": { "metrics_collection_interval": 60 },
  "metrics": {
    "namespace": "PhishingScorer",
    "append_dimensions": {
      "InstanceId": "\$${aws:InstanceId}",
      "AutoScalingGroupName": "\$${aws:AutoScalingGroupName}"
    },
    "aggregation_dimensions": [["AutoScalingGroupName"], ["InstanceId"]],
    "metrics_collected": {
      "mem": { "measurement": ["mem_used_percent"] },
      "disk": { "measurement": ["used_percent"], "resources": ["/"] }
    }
  },
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          { "file_path": "/var/log/app/app.log", "log_group_name": "$LOG_GROUP", "log_stream_name": "{instance_id}" }
        ]
      }
    }
  }
}
EOF

/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
  -a fetch-config -m ec2 -s \
  -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json
