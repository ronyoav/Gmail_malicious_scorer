# AWS Architecture

Highly-available phishing scorer on AWS, region **eu-central-1 (Frankfurt)**.
Mirrors the Terraform in [`deploy/terraform/`](deploy/terraform/).

```mermaid
flowchart TB
    User([Gmail user]):::ext -->|add-on| Addon["Gmail Add-on<br/>PII strip · URL extract · SHA-256"]:::ext
    Browser([Web browser]):::ext -->|paste raw email| ALB
    Addon -->|"POST /api/v1/analyze · HTTP :80"| ALB

    subgraph AWS["AWS · eu-central-1 Frankfurt"]
      subgraph VPC["VPC 10.0.0.0/16 · 2 AZs"]
        ALB["Application Load Balancer<br/>:80 · health GET /health"]

        subgraph AZa["Availability Zone a"]
          subgraph PubA["Public subnet"]
            EC2a["EC2 t3.micro<br/>FastAPI :8000<br/>scorer.service"]
          end
          subgraph PrivA["Private subnet"]
            RDS[("RDS Postgres<br/>primary · encrypted")]
            Redis[("ElastiCache Redis<br/>single node")]
          end
        end

        subgraph AZb["Availability Zone b"]
          subgraph PubB["Public subnet"]
            EC2b["EC2 t3.micro<br/>FastAPI :8000<br/>scorer.service"]
          end
          subgraph PrivB["Private subnet"]
            RDSstby[("RDS Postgres<br/>Multi-AZ standby")]
          end
        end

        ALB --> EC2a
        ALB --> EC2b
        EC2a --> RDS
        EC2b --> RDS
        EC2a --> Redis
        EC2b --> Redis
        RDS -. sync replication / failover .-> RDSstby
      end

      ASG["Auto Scaling Group<br/>desired 2 · spans 2 AZs"]
      SSM["SSM Parameter Store<br/>Claude key · VT key<br/>DATABASE_URL · REDIS_URL"]
      S3[("S3<br/>app bundle")]
      CW["CloudWatch<br/>dashboard · log group<br/>alarms: CPU · unhealthy · 5xx · latency > 2s"]
      SNS["SNS<br/>alerts topic"]

      ASG -. manages .-> EC2a
      ASG -. manages .-> EC2b
      EC2a -. read secrets .-> SSM
      EC2b -. read secrets .-> SSM
      EC2a -. pull bundle .-> S3
      EC2b -. pull bundle .-> S3
      EC2a -. metrics + logs .-> CW
      EC2b -. metrics + logs .-> CW
      CW -. alarm enters ALARM .-> SNS
    end

    EC2a -->|analyze| Claude([Anthropic Claude API]):::ext
    EC2a -->|domain / file / URL lookup| VT([VirusTotal API]):::ext
    SNS -. email notification .-> Admin
    Admin([Operator]):::ext -. SSM Session Manager · no SSH .-> EC2a

    classDef ext fill:#eee,stroke:#999,color:#333;
```

## Key decisions

| Choice | Why |
|---|---|
| **2 AZs, ASG desired=2** | One EC2 / one AZ can fail; ALB routes to the healthy host. |
| **RDS Multi-AZ** | Standby replica in AZ-b; automatic failover. The slow part of `apply` (~10–15 min). |
| **No NAT Gateway** | EC2 sits in public subnets with public IPs instead → saves ~$32/mo. |
| **SSM, not SSH** | No key pairs, no port 22. Shell via Session Manager; secrets via Parameter Store. |
| **ElastiCache Redis** | Shared whole-email result cache across both instances (not in-process). |
| **CloudWatch + SNS** | Dashboard + 4 alarms (CPU, unhealthy hosts, 5xx, latency > 2s) + app log group. Alarms publish to an SNS topic → email (set `alert_email` at apply). |

## Request flow

1. Gmail Add-on / browser → **ALB :80** → one of 2 EC2 (`GET /health` gates routing).
2. FastAPI checks the **ElastiCache** whole-email cache → hit returns immediately.
3. Miss → analyzers run in parallel, calling **Claude** + **VirusTotal** outbound.
4. Result cached in ElastiCache; scan history written to **RDS**; metrics/logs to **CloudWatch**.

> Infra source of truth is the Terraform in `deploy/terraform/`; update this diagram when the stack changes.
