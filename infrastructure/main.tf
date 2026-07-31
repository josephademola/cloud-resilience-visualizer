# ============================================================
# Cloud Resilience Visualizer — test AWS infrastructure
#
# Creates a small fintech-style environment: 1 VPC with public and
# private subnets, 1 EC2 instance, 3 security groups, 2 S3 buckets
# (one properly configured, one deliberately misconfigured for the
# scanner to detect).
#
# ALL resources are tagged with Project=cloud-resilience-visualizer
# so they're easy to spot in the console and clean up.
#
# Usage:
#   terraform init      (once, downloads AWS provider)
#   terraform plan      (dry run — shows what will be created)
#   terraform apply     (creates everything, asks for confirmation)
#   terraform destroy   (deletes everything, asks for confirmation)
# ============================================================


# ---- Provider ------------------------------------------------------
# The provider block tells Terraform which cloud we're using.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "eu-west-2"
}


# ---- Variables ----------------------------------------------------
# Small suffix appended to S3 bucket names, because bucket names
# must be globally unique across all of AWS.

resource "random_id" "suffix" {
  byte_length = 4
}


# ---- Common tags --------------------------------------------------
# Applied to every resource so we can identify them at a glance and
# delete only these if manual cleanup is ever needed.

locals {
  common_tags = {
    Project     = "cloud-resilience-visualizer"
    Environment = "test"
    ManagedBy   = "terraform"
  }
}


# ---- VPC ----------------------------------------------------------

resource "aws_vpc" "main" {
  cidr_block           = "10.20.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(local.common_tags, {
    Name = "crv-test-vpc"
  })
}


# ---- Subnets ------------------------------------------------------

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.20.1.0/24"
  availability_zone       = "eu-west-2a"
  map_public_ip_on_launch = true

  tags = merge(local.common_tags, {
    Name = "crv-public-subnet"
    Tier = "public"
  })
}

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.20.2.0/24"
  availability_zone = "eu-west-2b"

  tags = merge(local.common_tags, {
    Name = "crv-private-subnet"
    Tier = "private"
  })
}


# ---- Internet Gateway ---------------------------------------------

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = merge(local.common_tags, {
    Name = "crv-igw"
  })
}


# ---- Security Groups ----------------------------------------------
# Three security groups in a chain: web (public HTTP/HTTPS in) ->
# app (only from web-sg) -> db (only from app-sg).

resource "aws_security_group" "web" {
  name        = "crv-web-sg"
  description = "Allow HTTP/HTTPS from anywhere"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP from anywhere"
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS from anywhere"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "crv-web-sg"
  })
}

resource "aws_security_group" "app" {
  name        = "crv-app-sg"
  description = "Allow traffic from web tier only"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.web.id]
    description     = "Application port from web tier"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "crv-app-sg"
  })
}

resource "aws_security_group" "db" {
  name        = "crv-db-sg"
  description = "Allow database traffic from app tier only"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
    description     = "MySQL from app tier"
  }

  tags = merge(local.common_tags, {
    Name = "crv-db-sg"
  })
}


# ---- EC2 Instance -------------------------------------------------
# t3.micro is Free Plan eligible. We're not installing anything on it
# — the instance just needs to exist so the scanner sees it.

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

resource "aws_instance" "web_01" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.web.id]

  tags = merge(local.common_tags, {
    Name = "crv-web-01"
  })
}


# ---- S3 Bucket: SECURE (properly configured) ----------------------
# All three protections enabled: no public ACL, PAB fully enabled,
# server-side encryption on.

resource "aws_s3_bucket" "secure_logs" {
  bucket = "crv-secure-logs-${random_id.suffix.hex}"

  tags = merge(local.common_tags, {
    Name    = "crv-secure-logs"
    Purpose = "demo-secure-bucket"
  })
}

resource "aws_s3_bucket_public_access_block" "secure_logs" {
  bucket = aws_s3_bucket.secure_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure_logs" {
  bucket = aws_s3_bucket.secure_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}


# ---- S3 Bucket: DELIBERATELY MISCONFIGURED ------------------------
#
# WARNING: This bucket is intentionally public and unencrypted for
# scanner demonstration purposes. It must:
#   1. Never contain sensitive data (put in only test files if any)
#   2. Be destroyed as soon as testing is complete
#   3. Never be renamed to look production-related
#
# All three misconfigurations that the scanner detects:
#   - No Public Access Block (all four flags off)
#   - Public ACL grant to AllUsers
#   - No server-side encryption

resource "aws_s3_bucket" "misconfigured_uploads" {
  bucket = "crv-demo-misconfigured-${random_id.suffix.hex}"

  tags = merge(local.common_tags, {
    Name    = "crv-demo-misconfigured"
    Purpose = "deliberately-misconfigured-for-scanner-demo"
    Warning = "must-not-store-real-data"
  })
}

# Explicitly disable Public Access Block. Required to allow the
# public ACL below.
resource "aws_s3_bucket_public_access_block" "misconfigured_uploads" {
  bucket = aws_s3_bucket.misconfigured_uploads.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Set bucket ownership so ACLs are allowed (AWS default is to block).
resource "aws_s3_bucket_ownership_controls" "misconfigured_uploads" {
  bucket = aws_s3_bucket.misconfigured_uploads.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# The public ACL — the actual misconfiguration.
resource "aws_s3_bucket_acl" "misconfigured_uploads" {
  bucket = aws_s3_bucket.misconfigured_uploads.id
  acl    = "public-read"

  depends_on = [
    aws_s3_bucket_ownership_controls.misconfigured_uploads,
    aws_s3_bucket_public_access_block.misconfigured_uploads,
  ]
}


# ---- Outputs ------------------------------------------------------
# Printed at the end of `terraform apply` so you can verify what
# got created without opening the console.

output "vpc_id" {
  value       = aws_vpc.main.id
  description = "VPC ID (should appear in your tool's topology view)"
}

output "ec2_instance_id" {
  value       = aws_instance.web_01.id
  description = "EC2 instance ID"
}

output "secure_bucket_name" {
  value       = aws_s3_bucket.secure_logs.id
  description = "Name of the correctly-configured bucket (should NOT produce findings)"
}

output "misconfigured_bucket_name" {
  value       = aws_s3_bucket.misconfigured_uploads.id
  description = "Name of the deliberately-misconfigured bucket (should produce 3 findings)"
}

output "rds_instance_id" {
  value       = aws_db_instance.main.identifier
  description = "RDS instance identifier"
}

# ---- RDS Instance -------------------------------------------------
# Smallest possible RDS instance, deliberately Single-AZ (cheaper),
# minimum storage (20 GB), no backups (default 0). This exists so
# the scanner has real RDS to normalise — no application uses it.
#
# WARNING: RDS accrues cost from your Free Plan credits at roughly
# $0.20-0.30 per day. Destroy with `terraform destroy` when done.

resource "aws_db_subnet_group" "main" {
  name       = "crv-db-subnet-group"
  subnet_ids = [aws_subnet.public.id, aws_subnet.private.id]

  tags = merge(local.common_tags, {
    Name = "crv-db-subnet-group"
  })
}

resource "aws_db_instance" "main" {
  identifier             = "crv-primary-db"
  engine                 = "mysql"
  engine_version         = "8.0"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  db_name                = "crvdemo"
  username               = "admin"
  password               = "ChangeMeNow2026!" # Not real — this DB has no real use
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.db.id]
  skip_final_snapshot    = true
  publicly_accessible    = false
  storage_encrypted      = true
  backup_retention_period = 0

  tags = merge(local.common_tags, {
    Name = "crv-primary-db"
  })
}