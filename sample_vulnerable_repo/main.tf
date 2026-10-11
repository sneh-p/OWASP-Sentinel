# Sample Vulnerable Terraform Infrastructure File

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# SEC-IAC-005: Security Group Open to World on Sensitive Port (SSH / 22)
resource "aws_security_group" "public_ssh" {
  name        = "allow_ssh_from_anywhere"
  description = "Dangerous SG rule allowing 0.0.0.0/0 on SSH"

  ingress {
    description = "SSH from world"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# SEC-IAC-006: S3 Bucket with Public ACL
resource "aws_s3_bucket" "data_lake" {
  bucket = "company-internal-data-backup-bucket"
  acl    = "public-read"

  tags = {
    Environment = "Production"
  }
}

# CIS-CLOUD-001: AWS EBS volume unencrypted at rest
resource "aws_ebs_volume" "database_storage" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false
}

# CIS-CLOUD-002: AWS RDS database publicly accessible
resource "aws_db_instance" "backend_db" {
  allocated_storage   = 50
  engine              = "postgres"
  publicly_accessible = true
}
