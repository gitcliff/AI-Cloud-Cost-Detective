"""Shared fixtures for backend tests."""

import os

import pytest

# Set required env vars before importing any app modules
os.environ.setdefault("JWT_SECRET", "test-secret-key-for-ci")
os.environ.setdefault("JWT_ALGORITHM", "HS256")
os.environ.setdefault("JWT_EXPIRE_HOURS", "1")
os.environ.setdefault("LLM_PROVIDER", "groq")
os.environ.setdefault("LLM_API_KEY", "test-key")


@pytest.fixture
def sample_resources():
    """Minimal AWS resource inventory for testing the pricing engine."""
    return {
        "ec2_instances": [
            {
                "instance_id": "i-stopped001",
                "instance_type": "t2.micro",
                "state": "stopped",
                "name": "stopped-dev-server",
                "platform": "Linux/UNIX",
            },
            {
                "instance_id": "i-running001",
                "instance_type": "m4.large",
                "state": "running",
                "name": "old-gen-web",
                "platform": "Linux/UNIX",
            },
            {
                "instance_id": "i-running002",
                "instance_type": "t3.medium",
                "state": "running",
                "name": "current-gen-app",
                "platform": "Linux/UNIX",
            },
        ],
        "ebs_volumes": [
            {
                "volume_id": "vol-unattached01",
                "volume_type": "gp2",
                "size_gb": 100,
                "state": "available",
                "attached": False,
                "attached_instance_id": None,
                "name": "orphan-volume",
            },
            {
                "volume_id": "vol-gp2attached",
                "volume_type": "gp2",
                "size_gb": 50,
                "state": "in-use",
                "attached": True,
                "attached_instance_id": "i-stopped001",
                "name": "stopped-root",
            },
            {
                "volume_id": "vol-gp3attached",
                "volume_type": "gp3",
                "size_gb": 200,
                "state": "in-use",
                "attached": True,
                "attached_instance_id": "i-running002",
                "name": "app-data",
            },
        ],
        "elastic_ips": [
            {
                "allocation_id": "eipalloc-unused01",
                "public_ip": "203.0.113.10",
                "associated": False,
                "instance_id": "",
            },
            {
                "allocation_id": "eipalloc-used01",
                "public_ip": "203.0.113.20",
                "associated": True,
                "instance_id": "i-running002",
            },
        ],
        "nat_gateways": [
            {
                "nat_gateway_id": "nat-idle01",
                "vpc_id": "vpc-abc",
                "subnet_id": "subnet-123",
                "state": "available",
                "bytes_out_7d": 0,
            },
        ],
        "load_balancers": [
            {
                "name": "idle-alb",
                "arn": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/idle-alb/abc",
                "type": "application",
                "state": "active",
                "has_healthy_targets": False,
            },
        ],
        "lambda_functions": [
            {
                "function_name": "dead-function",
                "runtime": "python3.12",
                "memory_mb": 128,
                "timeout_seconds": 30,
                "code_size_bytes": 5000,
                "last_modified": "2024-01-01T00:00:00Z",
                "invocations_last_30d": 0,
            },
        ],
        "rds_instances": [
            {
                "db_instance_id": "dev-db-multi-az",
                "db_instance_class": "db.t3.medium",
                "engine": "postgres",
                "engine_version": "15.4",
                "status": "available",
                "multi_az": True,
                "storage_type": "gp3",
                "allocated_storage_gb": 100,
                "publicly_accessible": False,
            },
        ],
        "s3_buckets": [],
    }
