"""Tests for the deterministic pricing engine."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pricing_engine import (
    ALB_HOURLY,
    EIP_MONTHLY,
    HOURS_PER_MONTH,
    NAT_GW_HOURLY,
    PricingProvider,
    SavingsEstimate,
    _auto_severity,
    _build_issue,
    _instance_family,
    _map_ebs_to_instances,
    _replace_family,
    calc_gp2_to_gp3,
    calc_idle_load_balancer,
    calc_idle_nat_gateway,
    calc_multi_az_rds,
    calc_old_gen_instance,
    calc_stopped_ec2_ebs,
    calc_unassociated_eip,
    calc_unattached_ebs,
    calc_zero_invocation_lambda,
    detect_and_price_issues,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class FakePricingProvider(PricingProvider):
    """PricingProvider with the AWS Pricing API disabled (uses hardcoded prices)."""

    def __init__(self, region: str = "us-east-1"):
        super().__init__(region)
        self._pricing_available = False


def _provider():
    return FakePricingProvider("us-east-1")


# ---------------------------------------------------------------------------
# Unit tests — utility functions
# ---------------------------------------------------------------------------


class TestUtilityFunctions:
    def test_instance_family_standard(self):
        assert _instance_family("t2.micro") == "t2"
        assert _instance_family("m5.xlarge") == "m5"

    def test_instance_family_no_dot(self):
        assert _instance_family("custom") == "custom"

    def test_replace_family(self):
        assert _replace_family("t2.micro", "t3") == "t3.micro"
        assert _replace_family("m4.2xlarge", "m5") == "m5.2xlarge"

    def test_replace_family_no_dot(self):
        assert _replace_family("custom", "t3") == "custom"

    def test_auto_severity_high(self):
        assert _auto_severity(100.0) == "high"

    def test_auto_severity_medium(self):
        assert _auto_severity(25.0) == "medium"

    def test_auto_severity_low(self):
        assert _auto_severity(5.0) == "low"

    def test_auto_severity_boundary(self):
        assert _auto_severity(50.0) == "medium"
        assert _auto_severity(50.01) == "high"
        assert _auto_severity(10.0) == "medium"
        assert _auto_severity(9.99) == "low"


# ---------------------------------------------------------------------------
# Unit tests — individual calculators
# ---------------------------------------------------------------------------


class TestCalcUnattachedEbs:
    def test_deterministic_gp2(self):
        vol = {"volume_id": "vol-1", "size_gb": 100, "volume_type": "gp2"}
        est = calc_unattached_ebs(vol, _provider())
        assert est.monthly_savings == 10.0  # 100 * 0.10
        assert est.confidence == "high"
        assert est.calculation_method == "deterministic"
        assert "100 GB" in est.formula

    def test_deterministic_gp3(self):
        vol = {"volume_id": "vol-2", "size_gb": 500, "volume_type": "gp3"}
        est = calc_unattached_ebs(vol, _provider())
        assert est.monthly_savings == 40.0  # 500 * 0.08

    def test_deterministic_io1(self):
        vol = {"volume_id": "vol-3", "size_gb": 200, "volume_type": "io1"}
        est = calc_unattached_ebs(vol, _provider())
        assert est.monthly_savings == 25.0  # 200 * 0.125

    def test_cost_explorer_override(self):
        vol = {
            "volume_id": "vol-4",
            "size_gb": 100,
            "volume_type": "gp2",
            "cost_info": {"current_month_cost": 12.50},
        }
        est = calc_unattached_ebs(vol, _provider())
        assert est.monthly_savings == 12.50
        assert est.calculation_method == "cost_explorer"

    def test_zero_size_volume(self):
        vol = {"volume_id": "vol-5", "size_gb": 0, "volume_type": "gp2"}
        est = calc_unattached_ebs(vol, _provider())
        assert est.monthly_savings == 0.0


class TestCalcGp2ToGp3:
    def test_basic_migration(self):
        vol = {"volume_id": "vol-1", "size_gb": 100, "volume_type": "gp2"}
        est = calc_gp2_to_gp3(vol, _provider())
        # 100 * (0.10 - 0.08) = 2.00
        assert est.monthly_savings == 2.0
        assert est.confidence == "high"

    def test_large_volume(self):
        vol = {"volume_id": "vol-2", "size_gb": 1000, "volume_type": "gp2"}
        est = calc_gp2_to_gp3(vol, _provider())
        assert est.monthly_savings == 20.0  # 1000 * 0.02

    def test_cost_explorer_override(self):
        vol = {
            "volume_id": "vol-3",
            "size_gb": 100,
            "volume_type": "gp2",
            "cost_info": {"current_month_cost": 15.0},
        }
        est = calc_gp2_to_gp3(vol, _provider())
        # 15.0 * (0.10 - 0.08) / 0.10 = 3.0
        assert est.monthly_savings == 3.0
        assert est.calculation_method == "cost_explorer"


class TestCalcUnassociatedEip:
    def test_fixed_price(self):
        eip = {"allocation_id": "eipalloc-1", "public_ip": "1.2.3.4"}
        est = calc_unassociated_eip(eip, _provider())
        assert est.monthly_savings == EIP_MONTHLY
        assert est.confidence == "high"

    def test_cost_explorer_override(self):
        eip = {
            "allocation_id": "eipalloc-2",
            "public_ip": "5.6.7.8",
            "cost_info": {"current_month_cost": 4.00},
        }
        est = calc_unassociated_eip(eip, _provider())
        assert est.monthly_savings == 4.00


class TestCalcIdleNatGateway:
    def test_deterministic(self):
        nat = {"nat_gateway_id": "nat-1", "bytes_out_7d": 0}
        est = calc_idle_nat_gateway(nat, _provider())
        expected = round(NAT_GW_HOURLY * HOURS_PER_MONTH, 2)
        assert est.monthly_savings == expected
        assert est.confidence == "high"


class TestCalcIdleLoadBalancer:
    def test_alb(self):
        lb = {"name": "idle-alb", "type": "application"}
        est = calc_idle_load_balancer(lb, _provider())
        expected = round(ALB_HOURLY * HOURS_PER_MONTH, 2)
        assert est.monthly_savings == expected

    def test_classic(self):
        lb = {"name": "idle-clb", "type": "classic"}
        est = calc_idle_load_balancer(lb, _provider())
        expected = round(0.025 * HOURS_PER_MONTH, 2)
        assert est.monthly_savings == expected


class TestCalcZeroInvocationLambda:
    def test_zero_cost(self):
        fn = {"function_name": "dead-fn", "invocations_last_30d": 0}
        est = calc_zero_invocation_lambda(fn, _provider())
        assert est.monthly_savings == 0.0
        assert est.confidence == "high"


class TestCalcStoppedEc2Ebs:
    def test_with_attached_volumes(self):
        inst = {"instance_id": "i-1", "state": "stopped"}
        vols = [
            {"size_gb": 50, "volume_type": "gp2"},
            {"size_gb": 100, "volume_type": "gp3"},
        ]
        est = calc_stopped_ec2_ebs(inst, vols, _provider())
        # 50*0.10 + 100*0.08 = 5 + 8 = 13
        assert est.monthly_savings == 13.0
        assert est.confidence == "high"

    def test_no_attached_volumes(self):
        inst = {"instance_id": "i-2", "state": "stopped"}
        est = calc_stopped_ec2_ebs(inst, [], _provider())
        assert est.monthly_savings == 0.0
        assert est.confidence == "medium"


class TestCalcOldGenInstance:
    def test_unknown_family(self):
        inst = {"instance_id": "i-1", "instance_type": "t3.micro", "platform": "Linux/UNIX"}
        est = calc_old_gen_instance(inst, _provider())
        assert est.monthly_savings == 0.0
        assert est.confidence == "low"

    def test_old_gen_no_pricing_no_ce(self):
        """Without Pricing API or Cost Explorer, savings are 0 with low confidence."""
        inst = {"instance_id": "i-1", "instance_type": "m4.large", "platform": "Linux/UNIX"}
        est = calc_old_gen_instance(inst, _provider())
        assert est.confidence == "low"

    def test_old_gen_with_cost_explorer(self):
        inst = {
            "instance_id": "i-1",
            "instance_type": "m4.large",
            "platform": "Linux/UNIX",
            "cost_info": {"current_month_cost": 100.0},
        }
        est = calc_old_gen_instance(inst, _provider())
        assert est.monthly_savings == 15.0  # 100 * 0.15
        assert est.calculation_method == "cost_explorer"


class TestCalcMultiAzRds:
    def test_with_cost_explorer(self):
        rds = {
            "db_instance_id": "mydb",
            "db_instance_class": "db.t3.medium",
            "engine": "postgres",
            "multi_az": True,
            "cost_info": {"current_month_cost": 200.0},
        }
        est = calc_multi_az_rds(rds, _provider())
        assert est.monthly_savings == 100.0  # 200 * 0.50
        assert est.calculation_method == "cost_explorer"

    def test_without_pricing(self):
        rds = {
            "db_instance_id": "mydb",
            "db_instance_class": "db.t3.medium",
            "engine": "postgres",
            "multi_az": True,
        }
        est = calc_multi_az_rds(rds, _provider())
        assert est.confidence == "low"


# ---------------------------------------------------------------------------
# Integration test — detect_and_price_issues orchestrator
# ---------------------------------------------------------------------------


class TestDetectAndPriceIssues:
    def test_detects_all_issue_types(self, sample_resources):
        """The orchestrator should find issues across all resource types."""
        # Patch PricingProvider to avoid AWS API calls
        import pricing_engine

        original_init = PricingProvider.__init__

        def fake_init(self, region):
            original_init(self, region)
            self._pricing_available = False

        pricing_engine.PricingProvider.__init__ = fake_init
        try:
            issues = detect_and_price_issues(sample_resources, "us-east-1")
        finally:
            pricing_engine.PricingProvider.__init__ = original_init

        resource_ids = [i["resource_id"] for i in issues]

        # Unattached EBS
        assert "vol-unattached01" in resource_ids
        # gp2 -> gp3 (attached gp2 volume)
        assert "vol-gp2attached" in resource_ids
        # Unassociated EIP
        assert "eipalloc-unused01" in resource_ids
        # Idle NAT GW
        assert "nat-idle01" in resource_ids
        # Idle ALB
        assert "idle-alb" in resource_ids
        # Zero invocation Lambda
        assert "dead-function" in resource_ids
        # Stopped EC2
        assert "i-stopped001" in resource_ids
        # Old gen EC2 (m4.large) — without Pricing API, savings=0 + confidence=low
        # gets filtered out by the orchestrator; only appears with real pricing data
        # or Cost Explorer enrichment.
        # Multi-AZ RDS
        assert "dev-db-multi-az" in resource_ids

    def test_issue_structure(self, sample_resources):
        """Each issue should have required fields."""
        import pricing_engine

        original_init = PricingProvider.__init__

        def fake_init(self, region):
            original_init(self, region)
            self._pricing_available = False

        pricing_engine.PricingProvider.__init__ = fake_init
        try:
            issues = detect_and_price_issues(sample_resources, "us-east-1")
        finally:
            pricing_engine.PricingProvider.__init__ = original_init

        required_fields = {
            "resource_id",
            "resource_type",
            "issue_type",
            "estimated_monthly_savings",
            "confidence",
            "calculation_method",
            "savings_formula",
            "severity",
        }
        for issue in issues:
            missing = required_fields - set(issue.keys())
            assert not missing, f"Issue {issue['resource_id']} missing fields: {missing}"


class TestMapEbsToInstances:
    def test_mapping(self):
        vols = [
            {"volume_id": "vol-1", "attached_instance_id": "i-1"},
            {"volume_id": "vol-2", "attached_instance_id": "i-1"},
            {"volume_id": "vol-3", "attached_instance_id": "i-2"},
            {"volume_id": "vol-4", "attached_instance_id": None},
        ]
        result = _map_ebs_to_instances(vols)
        assert len(result["i-1"]) == 2
        assert len(result["i-2"]) == 1
        assert None not in result


class TestBuildIssue:
    def test_structure(self):
        resource = {"volume_id": "vol-1", "name": "test"}
        est = SavingsEstimate(
            monthly_savings=10.0,
            confidence="high",
            calculation_method="deterministic",
            formula="test formula",
        )
        issue = _build_issue(resource, "volume_id", "ebs", "unused", est)
        assert issue["resource_id"] == "vol-1"
        assert issue["resource_type"] == "ebs"
        assert issue["issue_type"] == "unused"
        assert issue["estimated_monthly_savings"] == "$10.00/mo"
        assert issue["confidence"] == "high"
        assert issue["savings_formula"] == "test formula"
