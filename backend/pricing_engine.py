"""Deterministic pricing engine for AWS cost savings calculations.

Calculates savings from AWS pricing data + resource configuration + utilization,
rather than letting the LLM invent figures. Each estimate includes a confidence
level, calculation method, assumptions, and the formula used.
"""

import logging
from dataclasses import dataclass, field

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Hardcoded fallback pricing (us-east-1 baseline)
# ---------------------------------------------------------------------------

EBS_PRICES_PER_GB: dict[str, float] = {
    "gp2": 0.10,
    "gp3": 0.08,
    "io1": 0.125,
    "io2": 0.125,
    "st1": 0.045,
    "sc1": 0.015,
    "standard": 0.05,
}

EIP_MONTHLY = 3.60  # Fixed since Feb 2024

NAT_GW_HOURLY = 0.045
ALB_HOURLY = 0.0225
NLB_HOURLY = 0.0225
CLB_HOURLY = 0.025

HOURS_PER_MONTH = 730

# Old-generation instance family -> recommended replacement
OLD_GEN_MAP: dict[str, str] = {
    "t2": "t3",
    "m3": "m5",
    "m4": "m5",
    "c3": "c5",
    "c4": "c5",
    "r3": "r5",
    "r4": "r5",
    "i2": "i3",
    "d2": "d3",
}

# Region display name mapping for AWS Pricing API filters
REGION_DISPLAY_NAMES: dict[str, str] = {
    "us-east-1": "US East (N. Virginia)",
    "us-east-2": "US East (Ohio)",
    "us-west-1": "US West (N. California)",
    "us-west-2": "US West (Oregon)",
    "ca-central-1": "Canada (Central)",
    "eu-west-1": "EU (Ireland)",
    "eu-west-2": "EU (London)",
    "eu-west-3": "EU (Paris)",
    "eu-central-1": "EU (Frankfurt)",
    "eu-north-1": "EU (Stockholm)",
    "ap-southeast-1": "Asia Pacific (Singapore)",
    "ap-southeast-2": "Asia Pacific (Sydney)",
    "ap-northeast-1": "Asia Pacific (Tokyo)",
    "ap-northeast-2": "Asia Pacific (Seoul)",
    "ap-south-1": "Asia Pacific (Mumbai)",
    "sa-east-1": "South America (Sao Paulo)",
}


# ---------------------------------------------------------------------------
# SavingsEstimate
# ---------------------------------------------------------------------------

@dataclass
class SavingsEstimate:
    monthly_savings: float
    confidence: str  # "high" | "medium" | "low"
    calculation_method: str  # "deterministic" | "cost_explorer" | "llm_estimated"
    assumptions: list[str] = field(default_factory=list)
    current_monthly_cost: float | None = None
    formula: str = ""


# ---------------------------------------------------------------------------
# PricingProvider — fetches prices from AWS Pricing API with hardcoded fallback
# ---------------------------------------------------------------------------

class PricingProvider:
    """Fetch and cache AWS pricing data for a specific region."""

    def __init__(self, region: str):
        self.region = region
        self.region_display = REGION_DISPLAY_NAMES.get(region, region)
        self._cache: dict[tuple, float | None] = {}
        self._pricing_client = None
        self._pricing_available = True

    def _get_client(self):
        if self._pricing_client is None and self._pricing_available:
            try:
                session = boto3.Session(region_name="us-east-1")
                self._pricing_client = session.client("pricing")
            except (NoCredentialsError, ClientError):
                self._pricing_available = False
        return self._pricing_client

    def _api_lookup(self, service_code: str, filters: list[dict]) -> float | None:
        """Query AWS Pricing API. Returns hourly USD price or None."""
        client = self._get_client()
        if not client:
            return None

        cache_key = (service_code, tuple((f["Field"], f["Value"]) for f in filters))
        if cache_key in self._cache:
            return self._cache[cache_key]

        try:
            import json as _json
            resp = client.get_products(
                ServiceCode=service_code,
                Filters=filters,
                MaxResults=1,
            )
            for price_item_str in resp.get("PriceList", []):
                price_item = _json.loads(price_item_str) if isinstance(price_item_str, str) else price_item_str
                terms = price_item.get("terms", {}).get("OnDemand", {})
                for term in terms.values():
                    for dim in term.get("priceDimensions", {}).values():
                        usd = dim.get("pricePerUnit", {}).get("USD")
                        if usd:
                            price = float(usd)
                            self._cache[cache_key] = price
                            return price
        except Exception as e:
            logger.debug("Pricing API lookup failed for %s: %s", service_code, e)

        self._cache[cache_key] = None
        return None

    def get_ec2_hourly_price(self, instance_type: str, platform: str = "Linux/UNIX") -> float | None:
        """On-demand hourly price for an EC2 instance type."""
        os_map = {
            "Linux/UNIX": "Linux",
            "Windows": "Windows",
            "Red Hat Enterprise Linux": "RHEL",
            "SUSE Linux": "SUSE",
        }
        operating_system = os_map.get(platform, "Linux")

        price = self._api_lookup("AmazonEC2", [
            {"Type": "TERM_MATCH", "Field": "instanceType", "Value": instance_type},
            {"Type": "TERM_MATCH", "Field": "location", "Value": self.region_display},
            {"Type": "TERM_MATCH", "Field": "operatingSystem", "Value": operating_system},
            {"Type": "TERM_MATCH", "Field": "tenancy", "Value": "Shared"},
            {"Type": "TERM_MATCH", "Field": "preInstalledSw", "Value": "NA"},
            {"Type": "TERM_MATCH", "Field": "capacitystatus", "Value": "Used"},
        ])
        return price

    def get_ebs_price_per_gb(self, volume_type: str) -> float:
        """Price per GB-month for an EBS volume type. Uses hardcoded table."""
        return EBS_PRICES_PER_GB.get(volume_type, 0.10)

    def get_rds_hourly_price(self, instance_class: str, engine: str, multi_az: bool) -> float | None:
        """On-demand hourly price for an RDS instance."""
        engine_map = {
            "mysql": "MySQL",
            "postgres": "PostgreSQL",
            "mariadb": "MariaDB",
            "aurora-mysql": "Aurora MySQL",
            "aurora-postgresql": "Aurora PostgreSQL",
            "oracle-ee": "Oracle",
            "sqlserver-ee": "SQL Server",
            "sqlserver-se": "SQL Server",
        }
        db_engine = engine_map.get(engine, engine)
        deployment = "Multi-AZ" if multi_az else "Single-AZ"

        price = self._api_lookup("AmazonRDS", [
            {"Type": "TERM_MATCH", "Field": "instanceType", "Value": instance_class},
            {"Type": "TERM_MATCH", "Field": "location", "Value": self.region_display},
            {"Type": "TERM_MATCH", "Field": "databaseEngine", "Value": db_engine},
            {"Type": "TERM_MATCH", "Field": "deploymentOption", "Value": deployment},
        ])
        return price

    def get_elb_hourly_price(self, lb_type: str) -> float:
        """Fixed hourly price for a load balancer type. Uses hardcoded table."""
        prices = {"application": ALB_HOURLY, "network": NLB_HOURLY, "classic": CLB_HOURLY}
        return prices.get(lb_type, ALB_HOURLY)


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _instance_family(instance_type: str) -> str:
    """Extract family prefix: 't2.micro' -> 't2'."""
    return instance_type.split(".")[0] if "." in instance_type else instance_type


def _replace_family(instance_type: str, new_family: str) -> str:
    """Replace instance family: 't2.micro' with new_family='t3' -> 't3.micro'."""
    parts = instance_type.split(".", 1)
    if len(parts) == 2:
        return f"{new_family}.{parts[1]}"
    return instance_type


def _format_dollars(amount: float) -> str:
    return f"${amount:,.2f}/mo"


def _auto_severity(monthly_savings: float) -> str:
    if monthly_savings > 50:
        return "high"
    if monthly_savings >= 10:
        return "medium"
    return "low"


def _build_issue(
    resource: dict,
    id_field: str,
    resource_type: str,
    issue_type: str,
    estimate: SavingsEstimate,
    resource_name: str = "",
) -> dict:
    """Build a standardized issue dict from a resource and its savings estimate."""
    return {
        "resource_id": resource.get(id_field, ""),
        "resource_type": resource_type,
        "resource_name": resource_name or resource.get("name", ""),
        "issue_type": issue_type,
        "estimated_monthly_savings": _format_dollars(estimate.monthly_savings),
        "actual_monthly_cost": _format_dollars(estimate.current_monthly_cost) if estimate.current_monthly_cost else None,
        "confidence": estimate.confidence,
        "calculation_method": estimate.calculation_method,
        "assumptions": estimate.assumptions,
        "savings_formula": estimate.formula,
        # severity and explanation will be set by the LLM or auto-assigned
        "severity": _auto_severity(estimate.monthly_savings),
        "explanation": "",
        "fix_command": "",
    }


# ---------------------------------------------------------------------------
# Per-issue-type calculators
# ---------------------------------------------------------------------------

def _get_cost_explorer_cost(resource: dict) -> float | None:
    """Extract current monthly cost from Cost Explorer enrichment, if available."""
    cost_info = resource.get("cost_info")
    if cost_info and cost_info.get("current_month_cost"):
        return cost_info["current_month_cost"]
    return None


def calc_unattached_ebs(volume: dict, pricing: PricingProvider) -> SavingsEstimate:
    size_gb = volume.get("size_gb", 0)
    vol_type = volume.get("volume_type", "gp2")
    price_per_gb = pricing.get_ebs_price_per_gb(vol_type)

    ce_cost = _get_cost_explorer_cost(volume)
    if ce_cost is not None:
        return SavingsEstimate(
            monthly_savings=ce_cost,
            confidence="high",
            calculation_method="cost_explorer",
            assumptions=["Volume is unattached and can be safely deleted or snapshotted"],
            current_monthly_cost=ce_cost,
            formula=f"Actual Cost Explorer spend: ${ce_cost:,.2f}/mo",
        )

    savings = round(size_gb * price_per_gb, 2)
    return SavingsEstimate(
        monthly_savings=savings,
        confidence="high",
        calculation_method="deterministic",
        assumptions=["Volume is unattached and can be safely deleted or snapshotted"],
        current_monthly_cost=savings,
        formula=f"{size_gb} GB x ${price_per_gb}/GB ({vol_type}) = ${savings:,.2f}/mo",
    )


def calc_gp2_to_gp3(volume: dict, pricing: PricingProvider) -> SavingsEstimate:
    size_gb = volume.get("size_gb", 0)
    gp2_price = pricing.get_ebs_price_per_gb("gp2")
    gp3_price = pricing.get_ebs_price_per_gb("gp3")
    savings = round(size_gb * (gp2_price - gp3_price), 2)
    current_cost = round(size_gb * gp2_price, 2)

    ce_cost = _get_cost_explorer_cost(volume)
    if ce_cost is not None:
        current_cost = ce_cost
        savings = round(ce_cost * (gp2_price - gp3_price) / gp2_price, 2)

    return SavingsEstimate(
        monthly_savings=savings,
        confidence="high",
        calculation_method="cost_explorer" if ce_cost else "deterministic",
        assumptions=[
            "Workload needs <= 3,000 baseline IOPS (gp3 default)",
            "Workload needs <= 125 MB/s throughput (gp3 default)",
        ],
        current_monthly_cost=current_cost,
        formula=f"{size_gb} GB x (${gp2_price} - ${gp3_price})/GB = ${savings:,.2f}/mo",
    )


def calc_unassociated_eip(eip: dict, pricing: PricingProvider) -> SavingsEstimate:
    ce_cost = _get_cost_explorer_cost(eip)
    cost = ce_cost if ce_cost is not None else EIP_MONTHLY
    return SavingsEstimate(
        monthly_savings=cost,
        confidence="high",
        calculation_method="cost_explorer" if ce_cost else "deterministic",
        assumptions=["Elastic IP is not associated to any running instance"],
        current_monthly_cost=cost,
        formula=f"Fixed charge: ${EIP_MONTHLY}/mo per unassociated EIP",
    )


def calc_idle_nat_gateway(nat_gw: dict, pricing: PricingProvider) -> SavingsEstimate:
    ce_cost = _get_cost_explorer_cost(nat_gw)
    hourly_cost = NAT_GW_HOURLY * HOURS_PER_MONTH
    cost = ce_cost if ce_cost is not None else round(hourly_cost, 2)
    return SavingsEstimate(
        monthly_savings=cost,
        confidence="high",
        calculation_method="cost_explorer" if ce_cost else "deterministic",
        assumptions=[
            "NAT Gateway had zero bytes out in the last 7 days",
            "No workloads depend on this NAT Gateway",
        ],
        current_monthly_cost=cost,
        formula=f"${NAT_GW_HOURLY}/hr x {HOURS_PER_MONTH} hrs = ${hourly_cost:,.2f}/mo",
    )


def calc_idle_load_balancer(lb: dict, pricing: PricingProvider) -> SavingsEstimate:
    lb_type = lb.get("type", "application")
    hourly = pricing.get_elb_hourly_price(lb_type)
    monthly = round(hourly * HOURS_PER_MONTH, 2)

    ce_cost = _get_cost_explorer_cost(lb)
    cost = ce_cost if ce_cost is not None else monthly

    return SavingsEstimate(
        monthly_savings=cost,
        confidence="high",
        calculation_method="cost_explorer" if ce_cost else "deterministic",
        assumptions=[
            "Load balancer has no healthy targets",
            "No active traffic is being served",
        ],
        current_monthly_cost=cost,
        formula=f"${hourly}/hr x {HOURS_PER_MONTH} hrs = ${monthly:,.2f}/mo (fixed charge, {lb_type})",
    )


def calc_zero_invocation_lambda(fn: dict, pricing: PricingProvider) -> SavingsEstimate:
    return SavingsEstimate(
        monthly_savings=0.0,
        confidence="high",
        calculation_method="deterministic",
        assumptions=[
            "Lambda charges per invocation — zero invocations means zero Lambda cost",
            "There may be minor CloudWatch Logs storage costs not captured here",
        ],
        current_monthly_cost=0.0,
        formula="0 invocations x $0.20/1M requests = $0.00/mo (informational)",
    )


def calc_stopped_ec2_ebs(
    instance: dict,
    attached_volumes: list[dict],
    pricing: PricingProvider,
) -> SavingsEstimate:
    """Calculate the EBS cost of a stopped EC2 instance."""
    total_ebs_cost = 0.0
    formula_parts = []

    for vol in attached_volumes:
        size_gb = vol.get("size_gb", 0)
        vol_type = vol.get("volume_type", "gp2")
        price = pricing.get_ebs_price_per_gb(vol_type)
        cost = round(size_gb * price, 2)
        total_ebs_cost += cost
        formula_parts.append(f"{size_gb} GB {vol_type} = ${cost:,.2f}")

    ce_cost = _get_cost_explorer_cost(instance)
    if ce_cost is not None and ce_cost > total_ebs_cost:
        total_ebs_cost = ce_cost

    if not formula_parts:
        formula_parts.append("No attached volumes found")

    return SavingsEstimate(
        monthly_savings=round(total_ebs_cost, 2),
        confidence="high" if attached_volumes else "medium",
        calculation_method="deterministic",
        assumptions=[
            "Instance has been stopped and is not needed",
            "EBS volumes can be snapshotted and deleted",
        ],
        current_monthly_cost=round(total_ebs_cost, 2),
        formula=f"Attached EBS: {' + '.join(formula_parts)} = ${total_ebs_cost:,.2f}/mo",
    )


def calc_old_gen_instance(instance: dict, pricing: PricingProvider) -> SavingsEstimate:
    instance_type = instance.get("instance_type", "")
    platform = instance.get("platform", "Linux/UNIX")
    family = _instance_family(instance_type)
    new_family = OLD_GEN_MAP.get(family)

    if not new_family:
        return SavingsEstimate(
            monthly_savings=0.0,
            confidence="low",
            calculation_method="deterministic",
            assumptions=[],
            formula="Unable to determine replacement instance type",
        )

    new_type = _replace_family(instance_type, new_family)
    old_price = pricing.get_ec2_hourly_price(instance_type, platform)
    new_price = pricing.get_ec2_hourly_price(new_type, platform)

    if old_price is not None and new_price is not None:
        savings = round((old_price - new_price) * HOURS_PER_MONTH, 2)
        savings = max(savings, 0)  # New gen could rarely be same price
        return SavingsEstimate(
            monthly_savings=savings,
            confidence="medium",
            calculation_method="deterministic",
            assumptions=[
                f"Workload is compatible with {new_type} instance family",
                "No special hardware requirements tied to old generation",
            ],
            current_monthly_cost=round(old_price * HOURS_PER_MONTH, 2),
            formula=f"({instance_type} ${old_price}/hr - {new_type} ${new_price}/hr) x {HOURS_PER_MONTH} hrs = ${savings:,.2f}/mo",
        )

    # Pricing API unavailable — use Cost Explorer if we have it
    ce_cost = _get_cost_explorer_cost(instance)
    if ce_cost is not None:
        estimated_savings = round(ce_cost * 0.15, 2)  # ~15% typical gen upgrade savings
        return SavingsEstimate(
            monthly_savings=estimated_savings,
            confidence="low",
            calculation_method="cost_explorer",
            assumptions=[
                f"Estimated ~15% savings from upgrading {family} to {new_family}",
                f"Workload is compatible with {new_type}",
                "Actual savings depend on specific instance type pricing",
            ],
            current_monthly_cost=ce_cost,
            formula=f"~15% of ${ce_cost:,.2f}/mo actual spend = ${estimated_savings:,.2f}/mo",
        )

    return SavingsEstimate(
        monthly_savings=0.0,
        confidence="low",
        calculation_method="deterministic",
        assumptions=[
            f"Upgrade from {instance_type} to {new_type} recommended",
            "Could not retrieve pricing — savings amount is approximate",
        ],
        formula=f"Pricing unavailable for {instance_type} -> {new_type}",
    )


def calc_multi_az_rds(rds: dict, pricing: PricingProvider) -> SavingsEstimate:
    instance_class = rds.get("db_instance_class", "")
    engine = rds.get("engine", "")

    ce_cost = _get_cost_explorer_cost(rds)
    if ce_cost is not None:
        savings = round(ce_cost * 0.5, 2)
        return SavingsEstimate(
            monthly_savings=savings,
            confidence="medium",
            calculation_method="cost_explorer",
            assumptions=[
                "Workload does not require Multi-AZ high availability",
                "Multi-AZ approximately doubles the instance cost",
            ],
            current_monthly_cost=ce_cost,
            formula=f"${ce_cost:,.2f}/mo actual spend x 50% (Multi-AZ premium) = ${savings:,.2f}/mo",
        )

    multi_az_price = pricing.get_rds_hourly_price(instance_class, engine, True)
    single_az_price = pricing.get_rds_hourly_price(instance_class, engine, False)

    if multi_az_price is not None and single_az_price is not None:
        savings = round((multi_az_price - single_az_price) * HOURS_PER_MONTH, 2)
        return SavingsEstimate(
            monthly_savings=savings,
            confidence="medium",
            calculation_method="deterministic",
            assumptions=[
                "Workload does not require Multi-AZ high availability",
                "This is a non-production or non-critical database",
            ],
            current_monthly_cost=round(multi_az_price * HOURS_PER_MONTH, 2),
            formula=f"({instance_class} Multi-AZ ${multi_az_price}/hr - Single-AZ ${single_az_price}/hr) x {HOURS_PER_MONTH} hrs = ${savings:,.2f}/mo",
        )

    return SavingsEstimate(
        monthly_savings=0.0,
        confidence="low",
        calculation_method="deterministic",
        assumptions=[
            "Multi-AZ adds ~100% cost premium",
            "Could not retrieve exact pricing",
        ],
        formula=f"Pricing unavailable for {instance_class} {engine}",
    )


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def detect_and_price_issues(resources: dict, region: str) -> list[dict]:
    """Run all deterministic issue detectors across scanned resources.

    Returns a list of pre-priced issue dicts ready to be sent to the LLM
    for explanation and fix command generation.
    """
    pricing = PricingProvider(region)
    issues: list[dict] = []

    # --- EBS: unattached volumes ---
    for vol in resources.get("ebs_volumes", []):
        if not vol.get("attached"):
            est = calc_unattached_ebs(vol, pricing)
            issues.append(_build_issue(vol, "volume_id", "ebs", "unused", est))

    # --- EBS: gp2 -> gp3 migration ---
    for vol in resources.get("ebs_volumes", []):
        if vol.get("volume_type") == "gp2" and vol.get("attached"):
            est = calc_gp2_to_gp3(vol, pricing)
            issues.append(_build_issue(vol, "volume_id", "ebs", "old_generation", est))

    # --- Elastic IPs: unassociated ---
    for eip in resources.get("elastic_ips", []):
        if not eip.get("associated"):
            est = calc_unassociated_eip(eip, pricing)
            issues.append(_build_issue(
                eip, "allocation_id", "eip", "unused", est,
                resource_name=eip.get("public_ip", ""),
            ))

    # --- NAT Gateways: zero traffic ---
    for nat in resources.get("nat_gateways", []):
        if nat.get("bytes_out_7d") == 0:
            est = calc_idle_nat_gateway(nat, pricing)
            issues.append(_build_issue(nat, "nat_gateway_id", "nat_gateway", "unused", est))

    # --- Load Balancers: no healthy targets ---
    for lb in resources.get("load_balancers", []):
        if not lb.get("has_healthy_targets"):
            est = calc_idle_load_balancer(lb, pricing)
            issues.append(_build_issue(lb, "name", "elb", "unused", est,
                                       resource_name=lb.get("name", "")))

    # --- Lambda: zero invocations ---
    for fn in resources.get("lambda_functions", []):
        if fn.get("invocations_last_30d") == 0:
            est = calc_zero_invocation_lambda(fn, pricing)
            issues.append(_build_issue(
                fn, "function_name", "lambda", "unused", est,
                resource_name=fn.get("function_name", ""),
            ))

    # --- EC2: stopped instances (still paying for EBS) ---
    ebs_by_instance = _map_ebs_to_instances(resources.get("ebs_volumes", []))
    for inst in resources.get("ec2_instances", []):
        if inst.get("state") == "stopped":
            attached_vols = ebs_by_instance.get(inst["instance_id"], [])
            est = calc_stopped_ec2_ebs(inst, attached_vols, pricing)
            issues.append(_build_issue(inst, "instance_id", "ec2", "unused", est))

    # --- EC2: old generation instances ---
    for inst in resources.get("ec2_instances", []):
        if inst.get("state") == "running":
            family = _instance_family(inst.get("instance_type", ""))
            if family in OLD_GEN_MAP:
                est = calc_old_gen_instance(inst, pricing)
                if est.monthly_savings > 0 or est.confidence != "low":
                    issues.append(_build_issue(inst, "instance_id", "ec2", "old_generation", est))

    # --- RDS: Multi-AZ (flag for review) ---
    for rds in resources.get("rds_instances", []):
        if rds.get("multi_az"):
            est = calc_multi_az_rds(rds, pricing)
            issues.append(_build_issue(
                rds, "db_instance_id", "rds", "over_provisioned", est,
                resource_name=rds.get("db_instance_id", ""),
            ))

    logger.info(
        "Pricing engine detected %d issues (deterministic) for region %s",
        len(issues), region,
    )
    return issues


def _map_ebs_to_instances(ebs_volumes: list[dict]) -> dict[str, list[dict]]:
    """Group EBS volumes by their attached EC2 instance ID."""
    mapping: dict[str, list[dict]] = {}
    for vol in ebs_volumes:
        instance_id = vol.get("attached_instance_id")
        if instance_id:
            mapping.setdefault(instance_id, []).append(vol)
    return mapping
