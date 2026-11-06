"""AWS Cost Explorer integration — fetches actual cost data for a region."""

import copy
import logging
from datetime import UTC, datetime, timedelta

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

logger = logging.getLogger(__name__)

# Maps AWS Cost Explorer service names to scanner resource keys.
SERVICE_MAP = {
    "Amazon Elastic Compute Cloud - Compute": "ec2_instances",
    "Amazon Relational Database Service": "rds_instances",
    "Amazon Simple Storage Service": "s3_buckets",
    "Amazon Elastic Block Store": "ebs_volumes",
    "Elastic Load Balancing": "load_balancers",
    "AWS Lambda": "lambda_functions",
    "Amazon Virtual Private Cloud": "nat_gateways",
    "EC2 - Other": "elastic_ips",
}

# Resource ID field name per scanner key.
RESOURCE_ID_FIELD = {
    "ec2_instances": "instance_id",
    "rds_instances": "db_instance_id",
    "s3_buckets": "bucket_name",
    "ebs_volumes": "volume_id",
    "elastic_ips": "allocation_id",
    "load_balancers": "arn",
    "lambda_functions": "function_name",
    "nat_gateways": "nat_gateway_id",
}


def _month_periods(months: int = 3) -> tuple[str, str]:
    """Return (start, end) date strings spanning the last *months* full months
    plus the current partial month."""
    today = datetime.now(UTC).date()
    start = (today.replace(day=1) - timedelta(days=months * 30)).replace(day=1)
    # End is the first day of the next month (exclusive upper bound for CE API).
    if today.month == 12:
        end = today.replace(year=today.year + 1, month=1, day=1)
    else:
        end = today.replace(month=today.month + 1, day=1)
    return start.isoformat(), end.isoformat()


def _parse_ce_groups(result_by_time: list[dict], group_key_index: int = 0) -> dict:
    """Parse Cost Explorer ResultsByTime into {key: [{month, amount}, ...]}."""
    out: dict[str, list[dict]] = {}
    for period in result_by_time:
        month = period["TimePeriod"]["Start"][:7]  # e.g. "2026-09"
        for group in period.get("Groups", []):
            key = group["Keys"][group_key_index]
            amount = float(group["Metrics"]["UnblendedCost"]["Amount"])
            if amount == 0:
                continue
            out.setdefault(key, []).append({"month": month, "amount": round(amount, 2)})
    return out


def _compute_totals(result_by_time: list[dict]) -> list[dict]:
    """Compute total cost per month from ResultsByTime."""
    totals = []
    for period in result_by_time:
        month = period["TimePeriod"]["Start"][:7]
        total = float(period.get("Total", {}).get("UnblendedCost", {}).get("Amount", 0))
        # If grouped, Total is empty — sum groups instead.
        if total == 0:
            for group in period.get("Groups", []):
                total += float(group["Metrics"]["UnblendedCost"]["Amount"])
        totals.append({"month": month, "amount": round(total, 2)})
    return totals


def fetch_cost_data(region: str, months: int = 3) -> dict:
    """Fetch actual cost data from AWS Cost Explorer for a specific region.

    Makes at most 2 API calls ($0.02 total). Returns a dict with:
      - available (bool): whether cost data was retrieved
      - service_costs: per-service monthly costs
      - resource_costs: per-resource monthly costs (best-effort)
      - total_monthly_cost: total per-month costs
      - error (str, optional): reason if unavailable

    Never raises — returns {"available": False, "error": "..."} on failure.
    """
    try:
        # Cost Explorer is a global service; always use us-east-1.
        session = boto3.Session(region_name="us-east-1")
        ce = session.client("ce")

        start, end = _month_periods(months)
        time_period = {"Start": start, "End": end}

        region_filter = {
            "Dimensions": {
                "Key": "REGION",
                "Values": [region],
            }
        }

        # --- Call 1: costs grouped by SERVICE ---
        svc_response = ce.get_cost_and_usage(
            TimePeriod=time_period,
            Granularity="MONTHLY",
            Metrics=["UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
            Filter=region_filter,
        )
        service_costs = _parse_ce_groups(svc_response["ResultsByTime"])
        total_monthly_cost = _compute_totals(svc_response["ResultsByTime"])

        # --- Call 2: costs grouped by RESOURCE_ID (best-effort) ---
        resource_costs: dict = {}
        try:
            res_response = ce.get_cost_and_usage(
                TimePeriod=time_period,
                Granularity="MONTHLY",
                Metrics=["UnblendedCost"],
                GroupBy=[{"Type": "DIMENSION", "Key": "RESOURCE_ID"}],
                Filter=region_filter,
            )
            resource_costs = _parse_ce_groups(res_response["ResultsByTime"])
        except ClientError as e:
            code = e.response["Error"]["Code"]
            logger.warning("Resource-level cost data unavailable (%s): %s", code, e)

        # Build service breakdown for the most recent month.
        service_breakdown: dict[str, float] = {}
        for svc, months_data in service_costs.items():
            if months_data:
                service_breakdown[svc] = months_data[-1]["amount"]

        return {
            "available": True,
            "period": {"start": start, "end": end},
            "service_costs": service_costs,
            "resource_costs": resource_costs,
            "total_monthly_cost": total_monthly_cost,
            "service_breakdown": service_breakdown,
        }

    except (ClientError, NoCredentialsError) as e:
        error_msg = str(e)
        if "AccessDenied" in error_msg:
            error_msg = "Missing ce:GetCostAndUsage IAM permission."
        elif "OptInRequired" in error_msg:
            error_msg = "AWS Cost Explorer is not enabled for this account."
        logger.warning("Cost Explorer unavailable: %s", error_msg)
        return {"available": False, "error": error_msg}
    except Exception as e:
        logger.warning("Cost Explorer unexpected error: %s", e)
        return {"available": False, "error": str(e)}


def _compute_trend(monthly_costs: list[dict]) -> tuple[str, float]:
    """Compute trend direction and percentage from monthly cost list."""
    if len(monthly_costs) < 2:
        return "stable", 0.0
    prev = monthly_costs[-2]["amount"]
    curr = monthly_costs[-1]["amount"]
    if prev == 0:
        return ("increasing", 100.0) if curr > 0 else ("stable", 0.0)
    pct = round(((curr - prev) / prev) * 100, 1)
    if pct > 5:
        return "increasing", pct
    elif pct < -5:
        return "decreasing", pct
    return "stable", pct


def merge_costs_with_resources(resources: dict, cost_data: dict) -> dict:
    """Enrich each resource dict with a cost_info key using Cost Explorer data.

    Tries resource-level matching first; falls back to distributing service-level
    costs evenly across resources of that type.

    Returns a new dict (does not mutate the original).
    """
    if not cost_data.get("available"):
        return resources

    enriched = copy.deepcopy(resources)
    resource_costs = cost_data.get("resource_costs", {})
    service_costs = cost_data.get("service_costs", {})

    for ce_service, scanner_key in SERVICE_MAP.items():
        items = enriched.get(scanner_key, [])
        if not items:
            continue

        id_field = RESOURCE_ID_FIELD.get(scanner_key, "")
        svc_months = service_costs.get(ce_service, [])

        for item in items:
            resource_id = item.get(id_field, "")

            # Try direct resource-level match.
            res_months = resource_costs.get(resource_id, [])
            if res_months:
                current = res_months[-1]["amount"] if res_months else 0
                trend, trend_pct = _compute_trend(res_months)
                item["cost_info"] = {
                    "monthly_costs": res_months,
                    "current_month_cost": current,
                    "trend": trend,
                    "trend_pct": trend_pct,
                    "cost_source": "resource_level",
                }
                continue

            # Fallback: distribute service-level cost evenly.
            if svc_months and len(items) > 0:
                distributed = [{"month": m["month"], "amount": round(m["amount"] / len(items), 2)} for m in svc_months]
                current = distributed[-1]["amount"] if distributed else 0
                trend, trend_pct = _compute_trend(distributed)
                item["cost_info"] = {
                    "monthly_costs": distributed,
                    "current_month_cost": current,
                    "trend": trend,
                    "trend_pct": trend_pct,
                    "cost_source": "estimated_from_service_total",
                }

    return enriched
