import asyncio
import json
import logging
import os

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Supported providers and their default models
# ---------------------------------------------------------------------------
PROVIDER_DEFAULTS = {
    "groq": "openai/gpt-oss-120b",
    "openai": "gpt-4o-mini",
    "anthropic": "claude-3-5-haiku-20241022",
    "gemini": "gemini-2.5-flash",
}

# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = """\
You are an AWS cost optimization expert. You analyze AWS resource inventories \
and validate pre-calculated cost savings. You respond ONLY with valid JSON \
matching the schema provided — no markdown fences, no commentary outside the \
JSON object.

CRITICAL RULES FOR SAVINGS AMOUNTS:
- For pre-calculated issues (those with a "resource_id" in the pre-calculated \
list), you MUST keep the provided "estimated_monthly_savings" value exactly. \
Do NOT change it.
- You MAY add NEW issues not in the pre-calculated list. For these, tag them \
with "calculation_method": "llm_estimated" and "confidence": "low".
- For new issues you add, base your savings estimates on AWS public pricing \
and be conservative.

When actual AWS Cost Explorer data is provided, reference those real costs \
in your explanations. Clearly distinguish between resources with known costs \
and those where cost is estimated.

Your primary job is to:
1. Write clear, specific explanations for each issue
2. Generate safe, copy-paste-ready AWS CLI fix commands
3. Assign severity levels based on the savings amount and risk\
"""

USER_PROMPT_TEMPLATE = """\
Region: {region}

Below is a JSON inventory of AWS resources currently deployed in this region.

Resource inventory:
{resources_json}

{cost_data_section}

=== Pre-calculated Issues (verified savings) ===
The following issues have been detected by automated rules with deterministic \
savings calculations. For each issue below, you MUST:
1. Keep resource_id, resource_type, estimated_monthly_savings, actual_monthly_cost, \
confidence, calculation_method, assumptions, and savings_formula EXACTLY as provided
2. Write a clear "explanation" describing the problem and its cost impact
3. Generate a safe "fix_command" with --region {region}
4. Set "severity" based on the severity rules below

{precalculated_issues_json}

=== Additional Issues to Find ===
Beyond the pre-calculated issues above, analyze every resource for these \
additional cost issues that rules cannot easily detect:
1. **Over-provisioning** — instance types, memory, storage, or IOPS larger \
than the workload needs
2. **Misconfigurations** — publicly accessible RDS, missing S3 lifecycle \
rules, versioning enabled without old-version expiry
3. **General cost optimization** — any other actionable opportunity

For any NEW issues you identify (not in the pre-calculated list), set \
"calculation_method": "llm_estimated" and "confidence": "low", and include \
"assumptions": ["Savings estimated by AI based on public pricing"].

Return a JSON object with this exact structure:
{{
  "summary": "One-paragraph executive summary of findings",
  "issues": [
    {{
      "resource_id": "i-0abc123...",
      "resource_type": "ec2",
      "resource_name": "my-server",
      "issue_type": "unused | over_provisioned | misconfigured | old_generation",
      "severity": "high | medium | low",
      "explanation": "Clear explanation of the problem and its cost impact",
      "estimated_monthly_savings": "$X",
      "actual_monthly_cost": "$Y or null",
      "fix_command": "aws ec2 ... --region {region}",
      "confidence": "high | medium | low",
      "calculation_method": "deterministic | cost_explorer | llm_estimated",
      "assumptions": ["assumption 1", "assumption 2"],
      "savings_formula": "formula string or null"
    }}
  ]
}}

Severity rules:
- **high**: potential savings > $50/month, or a security risk (e.g. public RDS)
- **medium**: savings between $10–$50/month
- **low**: savings < $10/month, or a best-practice violation with minimal \
direct cost

Fix command rules:
- Always include the --region flag set to {region}
- Use the safest effective command (prefer modify over terminate where possible)
- Common patterns:
  * gp2 -> gp3: aws ec2 modify-volume --volume-id vol-xxx --volume-type gp3 --region {region}
  * Unattached EIP: aws ec2 release-address --allocation-id eipalloc-xxx --region {region}
  * Unattached EBS: aws ec2 delete-volume --volume-id vol-xxx --region {region}
  * Stopped EC2 (with snapshot first): aws ec2 create-image --instance-id i-xxx \
--name backup --region {region} && aws ec2 terminate-instances --instance-ids i-xxx --region {region}
  * Lambda memory: aws lambda update-function-configuration --function-name xxx --memory-size 256 --region {region}

If no additional issues are found beyond the pre-calculated ones, include \
only the pre-calculated issues with explanations added. \
Do NOT wrap the JSON in markdown code fences. Return raw JSON only.\
"""

MAX_RESOURCE_PAYLOAD_CHARS = 60_000


# ---------------------------------------------------------------------------
# Provider adapters — each returns raw JSON text
# ---------------------------------------------------------------------------


async def _complete_groq(system: str, user: str, api_key: str, model: str) -> str:
    try:
        from groq import AsyncGroq
    except ImportError as err:
        raise RuntimeError("groq package not installed. Run: pip install groq") from err

    client = AsyncGroq(api_key=api_key)
    response = await client.chat.completions.create(
        model=model,
        messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
        temperature=0.2,
        max_tokens=4096,
        response_format={"type": "json_object"},
    )
    return response.choices[0].message.content


async def _complete_openai(system: str, user: str, api_key: str, model: str) -> str:
    try:
        from openai import AsyncOpenAI
    except ImportError as err:
        raise RuntimeError("openai package not installed. Run: pip install openai") from err

    client = AsyncOpenAI(api_key=api_key)
    response = await client.chat.completions.create(
        model=model,
        messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
        temperature=0.2,
        max_tokens=4096,
        response_format={"type": "json_object"},
    )
    return response.choices[0].message.content


async def _complete_anthropic(system: str, user: str, api_key: str, model: str) -> str:
    try:
        import anthropic
    except ImportError as err:
        raise RuntimeError("anthropic package not installed. Run: pip install anthropic") from err

    client = anthropic.AsyncAnthropic(api_key=api_key)
    response = await client.messages.create(
        model=model,
        system=system,
        messages=[{"role": "user", "content": user}],
        temperature=0.2,
        max_tokens=4096,
    )
    return response.content[0].text


async def _complete_gemini(system: str, user: str, api_key: str, model: str) -> str:
    try:
        import google.generativeai as genai
    except ImportError as err:
        raise RuntimeError("google-generativeai package not installed. Run: pip install google-generativeai") from err

    genai.configure(api_key=api_key)
    llm = genai.GenerativeModel(
        model_name=model,
        system_instruction=system,
        generation_config=genai.types.GenerationConfig(
            temperature=0.2,
            max_output_tokens=4096,
            response_mime_type="application/json",
        ),
    )
    response = await llm.generate_content_async(user)
    return response.text


PROVIDER_ADAPTERS = {
    "groq": _complete_groq,
    "openai": _complete_openai,
    "anthropic": _complete_anthropic,
    "gemini": _complete_gemini,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _prepare_resources_payload(resources: dict[str, list[dict]]) -> str:
    trimmed = {svc: items for svc, items in resources.items() if items}
    payload = json.dumps(trimmed, indent=2, default=str)

    if len(payload) <= MAX_RESOURCE_PAYLOAD_CHARS:
        return payload

    caps = {
        "ec2_instances": 80,
        "rds_instances": 40,
        "s3_buckets": 40,
        "ebs_volumes": 60,
        "elastic_ips": 30,
        "load_balancers": 30,
        "lambda_functions": 40,
        "nat_gateways": 20,
    }
    for svc, items in trimmed.items():
        cap = caps.get(svc, 30)
        if len(items) > cap:
            trimmed[svc] = items[:cap]

    payload = json.dumps(trimmed, indent=2, default=str)
    logger.info("Resource payload trimmed to %d chars (%d services)", len(payload), len(trimmed))
    return payload


def _build_cost_data_section(cost_data: dict | None) -> str:
    """Build the cost data prompt section from Cost Explorer data."""
    if not cost_data or not cost_data.get("available"):
        return (
            "Note: AWS Cost Explorer data is not available for this account. "
            "For any NEW issues you add beyond the pre-calculated list, "
            "base your cost estimates on AWS public pricing. "
            "Set actual_monthly_cost to null for new issues."
        )

    total_costs = cost_data.get("total_monthly_cost", [])
    breakdown = cost_data.get("service_breakdown", {})

    total_str = ", ".join(f'{m["month"]}: ${m["amount"]:,.2f}' for m in total_costs)
    breakdown_str = "\n".join(f"  - {svc}: ${amt:,.2f}" for svc, amt in sorted(breakdown.items(), key=lambda x: -x[1]))

    lines = [
        "=== Actual AWS Cost Explorer Data (last 3 months) ===",
        f"Total monthly spend: {total_str}",
        f"Service breakdown (most recent month):\n{breakdown_str}",
        "",
        'Individual resources in the inventory above include a "cost_info" field with '
        "their actual monthly costs and trend. Reference these real costs in your "
        "explanations where relevant.",
    ]
    return "\n".join(lines)


def _auto_severity(monthly_savings: float) -> str:
    """Assign severity based on savings thresholds."""
    if monthly_savings > 50:
        return "high"
    if monthly_savings >= 10:
        return "medium"
    return "low"


def _merge_issues(precalculated: list[dict], llm_issues: list[dict]) -> list[dict]:
    """Merge LLM-generated fields with pre-calculated savings.

    For deterministic issues: keep savings/confidence/assumptions from pricing
    engine, take explanation/fix_command/severity from LLM.
    For LLM-only issues: take everything from LLM but tag as llm_estimated.
    Any pre-calculated issues the LLM missed: include with auto-generated severity.
    """
    precalc_by_id = {i["resource_id"]: dict(i) for i in precalculated}
    merged = []
    seen_ids = set()

    for llm_issue in llm_issues:
        rid = llm_issue.get("resource_id", "")
        if rid in precalc_by_id:
            # Deterministic issue — enforce pre-calculated savings
            base = precalc_by_id[rid]
            base["explanation"] = llm_issue.get("explanation", base.get("explanation", ""))
            base["fix_command"] = llm_issue.get("fix_command", base.get("fix_command", ""))
            base["severity"] = llm_issue.get("severity", base.get("severity", "medium"))
            # Keep resource_name from LLM if it's better
            if llm_issue.get("resource_name") and not base.get("resource_name"):
                base["resource_name"] = llm_issue["resource_name"]
            merged.append(base)
            seen_ids.add(rid)
        else:
            # LLM-discovered issue — tag appropriately
            llm_issue.setdefault("calculation_method", "llm_estimated")
            llm_issue.setdefault("confidence", "low")
            llm_issue.setdefault("assumptions", ["Savings estimated by AI based on public pricing"])
            llm_issue.setdefault("savings_formula", None)
            merged.append(llm_issue)

    # Include any pre-calculated issues the LLM missed
    for rid, issue in precalc_by_id.items():
        if rid not in seen_ids:
            if not issue.get("explanation"):
                issue["explanation"] = "Identified by automated cost analysis."
            if not issue.get("severity"):
                # Parse savings amount for auto-severity
                savings_str = issue.get("estimated_monthly_savings", "$0")
                try:
                    amount = float(savings_str.replace("$", "").replace(",", "").replace("/mo", ""))
                except ValueError:
                    amount = 0
                issue["severity"] = _auto_severity(amount)
            merged.append(issue)

    return merged


def _compute_total_savings(issues: list[dict]) -> str:
    """Sum all estimated_monthly_savings from merged issues."""
    total = 0.0
    for issue in issues:
        savings_str = issue.get("estimated_monthly_savings", "$0")
        try:
            amount = float(savings_str.replace("$", "").replace(",", "").replace("/mo", ""))
        except ValueError:
            continue
        total += amount
    return f"${total:,.2f}/month"


def _parse_response(raw_text: str, region: str, total_resources: int, precalculated: list[dict] | None) -> dict:
    text = raw_text.strip()
    if text.startswith("```"):
        first_newline = text.index("\n")
        last_fence = text.rfind("```")
        text = text[first_newline + 1 : last_fence].strip()

    data = json.loads(text)
    llm_issues = [
        {
            "resource_id": item.get("resource_id", ""),
            "resource_type": item.get("resource_type", ""),
            "resource_name": item.get("resource_name", ""),
            "issue_type": item.get("issue_type", ""),
            "severity": item.get("severity", "low"),
            "explanation": item.get("explanation", ""),
            "estimated_monthly_savings": item.get("estimated_monthly_savings", "$0"),
            "fix_command": item.get("fix_command", ""),
            "actual_monthly_cost": item.get("actual_monthly_cost"),
            "confidence": item.get("confidence", "low"),
            "calculation_method": item.get("calculation_method", "llm_estimated"),
            "assumptions": item.get("assumptions", []),
            "savings_formula": item.get("savings_formula"),
        }
        for item in data.get("issues", [])
    ]

    # Merge with pre-calculated issues (enforces deterministic savings)
    if precalculated:
        merged_issues = _merge_issues(precalculated, llm_issues)
    else:
        # No pre-calculated issues — tag all as llm_estimated
        for issue in llm_issues:
            issue.setdefault("calculation_method", "llm_estimated")
            issue.setdefault("confidence", "low")
            issue.setdefault("assumptions", ["Savings estimated by AI based on public pricing"])
            issue.setdefault("savings_formula", None)
        merged_issues = llm_issues

    # Recompute total from merged issues (never trust LLM's total)
    estimated_total_savings = _compute_total_savings(merged_issues)

    return {
        "region": region,
        "resources_scanned": total_resources,
        "issues_found": len(merged_issues),
        "estimated_total_savings": estimated_total_savings,
        "summary": data.get("summary", "No summary provided."),
        "issues": merged_issues,
    }


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def analyze_aws_resources(
    region: str,
    resources: dict[str, list[dict]],
    cost_data: dict | None = None,
    precalculated_issues: list[dict] | None = None,
) -> dict:
    """Analyze scanned AWS resources using the configured LLM provider.

    Pre-calculated issues from the pricing engine are passed to the LLM for
    explanation and fix command generation. The LLM may also identify additional
    issues. Deterministic savings values are enforced and cannot be overridden.

    Provider is selected via LLM_PROVIDER env var (groq | openai | anthropic | gemini).
    API key is read from LLM_API_KEY. Model can be overridden with LLM_MODEL.
    """
    provider = os.getenv("LLM_PROVIDER", "groq").lower()
    api_key = os.getenv("LLM_API_KEY")
    model = os.getenv("LLM_MODEL") or PROVIDER_DEFAULTS.get(provider)

    if provider not in PROVIDER_ADAPTERS:
        supported = ", ".join(PROVIDER_ADAPTERS)
        raise RuntimeError(f"Unknown LLM_PROVIDER '{provider}'. Supported: {supported}")

    if not api_key:
        raise RuntimeError("LLM_API_KEY not set. Add it to your .env file.")

    total_resources = sum(len(v) for v in resources.values())
    if total_resources == 0:
        return {
            "region": region,
            "resources_scanned": 0,
            "issues_found": 0,
            "estimated_total_savings": "$0/month",
            "summary": "No resources found in this region.",
            "issues": [],
        }

    resources_json = _prepare_resources_payload(resources)
    cost_section = _build_cost_data_section(cost_data)

    # Format pre-calculated issues for the prompt
    if precalculated_issues:
        precalc_json = json.dumps(precalculated_issues, indent=2)
    else:
        precalc_json = "No pre-calculated issues. Analyze all resources from scratch."

    user_prompt = USER_PROMPT_TEMPLATE.format(
        region=region,
        resources_json=resources_json,
        cost_data_section=cost_section,
        precalculated_issues_json=precalc_json,
    )
    adapter = PROVIDER_ADAPTERS[provider]

    logger.info(
        "Running AI analysis via provider=%s model=%s (%d precalculated issues)",
        provider,
        model,
        len(precalculated_issues or []),
    )

    try:
        raw_text = await asyncio.wait_for(
            adapter(SYSTEM_PROMPT, user_prompt, api_key, model),
            timeout=120,
        )
    except TimeoutError as err:
        raise RuntimeError(f"{provider} API call timed out after 120s. Try again shortly.") from err
    except Exception as e:
        logger.error("%s API error: %s", provider, e)
        raise RuntimeError(f"{provider} API error: {e}") from e

    if not raw_text:
        raise RuntimeError(f"{provider} returned an empty response.")

    try:
        result = _parse_response(raw_text, region, total_resources, precalculated_issues)
    except (json.JSONDecodeError, KeyError, IndexError) as e:
        logger.error("Failed to parse %s response: %s\nRaw: %s", provider, e, raw_text[:500])
        raise RuntimeError(f"{provider} returned an invalid response. Try running the analysis again.") from e

    # Attach cost summary from Cost Explorer data.
    if cost_data and cost_data.get("available"):
        totals = cost_data.get("total_monthly_cost", [])
        current = totals[-1]["amount"] if totals else 0
        result["cost_summary"] = {
            "available": True,
            "total_monthly_cost": totals,
            "service_breakdown": cost_data.get("service_breakdown", {}),
        }
        result["actual_total_monthly_cost"] = f"${current:,.2f}/month"
    else:
        result["cost_summary"] = {
            "available": False,
            "total_monthly_cost": [],
            "service_breakdown": {},
            "error": cost_data.get("error", "Cost Explorer not available") if cost_data else None,
        }
        result["actual_total_monthly_cost"] = None

    return result
