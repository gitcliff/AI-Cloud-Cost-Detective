import json
import logging
import os

from openai import AsyncOpenAI, APIConnectionError, RateLimitError, APIStatusError

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You are an AWS cost optimization expert. You analyze AWS resource inventories \
and identify cost inefficiencies. You respond ONLY with valid JSON matching the \
schema provided — no markdown fences, no commentary outside the JSON object.

Be specific: include exact resource IDs, concrete cost estimates based on \
current AWS public pricing, and copy-paste-ready AWS CLI commands that the \
user can run to fix each issue.\
"""

USER_PROMPT_TEMPLATE = """\
Region: {region}

Below is a JSON inventory of AWS resources currently deployed in this region.
Analyze every resource for the following cost issues:

1. **Over-provisioning** — instance types, memory, storage, or IOPS larger \
than the workload needs.
2. **Unused / idle resources** — stopped EC2 instances still paying for EBS, \
unattached EBS volumes, unassociated Elastic IPs, load balancers with no \
healthy targets, Lambda functions with zero invocations, NAT Gateways with \
zero traffic.
3. **Misconfigurations** — publicly accessible RDS, missing S3 lifecycle \
rules, versioning enabled without old-version expiry.
4. **Wrong pricing tiers / old generations** — gp2 volumes (should be gp3), \
old-gen instance families (t2/m3/c3/r3), Multi-AZ RDS for non-production \
workloads.
5. **General cost optimization** — any other actionable opportunity to reduce \
monthly spend.

Resource inventory:
{resources_json}

Return a JSON object with this exact structure:
{{
  "summary": "One-paragraph executive summary of findings",
  "estimated_total_savings": "$X/month",
  "issues": [
    {{
      "resource_id": "i-0abc123...",
      "resource_type": "ec2",
      "resource_name": "my-server",
      "issue_type": "unused | over_provisioned | misconfigured | old_generation",
      "severity": "high | medium | low",
      "explanation": "Clear explanation of the problem and its cost impact",
      "estimated_monthly_savings": "$X",
      "fix_command": "aws ec2 ... --region {region}"
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
  * gp2 → gp3: aws ec2 modify-volume --volume-id vol-xxx --volume-type gp3 --region {region}
  * Unattached EIP: aws ec2 release-address --allocation-id eipalloc-xxx --region {region}
  * Unattached EBS: aws ec2 delete-volume --volume-id vol-xxx --region {region}
  * Stopped EC2 (with snapshot first): aws ec2 create-image --instance-id i-xxx --name backup --region {region} && aws ec2 terminate-instances --instance-ids i-xxx --region {region}
  * Lambda memory: aws lambda update-function-configuration --function-name xxx --memory-size 256 --region {region}

If no issues are found, return an empty issues array with an appropriate summary.
Do NOT wrap the JSON in markdown code fences. Return raw JSON only.\
"""

# Maximum characters of serialized resources to send to OpenAI.
# GPT-4o supports ~128k tokens; we stay well under to leave room for response.
MAX_RESOURCE_PAYLOAD_CHARS = 60_000


def _prepare_resources_payload(resources: dict[str, list[dict]]) -> str:
    """Serialize resources to JSON, trimming if necessary to stay within token budget."""
    # Strip down to essentials — remove verbose fields per service
    trimmed = {}
    for service, items in resources.items():
        if not items:
            continue
        trimmed[service] = items

    payload = json.dumps(trimmed, indent=2, default=str)

    if len(payload) <= MAX_RESOURCE_PAYLOAD_CHARS:
        return payload

    # If too large, reduce by capping per-service item counts
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
    for service, items in trimmed.items():
        cap = caps.get(service, 30)
        if len(items) > cap:
            trimmed[service] = items[:cap]

    payload = json.dumps(trimmed, indent=2, default=str)
    logger.info(
        "Resource payload trimmed to %d chars (%d services)",
        len(payload),
        len(trimmed),
    )
    return payload


def _parse_response(raw_text: str, region: str, total_resources: int) -> dict:
    """Parse the OpenAI response text into a validated analysis dict."""
    # Strip markdown fences if the model wraps them despite instructions
    text = raw_text.strip()
    if text.startswith("```"):
        first_newline = text.index("\n")
        last_fence = text.rfind("```")
        text = text[first_newline + 1 : last_fence].strip()

    data = json.loads(text)

    issues = []
    for item in data.get("issues", []):
        issues.append({
            "resource_id": item.get("resource_id", ""),
            "resource_type": item.get("resource_type", ""),
            "resource_name": item.get("resource_name", ""),
            "issue_type": item.get("issue_type", ""),
            "severity": item.get("severity", "low"),
            "explanation": item.get("explanation", ""),
            "estimated_monthly_savings": item.get("estimated_monthly_savings", "$0"),
            "fix_command": item.get("fix_command", ""),
        })

    return {
        "region": region,
        "resources_scanned": total_resources,
        "issues_found": len(issues),
        "estimated_total_savings": data.get("estimated_total_savings", "$0/month"),
        "summary": data.get("summary", "No summary provided."),
        "issues": issues,
    }


async def analyze_aws_resources(
    region: str,
    resources: dict[str, list[dict]],
) -> dict:
    """Send scanned AWS resources to OpenAI GPT-4o for cost analysis.

    Returns a dict matching the AnalysisResult schema (minus analysis_id
    and created_at, which are added by the caller / database layer).

    Raises:
        RuntimeError: If the OpenAI API call fails after exhausting retries.
    """
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "OPENAI_API_KEY not set. Add it to your .env file."
        )

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
    user_prompt = USER_PROMPT_TEMPLATE.format(
        region=region,
        resources_json=resources_json,
    )

    client = AsyncOpenAI(api_key=api_key)

    try:
        response = await client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.2,
            max_tokens=4096,
            response_format={"type": "json_object"},
        )
    except APIConnectionError as e:
        logger.error("OpenAI connection error: %s", e)
        raise RuntimeError("Failed to connect to OpenAI API. Check your network.") from e
    except RateLimitError as e:
        logger.error("OpenAI rate limit: %s", e)
        raise RuntimeError("OpenAI rate limit exceeded. Try again shortly.") from e
    except APIStatusError as e:
        logger.error("OpenAI API error %d: %s", e.status_code, e.message)
        raise RuntimeError(f"OpenAI API error: {e.message}") from e

    raw_text = response.choices[0].message.content
    if not raw_text:
        raise RuntimeError("OpenAI returned an empty response.")

    try:
        return _parse_response(raw_text, region, total_resources)
    except (json.JSONDecodeError, KeyError, IndexError) as e:
        logger.error("Failed to parse OpenAI response: %s\nRaw: %s", e, raw_text[:500])
        raise RuntimeError(
            "OpenAI returned an invalid response. Try running the analysis again."
        ) from e
