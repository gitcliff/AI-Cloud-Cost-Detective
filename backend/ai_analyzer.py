import asyncio
import json
import logging
import os

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Supported providers and their default models
# ---------------------------------------------------------------------------
PROVIDER_DEFAULTS = {
    "groq":      "openai/gpt-oss-120b",
    "openai":    "gpt-4o-mini",
    "anthropic": "claude-3-5-haiku-20241022",
    "gemini":    "gemini-2.5-flash",
}

# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------
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

MAX_RESOURCE_PAYLOAD_CHARS = 60_000


# ---------------------------------------------------------------------------
# Provider adapters — each returns raw JSON text
# ---------------------------------------------------------------------------

async def _complete_groq(system: str, user: str, api_key: str, model: str) -> str:
    try:
        from groq import AsyncGroq
    except ImportError:
        raise RuntimeError("groq package not installed. Run: pip install groq")

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
    except ImportError:
        raise RuntimeError("openai package not installed. Run: pip install openai")

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
    except ImportError:
        raise RuntimeError("anthropic package not installed. Run: pip install anthropic")

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
    except ImportError:
        raise RuntimeError("google-generativeai package not installed. Run: pip install google-generativeai")

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
    "groq":      _complete_groq,
    "openai":    _complete_openai,
    "anthropic": _complete_anthropic,
    "gemini":    _complete_gemini,
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
        "ec2_instances": 80, "rds_instances": 40, "s3_buckets": 40,
        "ebs_volumes": 60, "elastic_ips": 30, "load_balancers": 30,
        "lambda_functions": 40, "nat_gateways": 20,
    }
    for svc, items in trimmed.items():
        cap = caps.get(svc, 30)
        if len(items) > cap:
            trimmed[svc] = items[:cap]

    payload = json.dumps(trimmed, indent=2, default=str)
    logger.info("Resource payload trimmed to %d chars (%d services)", len(payload), len(trimmed))
    return payload


def _parse_response(raw_text: str, region: str, total_resources: int) -> dict:
    text = raw_text.strip()
    if text.startswith("```"):
        first_newline = text.index("\n")
        last_fence = text.rfind("```")
        text = text[first_newline + 1 : last_fence].strip()

    data = json.loads(text)
    issues = [
        {
            "resource_id":               item.get("resource_id", ""),
            "resource_type":             item.get("resource_type", ""),
            "resource_name":             item.get("resource_name", ""),
            "issue_type":                item.get("issue_type", ""),
            "severity":                  item.get("severity", "low"),
            "explanation":               item.get("explanation", ""),
            "estimated_monthly_savings": item.get("estimated_monthly_savings", "$0"),
            "fix_command":               item.get("fix_command", ""),
        }
        for item in data.get("issues", [])
    ]
    return {
        "region": region,
        "resources_scanned": total_resources,
        "issues_found": len(issues),
        "estimated_total_savings": data.get("estimated_total_savings", "$0/month"),
        "summary": data.get("summary", "No summary provided."),
        "issues": issues,
    }


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

async def analyze_aws_resources(region: str, resources: dict[str, list[dict]]) -> dict:
    """Analyze scanned AWS resources using the configured LLM provider.

    Provider is selected via LLM_PROVIDER env var (groq | openai | anthropic | gemini).
    API key is read from LLM_API_KEY. Model can be overridden with LLM_MODEL.

    Raises:
        RuntimeError: If configuration is missing or the API call fails.
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
    user_prompt = USER_PROMPT_TEMPLATE.format(region=region, resources_json=resources_json)
    adapter = PROVIDER_ADAPTERS[provider]

    logger.info("Running AI analysis via provider=%s model=%s", provider, model)

    try:
        raw_text = await asyncio.wait_for(
            adapter(SYSTEM_PROMPT, user_prompt, api_key, model),
            timeout=120,
        )
    except asyncio.TimeoutError:
        raise RuntimeError(f"{provider} API call timed out after 120s. Try again shortly.")
    except Exception as e:
        logger.error("%s API error: %s", provider, e)
        raise RuntimeError(f"{provider} API error: {e}") from e

    if not raw_text:
        raise RuntimeError(f"{provider} returned an empty response.")

    try:
        return _parse_response(raw_text, region, total_resources)
    except (json.JSONDecodeError, KeyError, IndexError) as e:
        logger.error("Failed to parse %s response: %s\nRaw: %s", provider, e, raw_text[:500])
        raise RuntimeError(f"{provider} returned an invalid response. Try running the analysis again.") from e
