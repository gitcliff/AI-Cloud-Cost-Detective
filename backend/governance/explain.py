"""LLM explanation layer for governance findings.

The LLM may add one thing: a plain-language `explanation` per failed
evaluation. It cannot change rule IDs, status, severity, evidence or
remediation, and it never authors commands. Its output is validated:
unknown evaluation IDs, extra fields, over-long text and anything that looks
like a command are discarded.

Data minimisation: only rule metadata, resource type, a shortened resource
reference, the deterministic message and remediation risk metadata are sent.
Evidence, policy documents and full identifiers are not.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from dataclasses import dataclass, field

from governance.remediation import REGISTRY

logger = logging.getLogger(__name__)

MAX_ITEMS = 40
MAX_EXPLANATION_CHARS = 600
TIMEOUT_SECONDS = 90
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Command-like content the explanation must not contain (case-sensitive on purpose:
# "AWS S3 buckets" in prose is fine, "aws s3api put-bucket-policy" is not).
_COMMAND_PATTERNS = re.compile(
    r"```"  # code fences
    r"|\baws [a-z0-9]+ [a-z0-9]+-[a-z0-9-]+"  # aws <service> <verb-noun>
    r"|(?:^|\s)--[a-z][a-z0-9-]+"  # CLI flags
    r"|\$\("  # shell substitution
    r"|\b(?:sudo|curl|wget|rm -rf|chmod)\b"
)

SYSTEM_PROMPT = """\
You explain AWS governance findings to engineers. Each finding was already detected and
classified by a deterministic policy engine. You must not change, question or re-rate its
status or severity, and you must not invent compliance claims or cost figures.

For each finding, write 2-4 sentences of plain English: why it matters, the likely
operational or security impact, and what to consider before applying the provided
remediation (use its risk, downtime and reversibility fields). Do not write commands,
code, CLI flags or step-by-step instructions: approved remediation steps are shown
separately.

Respond with JSON only:
{"explanations": [{"evaluation_id": <int>, "explanation": "<text>"}]}
"""


@dataclass
class ExplainResult:
    status: str  # completed | unavailable | failed | skipped
    explanations: dict[int, str] = field(default_factory=dict)
    error: str | None = None
    rejected: int = 0


def shorten(resource_id: str | None) -> str:
    if not resource_id:
        return "unknown"
    return resource_id if len(resource_id) <= 4 else "..." + resource_id[-4:]


def build_payload(evaluations: list[dict]) -> list[dict]:
    """Minimal, redacted view of failing evaluations, most severe first."""
    failing = [e for e in evaluations if e.get("status") == "fail"]
    failing.sort(key=lambda e: (_SEVERITY_RANK.get(e.get("severity"), 9), e.get("kind") != "confirmed", e["id"]))
    payload = []
    for e in failing[:MAX_ITEMS]:
        template = REGISTRY.get(e.get("remediation_ref") or "")
        payload.append(
            {
                "evaluation_id": e["id"],
                "rule_id": e["rule_id"],
                "rule_name": e.get("rule_name"),
                "category": e.get("category"),
                "severity": e.get("severity"),
                "finding_kind": e.get("kind"),
                "resource_type": e.get("resource_type"),
                "resource_ref": shorten(e.get("resource_id")),
                "message": e.get("message"),
                "remediation": (
                    {
                        "title": template.title,
                        "type": template.type,
                        "risk_level": template.risk_level,
                        "requires_downtime": template.requires_downtime,
                        "reversible": template.reversible,
                        "data_loss_risk": template.data_loss_risk,
                    }
                    if template
                    else None
                ),
            }
        )
    return payload


def parse_response(raw: str, allowed_ids: set[int]) -> tuple[dict[int, str], int]:
    """Validate the LLM response. Returns (explanations, rejected_count). Raises ValueError on bad JSON shape."""
    text = raw.strip()
    if text.startswith("```"):
        text = text[text.index("\n") + 1 : text.rfind("```")].strip()
    data = json.loads(text)
    items = data.get("explanations") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise ValueError("response has no 'explanations' list")

    accepted: dict[int, str] = {}
    rejected = 0
    for item in items:
        if not isinstance(item, dict):
            rejected += 1
            continue
        eid, text = item.get("evaluation_id"), item.get("explanation")
        if isinstance(eid, str) and eid.isdigit():
            eid = int(eid)
        if not isinstance(eid, int) or isinstance(eid, bool) or eid not in allowed_ids or eid in accepted:
            rejected += 1
            continue
        if not isinstance(text, str) or not text.strip() or _COMMAND_PATTERNS.search(text):
            rejected += 1
            continue
        text = " ".join(text.split())
        if len(text) > MAX_EXPLANATION_CHARS:
            text = text[: MAX_EXPLANATION_CHARS - 1].rstrip() + "…"
        accepted[eid] = text
    return accepted, rejected


async def explain_evaluations(evaluations: list[dict], adapter=None) -> ExplainResult:
    """Ask the configured LLM to explain failing evaluations. Never raises."""
    payload = build_payload(evaluations)
    if not payload:
        return ExplainResult(status="skipped")

    if adapter is None:
        from ai_analyzer import PROVIDER_ADAPTERS, PROVIDER_DEFAULTS

        provider = os.getenv("LLM_PROVIDER", "groq").lower()
        api_key = os.getenv("LLM_API_KEY")
        model = os.getenv("LLM_MODEL") or PROVIDER_DEFAULTS.get(provider)
        if provider not in PROVIDER_ADAPTERS or not api_key:
            return ExplainResult(status="unavailable", error="LLM provider or API key not configured")
        base = PROVIDER_ADAPTERS[provider]

        async def adapter(system, user):
            return await base(system, user, api_key, model)

    user_prompt = "Findings:\n" + json.dumps(payload, indent=2)
    try:
        raw = await asyncio.wait_for(adapter(SYSTEM_PROMPT, user_prompt), timeout=TIMEOUT_SECONDS)
        explanations, rejected = parse_response(raw or "", {p["evaluation_id"] for p in payload})
    except TimeoutError:
        return ExplainResult(status="failed", error=f"LLM timed out after {TIMEOUT_SECONDS}s")
    except Exception as err:
        logger.warning("Governance explanation failed: %s", err)
        return ExplainResult(status="failed", error=f"{type(err).__name__}: {str(err)[:200]}")
    if rejected:
        logger.info("Discarded %d invalid governance explanation item(s)", rejected)
    return ExplainResult(status="completed", explanations=explanations, rejected=rejected)
