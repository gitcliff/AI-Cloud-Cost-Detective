"""Golden regression test: the governance extension must not change cost findings.

The fixture was generated from the pricing engine before any governance work.
If a deliberate pricing change breaks this test, regenerate it with:
    REGENERATE_PRICING_GOLDEN=1 python -m pytest tests/test_pricing_regression.py
and review the diff.
"""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pricing_engine  # noqa: E402

GOLDEN = Path(__file__).parent / "fixtures" / "pricing_golden.json"


def _run_offline(resources):
    original_init = pricing_engine.PricingProvider.__init__

    def offline_init(self, region):
        original_init(self, region)
        self._pricing_available = False

    pricing_engine.PricingProvider.__init__ = offline_init
    try:
        return pricing_engine.detect_and_price_issues(resources, "us-east-1")
    finally:
        pricing_engine.PricingProvider.__init__ = original_init


def test_pricing_output_matches_golden(sample_resources):
    actual = json.loads(json.dumps(_run_offline(sample_resources), sort_keys=True, default=str))
    if os.getenv("REGENERATE_PRICING_GOLDEN") == "1":
        GOLDEN.parent.mkdir(exist_ok=True)
        GOLDEN.write_text(json.dumps(actual, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    assert actual == json.loads(GOLDEN.read_text(encoding="utf-8"))
