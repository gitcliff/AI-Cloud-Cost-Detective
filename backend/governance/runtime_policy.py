"""Versioned Lambda runtime support policy, loaded from a data file (not hardcoded in rules)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date
from functools import lru_cache
from pathlib import Path

DEFAULT_PATH = Path(__file__).parent / "data" / "lambda_runtime_policy.json"


@dataclass(frozen=True)
class RuntimeEntry:
    deprecation_date: date | None
    block_update_date: date | None


@dataclass(frozen=True)
class RuntimePolicy:
    as_of: date
    source: str
    runtimes: dict[str, RuntimeEntry]

    def age_days(self, today: date) -> int:
        return (today - self.as_of).days


def _d(value: str | None) -> date | None:
    return date.fromisoformat(value) if value else None


def parse_runtime_policy(raw: dict) -> RuntimePolicy:
    return RuntimePolicy(
        as_of=date.fromisoformat(raw["as_of"]),
        source=raw.get("source", ""),
        runtimes={
            name: RuntimeEntry(_d(v.get("deprecation_date")), _d(v.get("block_update_date")))
            for name, v in raw["runtimes"].items()
        },
    )


@lru_cache(maxsize=1)
def load_runtime_policy(path: str = str(DEFAULT_PATH)) -> RuntimePolicy:
    with open(path, encoding="utf-8") as fh:
        return parse_runtime_policy(json.load(fh))
