from __future__ import annotations

from collections import defaultdict
from typing import Any


def get_field(event: dict[str, Any], field: str) -> Any:
    value: Any = event
    for part in field.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _group_key(event: dict[str, Any], fields: list[str]) -> str:
    if not fields:
        return "all"
    return "|".join(str(get_field(event, field) or "") for field in fields)


def _matches_filter(event: dict[str, Any], fields: dict[str, Any]) -> bool:
    for field, expected in fields.items():
        actual = get_field(event, field)
        if isinstance(expected, list):
            if actual not in expected:
                return False
        elif str(actual).lower() != str(expected).lower():
            return False
    return True


def evaluate_threshold(
    events: list[dict[str, Any]],
    query_definition: dict[str, Any],
    *,
    threshold: int,
    group_by: list[str],
) -> list[dict[str, Any]]:
    fields = query_definition.get("fields") or {}
    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if fields and not _matches_filter(event, fields):
            continue
        buckets[_group_key(event, group_by)].append(event)
    return [{"group": key, "events": grouped} for key, grouped in buckets.items() if len(grouped) >= threshold]
