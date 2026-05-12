from __future__ import annotations

from typing import Any


def get_field(event: dict[str, Any], field: str) -> Any:
    value: Any = event
    for part in field.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _event_matches(event: dict[str, Any], condition: dict[str, Any]) -> bool:
    return all(str(get_field(event, field) or "").lower() == str(expected).lower() for field, expected in condition.items())


def evaluate_sequence(events: list[dict[str, Any]], query_definition: dict[str, Any], *, group_by: list[str]) -> list[dict[str, Any]]:
    sequence = query_definition.get("sequence") or []
    if not sequence:
        return []
    sorted_events = sorted(events, key=lambda item: item.get("timestamp", ""))
    groups: dict[str, list[dict[str, Any]]] = {}
    for event in sorted_events:
        key = "|".join(str(get_field(event, field) or "") for field in group_by) if group_by else "all"
        groups.setdefault(key, []).append(event)
    results = []
    for key, grouped in groups.items():
        pos = 0
        matched = []
        for event in grouped:
            if _event_matches(event, sequence[pos]):
                matched.append(event)
                pos += 1
                if pos == len(sequence):
                    results.append({"group": key, "events": matched})
                    break
    return results
