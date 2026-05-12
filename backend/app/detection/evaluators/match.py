from __future__ import annotations

from typing import Any


def get_field(event: dict[str, Any], field: str) -> Any:
    value: Any = event
    for part in field.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def evaluate_match(events: list[dict[str, Any]], query_definition: dict[str, Any]) -> list[dict[str, Any]]:
    fields = query_definition.get("fields") or query_definition
    matches = []
    for event in events:
        ok = True
        for field, expected in fields.items():
            if field in {"timeframe_minutes", "threshold"}:
                continue
            actual = get_field(event, field)
            if isinstance(expected, list):
                ok = actual in expected
            else:
                ok = str(actual).lower() == str(expected).lower()
            if not ok:
                break
        if ok:
            matches.append({"group": "match", "events": [event]})
    return matches
