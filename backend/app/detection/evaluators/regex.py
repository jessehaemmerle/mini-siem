from __future__ import annotations

import re
from typing import Any


def evaluate_regex(events: list[dict[str, Any]], query_definition: dict[str, Any]) -> list[dict[str, Any]]:
    pattern = query_definition.get("pattern") or query_definition.get("regex")
    fields = query_definition.get("fields") or ["message", "command_line", "raw_log"]
    if not pattern:
        return []
    compiled = re.compile(pattern, re.IGNORECASE)
    matches = []
    for event in events:
        haystack = "\n".join(str(event.get(field) or "") for field in fields)
        if compiled.search(haystack):
            matches.append({"group": "regex", "events": [event]})
    return matches
