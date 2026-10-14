"""Die Abfragesprache des SIEM.

Eine Abfrage wird einmal geparst und kann dann

* in SQL übersetzt werden (Suche in den gespeicherten Events) und
* direkt in Python gegen ein Event ausgewertet werden (Erkennungsregeln).

Beide Wege liefern dasselbe Ergebnis – was man sucht, kann man auch alarmieren.

Syntax (Beispiele)::

    Failed password                 Freitext (alle Wörter müssen vorkommen)
    "Failed password"               exakte Wortfolge
    pass*                           Wortanfang
    host:web01                      Feld ist gleich Wert (ohne Groß/Klein)
    host:web*                       Platzhalter * und ?
    src_ip:10.0.0.0/8               IP-Bereich (CIDR)
    severity:<=warning              Vergleich: > >= < <=
    user:~"^adm.*"                  regulärer Ausdruck
    dst_port:*                      Feld ist vorhanden
    data.status:500                 Feld aus den Rohdaten (JSON)
    a OR b, a AND b, NOT a, -a, ( ) logische Verknüpfungen
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Callable

# Feldname -> Typ ("text", "int", "ip")
FIELDS: dict[str, str] = {
    "host": "text",
    "app": "text",
    "severity": "int",
    "facility": "int",
    "category": "text",
    "event_id": "text",
    "user": "text",
    "src_ip": "ip",
    "dst_ip": "ip",
    "dst_port": "int",
    "action": "text",
    "input": "text",
    "source_ip": "ip",
    "message": "text",
}

# Kurzformen
ALIASES: dict[str, list[str]] = {
    "sev": ["severity"],
    "ip": ["src_ip", "dst_ip", "source_ip"],
    "port": ["dst_port"],
    "msg": ["message"],
}

SEVERITY_NAMES: dict[str, int] = {
    "emerg": 0, "emergency": 0, "notfall": 0,
    "alert": 1, "alarm": 1, "dringend": 1,
    "crit": 2, "critical": 2, "kritisch": 2, "fatal": 2,
    "err": 3, "error": 3, "fehler": 3,
    "warn": 4, "warning": 4, "warnung": 4,
    "notice": 5, "hinweis": 5,
    "info": 6, "informational": 6,
    "debug": 7,
}

SEVERITY_LABELS = ["emerg", "alert", "crit", "error", "warning", "notice", "info", "debug"]


class QueryError(ValueError):
    """Fehler in einer Abfrage – die Meldung ist für Anwender gedacht."""


# ---------------------------------------------------------------------------
# Tokenisierung von Freitext (entspricht dem FTS5-Tokenizer "unicode61")
# ---------------------------------------------------------------------------

_WORD_RE = re.compile(r"[^\W_]+", re.UNICODE)


def _fold(text: str) -> str:
    text = unicodedata.normalize("NFKD", text.lower())
    return "".join(c for c in text if not unicodedata.combining(c))


def text_tokens(text: str) -> list[str]:
    return _WORD_RE.findall(_fold(text))


# ---------------------------------------------------------------------------
# AST
# ---------------------------------------------------------------------------


@dataclass
class Text:
    raw: str
    tokens: list[str]
    prefix: bool


@dataclass
class FieldCmp:
    field: str
    op: str  # eq, wild, cidr, exists, regex, gt, ge, lt, le
    value: Any


@dataclass
class Not:
    child: Any


@dataclass
class BoolOp:
    op: str  # and | or
    children: list


# ---------------------------------------------------------------------------
# Lexer
# ---------------------------------------------------------------------------


@dataclass
class _Tok:
    kind: str  # LP, RP, WORD, PHRASE
    value: str
    pos: int
    quoted_value: bool = False


def _lex(q: str) -> list[_Tok]:
    toks: list[_Tok] = []
    i, n = 0, len(q)
    while i < n:
        c = q[i]
        if c.isspace():
            i += 1
            continue
        if c == "(":
            toks.append(_Tok("LP", c, i))
            i += 1
            continue
        if c == ")":
            toks.append(_Tok("RP", c, i))
            i += 1
            continue
        if c == '"':
            val, i = _read_quoted(q, i)
            toks.append(_Tok("PHRASE", val, i))
            continue
        start = i
        buf = []
        quoted = False
        while i < n and not q[i].isspace() and q[i] not in "()":
            if q[i] == '"':
                val, i = _read_quoted(q, i)
                buf.append(val)
                quoted = True
                continue
            buf.append(q[i])
            i += 1
        toks.append(_Tok("WORD", "".join(buf), start, quoted))
    return toks


def _read_quoted(q: str, i: int) -> tuple[str, int]:
    start = i
    i += 1
    out = []
    while i < len(q):
        c = q[i]
        if c == "\\" and i + 1 < len(q) and q[i + 1] in '"\\':
            # nur \" und \\ sind Escapes – andere Backslashes bleiben für Regex erhalten
            out.append(q[i + 1])
            i += 2
            continue
        if c == '"':
            return "".join(out), i + 1
        out.append(c)
        i += 1
    raise QueryError(f"Anführungszeichen an Position {start + 1} wird nicht geschlossen")


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

_FIELD_RE = re.compile(r"^([A-Za-z_][\w.\-]*):(.*)$", re.S)


class _Parser:
    def __init__(self, toks: list[_Tok]):
        self.toks = toks
        self.i = 0

    def peek(self) -> _Tok | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def take(self) -> _Tok:
        t = self.toks[self.i]
        self.i += 1
        return t

    def is_kw(self, word: str) -> bool:
        t = self.peek()
        return t is not None and t.kind == "WORD" and not t.quoted_value and t.value == word

    def parse(self):
        node = self.parse_or()
        t = self.peek()
        if t is not None:
            if t.kind == "RP":
                raise QueryError(f"Unerwartete schließende Klammer an Position {t.pos + 1}")
            raise QueryError(f"Unerwartetes '{t.value}' an Position {t.pos + 1}")
        return node

    def parse_or(self):
        children = [self.parse_and()]
        while self.is_kw("OR"):
            self.take()
            children.append(self.parse_and())
        return children[0] if len(children) == 1 else BoolOp("or", children)

    def parse_and(self):
        children = [self.parse_unary()]
        while True:
            t = self.peek()
            if t is None or t.kind == "RP" or self.is_kw("OR"):
                break
            if self.is_kw("AND"):
                self.take()
            children.append(self.parse_unary())
        return children[0] if len(children) == 1 else BoolOp("and", children)

    def parse_unary(self):
        t = self.peek()
        if t is None:
            raise QueryError("Abfrage endet unerwartet")
        if self.is_kw("NOT"):
            self.take()
            return Not(self.parse_unary())
        if t.kind == "LP":
            self.take()
            node = self.parse_or()
            close = self.peek()
            if close is None or close.kind != "RP":
                raise QueryError(f"Klammer an Position {t.pos + 1} wird nicht geschlossen")
            self.take()
            return node
        if t.kind == "RP":
            raise QueryError(f"Unerwartete schließende Klammer an Position {t.pos + 1}")
        self.take()
        if t.kind == "PHRASE":
            return _text(t.value, phrase=True)
        word = t.value
        if word.startswith("-") and len(word) > 1:
            return Not(_atom(word[1:], t))
        if word in ("AND", "OR") and not t.quoted_value:
            raise QueryError(f"'{word}' an Position {t.pos + 1} ohne Ausdruck davor")
        return _atom(word, t)


def _text(value: str, phrase: bool) -> Text:
    prefix = False
    v = value
    if not phrase and v.endswith("*") and len(v) > 1:
        prefix = True
        v = v[:-1]
    return Text(raw=v, tokens=text_tokens(v), prefix=prefix)


def _atom(word: str, tok: _Tok):
    m = _FIELD_RE.match(word)
    if not m:
        return _text(word, phrase=tok.quoted_value)
    name, value = m.group(1), m.group(2)
    name_l = name.lower()
    if name_l not in FIELDS and name_l not in ALIASES and not name_l.startswith("data."):
        known = ", ".join(sorted(FIELDS))
        raise QueryError(
            f"Unbekanntes Feld '{name}'. Bekannte Felder: {known}, data.<name>. "
            f"Für Text mit Doppelpunkt bitte Anführungszeichen verwenden."
        )
    if name_l.startswith("data."):
        path = name[5:]
        if not path or not re.fullmatch(r"[\w\-]+(\.[\w\-]+)*", path):
            raise QueryError(f"Ungültiger Feldpfad '{name}'")
        fields = ["data." + path]
    else:
        fields = ALIASES.get(name_l, [name_l])
    nodes = [_field_cmp(f, value, tok.quoted_value) for f in fields]
    return nodes[0] if len(nodes) == 1 else BoolOp("or", nodes)


def _field_type(field: str) -> str:
    return FIELDS.get(field, "text")


def _field_cmp(field: str, value: str, quoted: bool) -> FieldCmp:
    ftype = _field_type(field)
    if value == "" and not quoted:
        raise QueryError(f"Kein Wert für Feld '{field}' angegeben")
    if value.startswith("~"):
        pattern = value[1:]
        try:
            re.compile(pattern)
        except re.error as exc:
            raise QueryError(f"Ungültiger regulärer Ausdruck für '{field}': {exc}") from None
        return FieldCmp(field, "regex", pattern)
    for sym, op in ((">=", "ge"), ("<=", "le"), (">", "gt"), ("<", "lt")):
        if value.startswith(sym) and not quoted:
            raw = value[len(sym):]
            return FieldCmp(field, op, _coerce(field, ftype, raw, numeric_required=False))
    if value == "*" and not quoted:
        return FieldCmp(field, "exists", None)
    if ftype == "ip" and "/" in value:
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise QueryError(f"Ungültiger IP-Bereich '{value}'") from None
        return FieldCmp(field, "cidr", str(net))
    if not quoted and ("*" in value or "?" in value):
        return FieldCmp(field, "wild", value)
    return FieldCmp(field, "eq", _coerce(field, ftype, value, numeric_required=True))


def _coerce(field: str, ftype: str, raw: str, numeric_required: bool):
    if ftype == "int":
        if field == "severity" and raw.lower() in SEVERITY_NAMES:
            return SEVERITY_NAMES[raw.lower()]
        try:
            return int(raw)
        except ValueError:
            raise QueryError(f"Feld '{field}' erwartet eine Zahl, nicht '{raw}'") from None
    try:
        return float(raw) if not numeric_required else raw
    except ValueError:
        return raw


def parse(q: str | None):
    """Parst eine Abfrage. Leere Abfrage -> ``None`` (passt auf alles)."""
    if q is None or not q.strip():
        return None
    if len(q) > 4000:
        raise QueryError("Abfrage ist zu lang (max. 4000 Zeichen)")
    toks = _lex(q)
    if not toks:
        return None
    return _Parser(toks).parse()


# ---------------------------------------------------------------------------
# SQL-Übersetzung
# ---------------------------------------------------------------------------


def _fts_expr(node: Text) -> str:
    phrase = '"' + " ".join(node.tokens) + '"'
    return phrase + ("*" if node.prefix else "")


def _like_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _wild_to_like(s: str) -> str:
    return _like_escape(s).replace("*", "%").replace("?", "_")


def _column(field: str, as_text: bool = False) -> str:
    if field.startswith("data."):
        parts = field[5:].split(".")
        path = "$" + "".join('."' + p + '"' for p in parts)
        raw = f"json_extract(e.data, '{path}')"
        if not as_text:
            return raw
        # JSON-Wahrheitswerte wie in Python als 'true'/'false' vergleichen
        return (
            f"(CASE json_type(e.data, '{path}') WHEN 'true' THEN 'true' "
            f"WHEN 'false' THEN 'false' ELSE CAST({raw} AS TEXT) END)"
        )
    return f"e.{field}"


def to_sql(node) -> tuple[str, list]:
    """Übersetzt den AST in eine WHERE-Bedingung (Tabelle ``events`` als ``e``)."""
    if node is None:
        return "1", []
    params: list = []
    sql = _sql(node, params)
    return sql, params


def _sql(node, params: list) -> str:
    if isinstance(node, BoolOp):
        joiner = " AND " if node.op == "and" else " OR "
        return "(" + joiner.join(_sql(c, params) for c in node.children) + ")"
    if isinstance(node, Not):
        return "(NOT " + _sql(node.child, params) + ")"
    if isinstance(node, Text):
        if not node.tokens:
            params.append("%" + _like_escape(node.raw) + "%")
            return "IFNULL(e.message LIKE ? ESCAPE '\\', 0)"
        params.append(_fts_expr(node))
        return "e.id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)"
    if isinstance(node, FieldCmp):
        ftype = _field_type(node.field)
        op, v = node.op, node.value
        col = _column(node.field, as_text=op in ("eq", "wild", "regex"))
        if op == "exists":
            return f"IFNULL({col} IS NOT NULL AND {col} != '', 0)"
        if op == "eq":
            params.append(v)
            if ftype == "int":
                return f"IFNULL({col} = ?, 0)"
            return f"IFNULL({col} = ? COLLATE NOCASE, 0)"
        if op == "wild":
            params.append(_wild_to_like(v))
            return f"IFNULL({col} LIKE ? ESCAPE '\\', 0)"
        if op == "cidr":
            params.append(v)
            return f"IFNULL(cidr_match({col}, ?), 0)"
        if op == "regex":
            params.append(v)
            return f"IFNULL(regexp(?, {col}), 0)"
        sym = {"gt": ">", "ge": ">=", "lt": "<", "le": "<="}[op]
        params.append(v)
        if isinstance(v, (int, float)) and ftype != "int":
            return f"IFNULL(CAST({col} AS REAL) {sym} ?, 0)"
        return f"IFNULL({col} {sym} ?, 0)"
    raise TypeError(node)


# SQL-Hilfsfunktionen, die an jede Verbindung gebunden werden


@lru_cache(maxsize=256)
def _re_cached(pattern: str):
    return re.compile(pattern, re.IGNORECASE)


@lru_cache(maxsize=256)
def _net_cached(cidr: str):
    return ipaddress.ip_network(cidr, strict=False)


def sql_regexp(pattern, value) -> int:
    if value is None:
        return 0
    return 1 if _re_cached(pattern).search(str(value)) else 0


def sql_cidr_match(value, cidr) -> int:
    if not value:
        return 0
    try:
        return 1 if ipaddress.ip_address(str(value)) in _net_cached(cidr) else 0
    except ValueError:
        return 0


def register_functions(conn) -> None:
    conn.create_function("regexp", 2, sql_regexp, deterministic=True)
    conn.create_function("cidr_match", 2, sql_cidr_match, deterministic=True)


# ---------------------------------------------------------------------------
# Auswertung in Python (für die Erkennungsregeln)
# ---------------------------------------------------------------------------


def _get(event: dict, field: str):
    if field.startswith("data."):
        cur: Any = event.get("data")
        for part in field[5:].split("."):
            if not isinstance(cur, dict):
                return None
            cur = cur.get(part)
        if isinstance(cur, (dict, list)):
            return None
        return cur
    return event.get(field)


def _contains_seq(hay: list[str], needle: list[str], prefix: bool) -> bool:
    n = len(needle)
    if n == 0:
        return True
    for i in range(len(hay) - n + 1):
        ok = True
        for j in range(n):
            word = hay[i + j]
            want = needle[j]
            if j == n - 1 and prefix:
                if not word.startswith(want):
                    ok = False
                    break
            elif word != want:
                ok = False
                break
        if ok:
            return True
    return False


def compile_matcher(node) -> Callable[[dict], bool]:
    """Erzeugt eine Funktion ``event -> bool``."""
    if node is None:
        return lambda e: True

    if isinstance(node, BoolOp):
        subs = [compile_matcher(c) for c in node.children]
        if node.op == "and":
            return lambda e: all(s(e) for s in subs)
        return lambda e: any(s(e) for s in subs)

    if isinstance(node, Not):
        sub = compile_matcher(node.child)
        return lambda e: not sub(e)

    if isinstance(node, Text):
        if not node.tokens:
            needle = node.raw.lower()
            return lambda e: needle in (e.get("message") or "").lower()
        tokens, prefix = node.tokens, node.prefix

        def match_text(e: dict) -> bool:
            toks = e.get("_tokens")
            if toks is None:
                toks = text_tokens(e.get("message") or "")
                e["_tokens"] = toks
            return _contains_seq(toks, tokens, prefix)

        return match_text

    if isinstance(node, FieldCmp):
        return _field_matcher(node)

    raise TypeError(node)


def _num(v):
    if isinstance(v, bool) or v is None:
        return None
    if isinstance(v, (int, float)):
        return v
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _field_matcher(node: FieldCmp) -> Callable[[dict], bool]:
    field, op, v = node.field, node.op, node.value
    ftype = _field_type(field)

    if op == "exists":
        return lambda e: _get(e, field) not in (None, "")
    if op == "eq":
        if ftype == "int":
            return lambda e: _num(_get(e, field)) == v
        lv = str(v).lower()

        def eq(e):
            val = _get(e, field)
            if val is None:
                return False
            if isinstance(val, bool):
                val = "true" if val else "false"
            return str(val).lower() == lv

        return eq
    if op == "wild":
        rx = re.compile(
            "^" + "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in v) + "$",
            re.IGNORECASE | re.S,
        )
        return lambda e: (val := _get(e, field)) is not None and rx.match(str(val)) is not None
    if op == "cidr":
        return lambda e: bool(sql_cidr_match(_get(e, field), v))
    if op == "regex":
        rx = _re_cached(v)
        return lambda e: (val := _get(e, field)) is not None and rx.search(str(val)) is not None

    def cmp(e):
        val = _get(e, field)
        if val is None:
            return False
        if isinstance(v, (int, float)):
            val = _num(val)
            if val is None:
                return False
        else:
            val = str(val)
        if op == "gt":
            return val > v
        if op == "ge":
            return val >= v
        if op == "lt":
            return val < v
        return val <= v

    return cmp
