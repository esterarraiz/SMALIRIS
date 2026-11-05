"""Validação leve do contrato JSON publicado pela SMALIRIS."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


SCHEMA_PATH = Path(__file__).with_name("schemas") / "analysis_report.schema.json"
JSON_TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "null": type(None),
}


def load_report_schema() -> dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def validate_report(report: dict[str, Any]) -> None:
    """Valida o subconjunto de JSON Schema usado pelo relatório oficial."""
    errors: list[str] = []
    _validate_node(report, load_report_schema(), "$", errors)
    if errors:
        raise ValueError("Relatório incompatível com o schema: " + "; ".join(errors))


def _validate_node(
    value: Any,
    schema: dict[str, Any],
    path: str,
    errors: list[str],
) -> None:
    expected = schema.get("type")
    if expected is not None:
        names = expected if isinstance(expected, list) else [expected]
        valid = any(_matches_json_type(value, name) for name in names)
        if not valid:
            errors.append(f"{path}: tipo esperado {names}")
            return

    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: valor esperado {schema['const']!r}")

    if isinstance(value, dict):
        for required in schema.get("required", []):
            if required not in value:
                errors.append(f"{path}.{required}: campo obrigatório ausente")
        for name, child_schema in schema.get("properties", {}).items():
            if name in value:
                _validate_node(value[name], child_schema, f"{path}.{name}", errors)

    if isinstance(value, list) and isinstance(schema.get("items"), dict):
        for index, item in enumerate(value):
            _validate_node(item, schema["items"], f"{path}[{index}]", errors)

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        minimum = schema.get("minimum")
        if minimum is not None and value < minimum:
            errors.append(f"{path}: valor menor que {minimum}")

    pattern = schema.get("pattern")
    if isinstance(value, str) and pattern and re.fullmatch(pattern, value) is None:
        errors.append(f"{path}: formato inválido")


def _matches_json_type(value: Any, name: str) -> bool:
    expected = JSON_TYPES.get(name)
    if expected is None:
        return True
    if name in {"integer", "number"} and isinstance(value, bool):
        return False
    return isinstance(value, expected)
