#!/usr/bin/env python3
"""Comparador experimental de relatórios SMALIRIS e MobSF.

Usa apenas a biblioteca padrão do Python. Os relatórios são pareados por
SHA-256; o nome do APK é usado como fallback identificado explicitamente.
"""

from __future__ import annotations

import argparse
import csv
import html
import json
import math
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Any, Iterable


COMPARATOR_VERSION = "1.0.1"
DEFAULT_CATALOG = Path(__file__).with_name("comparison_catalog.json")
SEVERITIES = ("high", "medium", "low", "info")
COMPONENT_TYPES = ("activity", "service", "receiver", "provider")
DIVERGENCE_STATUSES = {
    "somente_smaliris",
    "somente_mobsf",
    "quantidade_divergente",
    "componentes_divergentes",
}
EXPORTED_TITLE_RE = re.compile(
    r"(?i)\b(activity|service|broadcast\s+receiver|content\s+provider|provider)"
    r"\s*\(([^)]+)\).*?\[android:exported\s*=\s*true\]"
)


@dataclass(frozen=True)
class ReportFile:
    tool: str
    path: Path
    data: dict[str, Any]
    metadata: dict[str, Any]
    sha256: str | None
    file_name: str
    category: str


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8-sig") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"O JSON raiz não é um objeto: {path}")
    return value


def nested_get(data: dict[str, Any], *keys: str, default: Any = None) -> Any:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current


def first_present(*values: Any) -> Any:
    for value in values:
        if value not in (None, "", [], {}):
            return value
    return None


def normalize_sha256(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip().lower()
    return value if re.fullmatch(r"[0-9a-f]{64}", value) else None


def normalize_file_name(value: Any) -> str:
    if not value:
        return ""
    text = str(value).replace("\\", "/")
    return text.rsplit("/", 1)[-1]


def normalized_name_key(value: str) -> str:
    return normalize_file_name(value).strip().casefold()


def as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().casefold()
        if normalized in {"true", "1", "yes", "sim", "enabled"}:
            return True
        if normalized in {"false", "0", "no", "não", "nao", "disabled"}:
            return False
    return None


def collection_count(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, (list, tuple, set, dict)):
        return len(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return 0
        if text.isdigit():
            return int(text)
        try:
            decoded = json.loads(text)
        except (ValueError, TypeError):
            return None
        return collection_count(decoded)
    return None


def safe_float(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def normalize_component_name(value: Any, package: str = "") -> str:
    """Normaliza descritores, nomes relativos e separadores de classes Android."""
    if value is None:
        return ""
    text = str(value).strip().strip('"\'')
    if not text:
        return ""
    text = re.sub(r"^(?:activity|service|receiver|provider)\s*[:=]\s*", "", text, flags=re.I)
    if text.startswith("L") and text.endswith(";"):
        text = text[1:-1]
    text = text.replace("/", ".")
    text = re.sub(r"\s+", "", text)
    if text.startswith(".") and package:
        text = f"{package}{text}"
    elif "." not in text and package:
        text = f"{package}.{text}"
    return text.casefold()


def component_names(value: Any, package: str = "") -> list[str] | None:
    """Extrai um conjunto ordenado de componentes quando os nomes estão disponíveis."""
    if value is None:
        return None
    if isinstance(value, dict):
        raw_values = list(value.keys())
    elif isinstance(value, (list, tuple, set)):
        raw_values = list(value)
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        try:
            decoded = json.loads(text)
        except (TypeError, ValueError):
            raw_values = [text]
        else:
            return component_names(decoded, package)
    else:
        return None
    normalized: set[str] = set()
    for item in raw_values:
        if isinstance(item, dict):
            item = first_present(
                item.get("name"),
                item.get("component"),
                item.get("activity"),
                item.get("class"),
            )
        name = normalize_component_name(item, package)
        if name:
            normalized.add(name)
    return sorted(normalized)


def scalar_texts(value: Any, limit: int = 12000) -> str:
    """Monta texto pesquisável sem serializar grandes árvores do relatório."""
    values: list[str] = []

    def visit(item: Any) -> None:
        if sum(len(part) for part in values) >= limit:
            return
        if isinstance(item, dict):
            for key, nested in item.items():
                if key.casefold() in {"files", "source", "code", "strings"}:
                    continue
                visit(nested)
        elif isinstance(item, (list, tuple, set)):
            for nested in item[:100]:
                visit(nested)
        elif isinstance(item, (str, int, float, bool)):
            text = str(item).strip()
            if text:
                values.append(text)

    visit(value)
    return " ".join(values)[:limit]


def report_category(root: Path, path: Path, data: dict[str, Any], metadata: dict[str, Any]) -> str:
    explicit = first_present(metadata.get("categoria"), metadata.get("category"))
    if explicit:
        return str(explicit)

    apk_path = data.get("apk_path")
    if isinstance(apk_path, str) and apk_path:
        if "\\" in apk_path:
            parent = PureWindowsPath(apk_path).parent.name
        else:
            parent = Path(apk_path).parent.name
        if parent:
            return parent

    try:
        parts = path.relative_to(root).parts
    except ValueError:
        parts = path.parts
    return parts[0] if len(parts) >= 3 else "sem_categoria"


def load_sibling_metadata(path: Path) -> dict[str, Any]:
    candidate = path.with_name("metadata.json")
    if not candidate.exists():
        return {}
    try:
        return load_json(candidate)
    except (OSError, ValueError, json.JSONDecodeError):
        return {}


def discover_reports(root: Path, tool: str, warnings: list[str]) -> list[ReportFile]:
    target = "manifest_analysis.json" if tool == "smaliris" else "report.json"
    reports: list[ReportFile] = []
    for path in sorted(root.rglob(target), key=lambda item: str(item).casefold()):
        try:
            data = load_json(path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            warnings.append(f"{tool}: relatório ignorado ({path}): {exc}")
            continue

        metadata = load_sibling_metadata(path)
        if tool == "smaliris":
            sha256 = normalize_sha256(
                first_present(
                    nested_get(data, "reproducibility", "apk_sha256"),
                    data.get("apk_sha256"),
                    metadata.get("sha256"),
                )
            )
            file_name = normalize_file_name(
                first_present(data.get("apk_path"), metadata.get("arquivo"), path.parent.name)
            )
        else:
            sha256 = normalize_sha256(
                first_present(
                    data.get("sha256"),
                    nested_get(data, "file_hashes", "sha256"),
                    metadata.get("sha256"),
                )
            )
            file_name = normalize_file_name(
                first_present(data.get("file_name"), metadata.get("arquivo"), path.parent.name)
            )

        reports.append(
            ReportFile(
                tool=tool,
                path=path,
                data=data,
                metadata=metadata,
                sha256=sha256,
                file_name=file_name,
                category=report_category(root, path, data, metadata),
            )
        )
    return reports


def iter_mobsf_findings(report: dict[str, Any], severity_mapping: dict[str, str]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    signatures: set[tuple[str, str, str, str]] = set()

    def add_finding(item: dict[str, Any], raw_severity: str, section: str, index: int) -> None:
        title = str(
            first_present(
                item.get("title"),
                item.get("name"),
                item.get("rule"),
                item.get("issue"),
                item.get("description"),
                "Achado MobSF",
            )
            or "Achado MobSF"
        )
        description = str(first_present(item.get("description"), item.get("desc"), item.get("info"), "") or "")
        rule_id = str(first_present(item.get("rule_id"), item.get("rule"), item.get("id"), "") or "")
        signature = (rule_id, title, description, section)
        if signature in signatures:
            return
        signatures.add(signature)
        normalized_severity = severity_mapping.get(
            raw_severity,
            {"warning": "medium", "secure": "info"}.get(raw_severity, raw_severity),
        )
        if normalized_severity not in SEVERITIES:
            normalized_severity = "info"
        findings.append(
            {
                "id": f"MOBSF-{section.upper()}-{index:04d}",
                "rule_id": rule_id,
                "title": title,
                "description": description,
                "section": section,
                "severity": normalized_severity,
                "raw_severity": raw_severity,
                "component": str(
                    first_present(item.get("component"), extract_component_from_title(title), "") or ""
                ),
                "search_text": scalar_texts(item),
            }
        )

    appsec = report.get("appsec") or {}
    if isinstance(appsec, dict):
        for raw_severity in ("high", "warning", "info", "hotspot"):
            items = appsec.get(raw_severity) or []
            if not isinstance(items, list):
                continue
            for index, item in enumerate(items, start=1):
                if isinstance(item, dict):
                    add_finding(item, raw_severity, str(item.get("section") or "appsec"), index)

    def walk_section(value: Any, section: str, inherited_severity: str = "info") -> None:
        if isinstance(value, list):
            for index, item in enumerate(value, start=1):
                if isinstance(item, dict):
                    raw = str(first_present(item.get("severity"), inherited_severity, "info") or "info").casefold()
                    add_finding(item, raw, section, index)
                elif isinstance(item, (list, dict)):
                    walk_section(item, section, inherited_severity)
        elif isinstance(value, dict):
            looks_like_finding = any(
                key in value for key in ("title", "description", "rule", "rule_id", "issue")
            )
            if looks_like_finding:
                raw = str(first_present(value.get("severity"), inherited_severity, "info") or "info").casefold()
                add_finding(value, raw, section, len(findings) + 1)
                return
            for key, nested in value.items():
                raw = key.casefold() if key.casefold() in {"high", "warning", "info", "hotspot"} else inherited_severity
                walk_section(nested, section, raw)

    for section_key in ("manifest_analysis", "network_security", "code_analysis"):
        walk_section(report.get(section_key), section_key)
    return findings


def iter_smaliris_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for index, item in enumerate(report.get("findings") or [], start=1):
        if not isinstance(item, dict):
            continue
        rule_id = str(item.get("rule_id") or "")
        title = str(item.get("title") or "Achado SMALIRIS")
        evidence = str(item.get("evidence") or "")
        findings.append(
            {
                "id": f"SMALIRIS-MANIFEST-{index:04d}",
                "rule_id": rule_id,
                "title": title,
                "description": evidence,
                "section": "manifest",
                "severity": str(item.get("severity") or "info").lower(),
                "raw_severity": str(item.get("severity") or "info").lower(),
                "component": str(item.get("component") or ""),
                "search_text": " ".join((rule_id, title, evidence, str(item.get("recommendation") or ""))),
            }
        )

    candidates = nested_get(report, "risk_analysis", "candidates", default=[]) or []
    for index, item in enumerate(candidates, start=1):
        if not isinstance(item, dict):
            continue
        rule_id = str(item.get("rule_id") or "")
        title = str(item.get("title") or "Candidato de risco SMALIRIS")
        reasons = " ".join(str(value) for value in (item.get("reasons") or []))
        api_text = " ".join(
            str(value)
            for key in ("source_apis", "sensitive_apis", "reachable_sensitive_apis")
            for value in (item.get(key) or [])
        )
        classification = str(item.get("critical_argument_classification") or "")
        findings.append(
            {
                "id": f"SMALIRIS-RISK-{index:04d}",
                "rule_id": rule_id,
                "title": title,
                "description": reasons,
                "section": "risk-correlation",
                "severity": str(item.get("severity") or "info").lower(),
                "raw_severity": str(item.get("severity") or "info").lower(),
                "component": str(item.get("component") or ""),
                "search_text": " ".join((rule_id, title, reasons, api_text, classification)),
            }
        )
    return findings


def extract_component_from_title(title: str) -> str:
    match = re.search(r"\(([^)]+)\)", title)
    return match.group(1) if match else ""


def component_type(value: Any) -> str:
    normalized = str(value or "").strip().casefold().replace("-", "_")
    aliases = {
        "broadcast_receiver": "receiver",
        "broadcast receiver": "receiver",
        "content_provider": "provider",
        "content provider": "provider",
        "activity_alias": "activity",
        "activity-alias": "activity",
    }
    return aliases.get(normalized, normalized)


def smaliris_duration(report: dict[str, Any]) -> float | None:
    decompilation = safe_float(nested_get(report, "reproducibility", "decompilation_duration_seconds"))
    analysis = safe_float(nested_get(report, "reproducibility", "analysis_duration_seconds"))
    if decompilation is None and analysis is None:
        return None
    return (decompilation or 0.0) + (analysis or 0.0)


def normalize_smaliris(record: ReportFile) -> dict[str, Any]:
    report = record.data
    package = str(report.get("package") or "")
    components = [item for item in (report.get("components") or []) if isinstance(item, dict)]
    effective_exported: dict[str, set[str]] = {kind: set() for kind in COMPONENT_TYPES}
    explicit_exported: dict[str, set[str]] = {kind: set() for kind in COMPONENT_TYPES}
    launcher_activities: set[str] = set()
    totals = Counter()
    for item in components:
        kind = component_type(item.get("type"))
        if kind in COMPONENT_TYPES:
            totals[kind] += 1
            name = normalize_component_name(item.get("name"), package)
            if item.get("exported") is True:
                if name:
                    effective_exported[kind].add(name)
                source = str(item.get("exported_source") or "").casefold()
                if not source or source == "explicit" or source.startswith("explicit-"):
                    if name:
                        explicit_exported[kind].add(name)
            if kind == "activity":
                for intent_filter in item.get("intent_filters") or []:
                    if not isinstance(intent_filter, dict):
                        continue
                    actions = set(intent_filter.get("actions") or [])
                    categories = set(intent_filter.get("categories") or [])
                    if "android.intent.action.MAIN" in actions and "android.intent.category.LAUNCHER" in categories and name:
                        launcher_activities.add(name)

    summary = report.get("summary") or {}
    findings = iter_smaliris_findings(report)
    severity_counts = Counter(item["severity"] for item in findings)
    browsable_count = first_present(summary.get("browsable_deep_link_count"), 0)
    debuggable = as_bool(nested_get(report, "application", "debuggable"))
    if debuggable is None:
        debuggable = any_finding_matches(
            findings,
            (r"^APP-DEBUG-001$", r"depura[cç][aã]o habilitada", r"debuggable\s*=\s*true"),
        )
    target_sdk = safe_int(nested_get(report, "sdk", "target"))
    cleartext = as_bool(nested_get(report, "application", "uses_cleartext_traffic"))
    cleartext_source = "manifest-explicit"
    if cleartext is None and target_sdk is not None:
        cleartext = target_sdk <= 27
        cleartext_source = "android-default-by-target-sdk"
    elif cleartext is None:
        cleartext_source = "unknown"
    facts = {
        "debuggable": debuggable,
        "debuggable_source": "application-or-finding",
        "cleartext_traffic": cleartext,
        "cleartext_traffic_source": cleartext_source,
        "target_sdk": target_sdk,
        "browsable_deep_link_count": int(browsable_count or 0),
        "browsable_deep_link_present": int(browsable_count or 0) > 0,
        "component_count": len(components),
        "exported_component_count": sum(len(values) for values in effective_exported.values()),
        "explicit_exported_component_count": sum(len(values) for values in explicit_exported.values()),
        "launcher_activities": sorted(launcher_activities),
        "manifest_finding_count": len(report.get("findings") or []),
        "risk_candidate_count": int(summary.get("risk_candidate_count") or 0),
        "confirmed_flow_count": int(summary.get("data_flow_confirmed_count") or 0),
    }
    for kind in COMPONENT_TYPES:
        facts[f"{kind}_count"] = totals[kind]
        facts[f"exported_{kind}_components"] = sorted(explicit_exported[kind])
        facts[f"exported_{kind}_count"] = len(explicit_exported[kind])
        facts[f"effective_exported_{kind}_components"] = sorted(effective_exported[kind])
        facts[f"effective_exported_{kind}_count"] = len(effective_exported[kind])

    return {
        "tool": "SMALIRIS",
        "tool_version": str(nested_get(report, "tool", "version") or nested_get(report, "reproducibility", "tool_version") or ""),
        "report_path": str(record.path),
        "sha256": record.sha256,
        "file_name": record.file_name,
        "category": record.category,
        "package": package,
        "version_name": "",
        "duration_seconds": smaliris_duration(report),
        "facts": facts,
        "findings": findings,
        "severity_counts": {severity: severity_counts.get(severity, 0) for severity in SEVERITIES},
        "reported_finding_count": len(findings),
        "security_score": None,
    }


def mobsf_exported_from_findings(
    findings: list[dict[str, Any]], package: str = ""
) -> dict[str, list[str]]:
    values: dict[str, set[str]] = {kind: set() for kind in COMPONENT_TYPES}
    aliases = {
        "activity": "activity",
        "service": "service",
        "broadcast receiver": "receiver",
        "content provider": "provider",
        "provider": "provider",
    }
    for finding in findings:
        match = EXPORTED_TITLE_RE.search(finding.get("title", ""))
        if match:
            name = normalize_component_name(match.group(2), package)
            if name:
                values[aliases[match.group(1).casefold()]].add(name)
    return {kind: sorted(items) for kind, items in values.items()}


def mobsf_component_count(report: dict[str, Any], kind: str) -> int | None:
    plural = {
        "activity": "activities",
        "service": "services",
        "receiver": "receivers",
        "provider": "providers",
    }[kind]
    return collection_count(report.get(plural))


def mobsf_exported_count(report: dict[str, Any], kind: str, fallback: dict[str, list[str]]) -> int:
    plural = {
        "activity": "activities",
        "service": "services",
        "receiver": "receivers",
        "provider": "providers",
    }[kind]
    key = f"exported_{plural}"
    direct = collection_count(report.get(key))
    if direct is not None:
        return direct
    exported_count = report.get("exported_count")
    if isinstance(exported_count, dict):
        nested = collection_count(first_present(exported_count.get(key), exported_count.get(plural)))
        if nested is not None:
            return nested
    return len(fallback.get(kind, []))


def mobsf_exported_names(
    report: dict[str, Any],
    kind: str,
    package: str,
    fallback: dict[str, list[str]],
    count: int,
) -> list[str] | None:
    plural = {
        "activity": "activities",
        "service": "services",
        "receiver": "receivers",
        "provider": "providers",
    }[kind]
    direct_key = f"exported_{plural}"
    if direct_key in report:
        direct = component_names(report.get(direct_key), package)
        if direct is not None:
            return direct
    fallback_names = fallback.get(kind, [])
    if fallback_names:
        return sorted(set(fallback_names))
    return [] if count == 0 else None


def any_finding_matches(findings: Iterable[dict[str, Any]], patterns: Iterable[str]) -> bool:
    compiled = [re.compile(pattern, re.IGNORECASE | re.DOTALL) for pattern in patterns]
    return any(regex.search(str(item.get("search_text") or "")) for item in findings for regex in compiled)


def normalize_mobsf(record: ReportFile, severity_mapping: dict[str, str]) -> dict[str, Any]:
    report = record.data
    findings = iter_mobsf_findings(report, severity_mapping)
    severity_counts = Counter(item["severity"] for item in findings)
    package = str(first_present(report.get("package_name"), report.get("package"), "") or "")
    exported_fallback = mobsf_exported_from_findings(findings, package)

    browsable_count = collection_count(report.get("browsable_activities"))
    if browsable_count is None:
        browsable_count = 1 if any_finding_matches(findings, (r"browsable activity", r"deep.?link")) else 0

    debuggable = as_bool(
        first_present(
            report.get("debuggable"),
            nested_get(report, "application", "debuggable"),
            nested_get(report, "manifest", "debuggable"),
            nested_get(report, "appsec", "debuggable"),
        )
    )
    if debuggable is None:
        debuggable = any_finding_matches(
            findings,
            (r"application.{0,80}debuggable", r"android:debuggable\s*=\s*(?:true|[\"']true[\"'])"),
        )

    cleartext = as_bool(
        first_present(
            report.get("uses_cleartext_traffic"),
            report.get("cleartext_traffic"),
            nested_get(report, "application", "uses_cleartext_traffic"),
            nested_get(report, "manifest", "uses_cleartext_traffic"),
        )
    )
    if cleartext is None:
        cleartext = any_finding_matches(
            findings,
            (r"clear.?text traffic", r"usesCleartextTraffic", r"insecure network traffic"),
        )

    facts: dict[str, Any] = {
        "debuggable": debuggable,
        "debuggable_source": "field-or-manifest-finding",
        "cleartext_traffic": cleartext,
        "cleartext_traffic_source": "field-or-manifest-finding",
        "target_sdk": safe_int(first_present(report.get("target_sdk"), nested_get(report, "sdk", "target"))),
        "browsable_deep_link_count": browsable_count,
        "browsable_deep_link_present": browsable_count > 0,
        "manifest_finding_count": sum(1 for item in findings if item.get("section") == "manifest"),
        "risk_candidate_count": 0,
        "confirmed_flow_count": 0,
    }
    total_components = 0
    exported_components = 0
    all_totals_known = True
    for kind in COMPONENT_TYPES:
        total = mobsf_component_count(report, kind)
        exported = mobsf_exported_count(report, kind, exported_fallback)
        names = mobsf_exported_names(report, kind, package, exported_fallback, exported)
        facts[f"{kind}_count"] = total
        facts[f"exported_{kind}_count"] = exported
        facts[f"exported_{kind}_components"] = names
        exported_components += exported
        if total is None:
            all_totals_known = False
        else:
            total_components += total
    facts["component_count"] = total_components if all_totals_known else None
    facts["exported_component_count"] = exported_components

    return {
        "tool": "MobSF",
        "tool_version": str(first_present(record.metadata.get("versao"), report.get("mobsf_version"), "")),
        "report_path": str(record.path),
        "sha256": record.sha256,
        "file_name": record.file_name,
        "category": record.category,
        "package": package,
        "version_name": str(report.get("version_name") or ""),
        "duration_seconds": safe_float(record.metadata.get("duracao_segundos")),
        "facts": facts,
        "findings": findings,
        "severity_counts": {severity: severity_counts.get(severity, 0) for severity in SEVERITIES},
        "reported_finding_count": len(findings),
        "security_score": safe_float(
            first_present(
                report.get("security_score"),
                nested_get(report, "appsec", "security_score"),
                nested_get(report, "appsec", "score"),
            )
        ),
    }


def index_reports(records: list[ReportFile], warnings: list[str]) -> tuple[dict[str, ReportFile], dict[str, ReportFile]]:
    by_hash: dict[str, ReportFile] = {}
    by_name: dict[str, ReportFile] = {}
    for record in records:
        if record.sha256:
            if record.sha256 in by_hash:
                warnings.append(
                    f"{record.tool}: SHA-256 duplicado; usando o primeiro relatório: {record.sha256}"
                )
            else:
                by_hash[record.sha256] = record
        name_key = normalized_name_key(record.file_name)
        if name_key and name_key not in by_name:
            by_name[name_key] = record
    return by_hash, by_name


def pair_reports(
    smaliris_records: list[ReportFile],
    mobsf_records: list[ReportFile],
    warnings: list[str],
) -> list[tuple[ReportFile | None, ReportFile | None, str]]:
    sm_hash, sm_name = index_reports(smaliris_records, warnings)
    mb_hash, mb_name = index_reports(mobsf_records, warnings)
    pairs: list[tuple[ReportFile | None, ReportFile | None, str]] = []
    used_sm: set[Path] = set()
    used_mb: set[Path] = set()

    for sha256 in sorted(set(sm_hash) | set(mb_hash)):
        sm = sm_hash.get(sha256)
        mb = mb_hash.get(sha256)
        if sm and mb:
            pairs.append((sm, mb, "sha256"))
            used_sm.add(sm.path)
            used_mb.add(mb.path)

    for sm in smaliris_records:
        if sm.path in used_sm:
            continue
        mb = mb_name.get(normalized_name_key(sm.file_name))
        if mb and mb.path not in used_mb:
            pairs.append((sm, mb, "filename_fallback"))
            used_sm.add(sm.path)
            used_mb.add(mb.path)
            warnings.append(f"Pareamento por nome, sem SHA-256 comum: {sm.file_name}")

    for sm in smaliris_records:
        if sm.path not in used_sm:
            pairs.append((sm, None, "unmatched"))
    for mb in mobsf_records:
        if mb.path not in used_mb:
            pairs.append((None, mb, "unmatched"))

    return sorted(
        pairs,
        key=lambda pair: (
            (pair[0] or pair[1]).category.casefold(),
            (pair[0] or pair[1]).file_name.casefold(),
        ),
    )


def finding_hits(normalized: dict[str, Any] | None, category: dict[str, Any], tool: str) -> list[dict[str, Any]]:
    if normalized is None:
        return []
    patterns = category.get(f"{tool}_patterns") or []
    if not patterns:
        return []
    compiled = [re.compile(pattern, re.IGNORECASE | re.DOTALL) for pattern in patterns]
    return [
        item
        for item in normalized.get("findings", [])
        if any(regex.search(str(item.get("search_text") or "")) for regex in compiled)
    ]


def category_value(normalized: dict[str, Any] | None, category: dict[str, Any], tool: str) -> tuple[Any, list[dict[str, Any]]]:
    if normalized is None:
        return None, []
    mode = category.get("mode")
    if mode == "component_set":
        facts = normalized.get("facts", {})
        names = facts.get(category.get("fact_key"))
        count = facts.get(category.get("count_key"))
        return {
            "names": names,
            "count": count,
            "definition": category.get("definition", "explicit-exported"),
        }, finding_hits(normalized, category, tool)
    if mode in {"boolean", "count"}:
        value = normalized.get("facts", {}).get(category.get("fact_key"))
        hits = finding_hits(normalized, category, tool)
        if value is None and mode == "boolean" and hits:
            value = True
        return value, hits
    hits = finding_hits(normalized, category, tool)
    if mode == "finding_presence":
        return bool(hits), hits
    return len(hits), hits


def component_comparison(
    sm_value: dict[str, Any], mb_value: dict[str, Any]
) -> tuple[str, dict[str, Any]]:
    sm_names = sm_value.get("names")
    mb_names = mb_value.get("names")
    sm_count = collection_count(sm_value.get("count"))
    mb_count = collection_count(mb_value.get("count"))
    details: dict[str, Any] = {
        "base_comparacao": "nomes" if sm_names is not None and mb_names is not None else "quantidade_fallback",
        "componentes_comuns": [],
        "somente_smaliris_componentes": [],
        "somente_mobsf_componentes": [],
    }
    if sm_names is not None and mb_names is not None:
        sm_set = set(sm_names)
        mb_set = set(mb_names)
        details["componentes_comuns"] = sorted(sm_set & mb_set)
        details["somente_smaliris_componentes"] = sorted(sm_set - mb_set)
        details["somente_mobsf_componentes"] = sorted(mb_set - sm_set)
        if sm_set == mb_set:
            return ("concordancia_ausencia" if not sm_set else "concordancia"), details
        if sm_set and not mb_set:
            return "somente_smaliris", details
        if mb_set and not sm_set:
            return "somente_mobsf", details
        return "componentes_divergentes", details
    if sm_count is None or mb_count is None:
        return "inconclusivo", details
    if sm_count == mb_count:
        return ("concordancia_ausencia" if sm_count == 0 else "concordancia"), details
    if sm_count and not mb_count:
        return "somente_smaliris", details
    if mb_count and not sm_count:
        return "somente_mobsf", details
    return "quantidade_divergente", details


def compare_values(sm_value: Any, mb_value: Any, category: dict[str, Any]) -> str:
    if not category.get("comparable", False) or not (
        category.get("smaliris_supported") and category.get("mobsf_supported")
    ):
        return "nao_comparavel"
    if sm_value is None or mb_value is None:
        return "inconclusivo"
    if category.get("mode") == "component_set":
        if not isinstance(sm_value, dict) or not isinstance(mb_value, dict):
            return "inconclusivo"
        return component_comparison(sm_value, mb_value)[0]
    if sm_value == mb_value:
        if category.get("mode") == "count":
            return "concordancia_ausencia" if sm_value == 0 else "concordancia"
        if category.get("mode") in {"boolean", "finding", "finding_presence"}:
            absent = sm_value is False or sm_value == 0
            return "concordancia_ausencia" if absent else "concordancia"
        return "concordancia"
    sm_present = bool(sm_value)
    mb_present = bool(mb_value)
    if sm_present and not mb_present:
        return "somente_smaliris"
    if mb_present and not sm_present:
        return "somente_mobsf"
    return "quantidade_divergente"


def display_category_value(value: Any, mode: str) -> Any:
    if mode != "component_set" or not isinstance(value, dict):
        return value
    count = collection_count(value.get("count"))
    if count is not None:
        return count
    names = value.get("names")
    return len(names) if isinstance(names, list) else None


def evidence_text(items: list[dict[str, Any]], limit: int = 5) -> str:
    values: list[str] = []
    for item in items:
        label = str(first_present(item.get("rule_id"), item.get("id"), "") or "")
        title = str(item.get("title") or "")
        value = f"{label}: {title}".strip(": ")
        if value and value not in values:
            values.append(value)
    if len(values) > limit:
        return " | ".join(values[:limit]) + f" | +{len(values) - limit}"
    return " | ".join(values)


def make_comparison_rows(
    pairs: list[tuple[ReportFile | None, ReportFile | None, str]],
    catalog: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    app_rows: list[dict[str, Any]] = []
    category_rows: list[dict[str, Any]] = []
    severity_mapping = catalog.get("mobsf_severity_mapping") or {}

    for sm_record, mb_record, match_method in pairs:
        sm = normalize_smaliris(sm_record) if sm_record else None
        mb = normalize_mobsf(mb_record, severity_mapping) if mb_record else None
        sha256 = first_present(sm and sm.get("sha256"), mb and mb.get("sha256"), "")
        file_name = str(first_present(sm and sm.get("file_name"), mb and mb.get("file_name"), "") or "")
        category = str(first_present(sm and sm.get("category"), mb and mb.get("category"), "sem_categoria") or "sem_categoria")
        package = str(first_present(sm and sm.get("package"), mb and mb.get("package"), "") or "")
        statuses = Counter()

        for definition in catalog.get("categories") or []:
            sm_value, sm_hits = category_value(sm, definition, "smaliris")
            mb_value, mb_hits = category_value(mb, definition, "mobsf")
            comparison_details = {
                "base_comparacao": definition.get("mode"),
                "componentes_comuns": [],
                "somente_smaliris_componentes": [],
                "somente_mobsf_componentes": [],
            }
            if sm is None:
                status = "relatorio_smaliris_ausente"
            elif mb is None:
                status = "relatorio_mobsf_ausente"
            else:
                status = compare_values(sm_value, mb_value, definition)
                if definition.get("mode") == "component_set" and isinstance(sm_value, dict) and isinstance(mb_value, dict):
                    status, comparison_details = component_comparison(sm_value, mb_value)
            statuses[status] += 1
            mode = str(definition.get("mode") or "")
            sm_names = sm_value.get("names") if isinstance(sm_value, dict) else None
            mb_names = mb_value.get("names") if isinstance(mb_value, dict) else None
            category_rows.append(
                {
                    "sha256": sha256,
                    "arquivo": file_name,
                    "categoria_apk": category,
                    "pacote": package,
                    "pareamento": match_method,
                    "categoria_id": definition.get("id"),
                    "categoria_titulo": definition.get("title"),
                    "escopo": definition.get("scope"),
                    "modo": definition.get("mode"),
                    "comparavel": bool(definition.get("comparable")),
                    "smaliris_suporta": bool(definition.get("smaliris_supported")),
                    "mobsf_suporta": bool(definition.get("mobsf_supported")),
                    "definicao_comparacao": definition.get("definition", mode),
                    "base_comparacao": comparison_details["base_comparacao"],
                    "smaliris_valor": display_category_value(sm_value, mode),
                    "mobsf_valor": display_category_value(mb_value, mode),
                    "smaliris_componentes": sm_names,
                    "mobsf_componentes": mb_names,
                    "componentes_comuns": comparison_details["componentes_comuns"],
                    "somente_smaliris_componentes": comparison_details["somente_smaliris_componentes"],
                    "somente_mobsf_componentes": comparison_details["somente_mobsf_componentes"],
                    "resultado": status,
                    "smaliris_evidence_count": len(sm_hits),
                    "mobsf_evidence_count": len(mb_hits),
                    "smaliris_evidencias": evidence_text(sm_hits),
                    "mobsf_evidencias": evidence_text(mb_hits),
                }
            )

        app_rows.append(
            {
                "sha256": sha256,
                "arquivo": file_name,
                "categoria_apk": category,
                "pacote": package,
                "pareamento": match_method,
                "smaliris_presente": sm is not None,
                "mobsf_presente": mb is not None,
                "smaliris_versao": sm.get("tool_version", "") if sm else "",
                "mobsf_versao": mb.get("tool_version", "") if mb else "",
                "smaliris_achados": sm.get("reported_finding_count") if sm else None,
                "mobsf_achados": mb.get("reported_finding_count") if mb else None,
                "smaliris_altos": nested_get(sm or {}, "severity_counts", "high"),
                "mobsf_altos": nested_get(mb or {}, "severity_counts", "high"),
                "smaliris_tempo_segundos": sm.get("duration_seconds") if sm else None,
                "mobsf_tempo_segundos": mb.get("duration_seconds") if mb else None,
                "mobsf_security_score": mb.get("security_score") if mb else None,
                "smaliris_exportados_efetivos": nested_get(sm or {}, "facts", "exported_component_count"),
                "smaliris_exportados_explicitos": nested_get(sm or {}, "facts", "explicit_exported_component_count"),
                "mobsf_exportados": nested_get(mb or {}, "facts", "exported_component_count"),
                "concordancias": statuses["concordancia"] + statuses["concordancia_ausencia"],
                "divergencias": (
                    statuses["somente_smaliris"]
                    + statuses["somente_mobsf"]
                    + statuses["quantidade_divergente"]
                    + statuses["componentes_divergentes"]
                ),
                "inconclusivos": statuses["inconclusivo"],
                "nao_comparaveis": statuses["nao_comparavel"],
                "smaliris_relatorio": sm.get("report_path", "") if sm else "",
                "mobsf_relatorio": mb.get("report_path", "") if mb else "",
            }
        )
    return app_rows, category_rows


def ground_truth_expected(value: Any) -> bool | None:
    if isinstance(value, dict):
        value = value.get("expected")
    return as_bool(value)


def load_ground_truth(path: Path | None) -> dict[str, dict[str, bool]]:
    if path is None:
        return {}
    data = load_json(path)
    result: dict[str, dict[str, bool]] = {}
    for app in data.get("apps") or []:
        if not isinstance(app, dict) or not isinstance(app.get("categories"), dict):
            continue
        key = normalize_sha256(app.get("sha256")) or normalized_name_key(str(app.get("file_name") or ""))
        if key:
            categories: dict[str, bool] = {}
            for category, raw_expected in app["categories"].items():
                expected = ground_truth_expected(raw_expected)
                if expected is not None:
                    categories[str(category)] = expected
            if categories:
                result[key] = categories
    return result


def build_ground_truth_template(
    app_rows: list[dict[str, Any]], catalog: dict[str, Any]
) -> dict[str, Any]:
    comparable = [
        definition
        for definition in catalog.get("categories") or []
        if definition.get("comparable")
        and definition.get("smaliris_supported")
        and definition.get("mobsf_supported")
    ]
    apps: list[dict[str, Any]] = []
    for app in app_rows:
        apps.append(
            {
                "sha256": app.get("sha256") or None,
                "file_name": app.get("arquivo"),
                "group": app.get("categoria_apk"),
                "categories": {
                    str(definition.get("id")): {
                        "expected": None,
                        "evidence_source": "",
                        "notes": "",
                    }
                    for definition in comparable
                },
            }
        )
    return {
        "schema_version": "1.1",
        "generated_by": f"SMALIRIS Comparison Tool {COMPARATOR_VERSION}",
        "instructions": (
            "Preencha expected somente com true ou false após revisão independente. "
            "Valores null são ignorados nas métricas. O MobSF não deve ser usado como gabarito."
        ),
        "apps": apps,
    }


def detected_presence(value: Any) -> bool:
    if isinstance(value, dict):
        names = value.get("names")
        if isinstance(names, list):
            return bool(names)
        return bool(value.get("count"))
    return bool(value)


def classification_metrics(category_rows: list[dict[str, Any]], oracle: dict[str, dict[str, bool]]) -> list[dict[str, Any]]:
    counters: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
    for row in category_rows:
        key = normalize_sha256(row.get("sha256")) or normalized_name_key(str(row.get("arquivo") or ""))
        expected_categories = oracle.get(key, {})
        category_id = str(row.get("categoria_id") or "")
        if category_id not in expected_categories:
            continue
        expected = expected_categories[category_id]
        for tool, support_key, value_key in (
            ("SMALIRIS", "smaliris_suporta", "smaliris_valor"),
            ("MobSF", "mobsf_suporta", "mobsf_valor"),
        ):
            if not row.get(support_key) or row.get(value_key) is None:
                continue
            detected = detected_presence(row.get(value_key))
            label = "tp" if expected and detected else "fn" if expected else "fp" if detected else "tn"
            counters[(tool, category_id)][label] += 1
            counters[(tool, "TOTAL")][label] += 1

    rows: list[dict[str, Any]] = []
    for (tool, category_id), values in sorted(counters.items()):
        tp, fp, fn, tn = (values[key] for key in ("tp", "fp", "fn", "tn"))
        precision = tp / (tp + fp) if tp + fp else None
        recall = tp / (tp + fn) if tp + fn else None
        f1 = 2 * precision * recall / (precision + recall) if precision is not None and recall is not None and precision + recall else None
        rows.append(
            {
                "ferramenta": tool,
                "categoria_id": category_id,
                "vp": tp,
                "fp": fp,
                "fn": fn,
                "vn": tn,
                "amostras": tp + fp + fn + tn,
                "precisao": precision,
                "revocacao": recall,
                "f1": f1,
            }
        )
    return rows


def ground_truth_summary(
    oracle: dict[str, dict[str, bool]], app_rows: list[dict[str, Any]], catalog: dict[str, Any]
) -> dict[str, Any]:
    comparable_ids = {
        str(definition.get("id"))
        for definition in catalog.get("categories") or []
        if definition.get("comparable")
        and definition.get("smaliris_supported")
        and definition.get("mobsf_supported")
    }
    app_keys = {
        normalize_sha256(app.get("sha256"))
        or normalized_name_key(str(app.get("arquivo") or ""))
        for app in app_rows
    }
    possible = len(app_rows) * len(comparable_ids)
    labels = sum(
        1
        for key, categories in oracle.items()
        if key in app_keys
        for category_id in categories
        if category_id in comparable_ids
    )
    return {
        "provided": bool(oracle),
        "apps_with_labels": sum(1 for key in oracle if key in app_keys),
        "labels_provided": labels,
        "possible_labels": possible,
        "coverage": labels / possible if possible else None,
    }


def build_manual_review_rows(category_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    review_statuses = DIVERGENCE_STATUSES | {"inconclusivo"}
    for row in category_rows:
        if row.get("resultado") not in review_statuses or not row.get("comparavel"):
            continue
        review_type = "componentes" if row.get("modo") == "component_set" else "codigo" if row.get("escopo") == "code" else "manifesto"
        rows.append(
            {
                **row,
                "tipo_revisao": review_type,
                "prioridade_revisao": "alta" if review_type == "codigo" else "media",
                "decisao_gabarito": "",
                "fonte_gabarito": "",
                "justificativa": "",
                "revisor": "",
                "data_revisao": "",
            }
        )
    return rows


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str] | None = None) -> None:
    if fieldnames is None:
        fieldnames = list(rows[0]) if rows else []
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        if not fieldnames:
            stream.write("")
            return
        writer = csv.DictWriter(stream, fieldnames=fieldnames, delimiter=";", extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            serialized = {
                key: (
                    json.dumps(value, ensure_ascii=False, sort_keys=True)
                    if isinstance(value, (list, dict, tuple, set))
                    else value
                )
                for key, value in row.items()
            }
            writer.writerow(serialized)


def json_serializable(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"Tipo não serializável: {type(value)!r}")


def write_html(
    path: Path,
    summary: dict[str, Any],
    app_rows: list[dict[str, Any]],
    category_rows: list[dict[str, Any]],
    metrics_rows: list[dict[str, Any]],
    ground_truth_info: dict[str, Any],
) -> None:
    status_counts = summary["comparison_statuses"]
    cards = [
        ("APKs pareados", summary["paired_apks"]),
        ("Concordâncias", status_counts.get("concordancia", 0) + status_counts.get("concordancia_ausencia", 0)),
        ("Divergências", summary["divergence_count"]),
        ("Não comparáveis", status_counts.get("nao_comparavel", 0)),
    ]

    def esc(value: Any) -> str:
        if value is None:
            return "—"
        if isinstance(value, bool):
            return "Sim" if value else "Não"
        return html.escape(str(value))

    app_body = "".join(
        "<tr>"
        + "".join(
            f"<td>{esc(row.get(key))}</td>"
            for key in ("arquivo", "categoria_apk", "pareamento", "smaliris_achados", "mobsf_achados", "concordancias", "divergencias")
        )
        + "</tr>"
        for row in app_rows
    )
    divergent = [
        row
        for row in category_rows
        if row["resultado"] in DIVERGENCE_STATUSES | {"inconclusivo"}
    ]
    divergence_body = "".join(
        "<tr>"
        + "".join(
            f"<td>{esc(row.get(key))}</td>"
            for key in ("arquivo", "categoria_titulo", "smaliris_valor", "mobsf_valor", "resultado")
        )
        + "</tr>"
        for row in divergent
    ) or '<tr><td colspan="5">Nenhuma divergência comparável.</td></tr>'
    metrics_section = ""
    if metrics_rows:
        body = "".join(
            "<tr>" + "".join(f"<td>{esc(row.get(key))}</td>" for key in ("ferramenta", "categoria_id", "amostras", "vp", "fp", "fn", "vn", "precisao", "revocacao", "f1")) + "</tr>"
            for row in metrics_rows
        )
        metrics_section = f"""
        <section><h2>Métricas com gabarito</h2><div class="table"><table>
        <thead><tr><th>Ferramenta</th><th>Categoria</th><th>Amostras</th><th>VP</th><th>FP</th><th>FN</th><th>VN</th><th>Precisão</th><th>Revocação</th><th>F1</th></tr></thead>
        <tbody>{body}</tbody></table></div></section>"""
    else:
        metrics_section = """
        <section><h2>Métricas com gabarito</h2>
        <p>Nenhuma métrica foi calculada. Preencha o arquivo <code>ground_truth_template.json</code>
        com valores independentes e execute novamente usando <code>--ground-truth</code>.</p></section>"""

    gt_coverage = ground_truth_info.get("coverage")
    gt_text = "—" if gt_coverage is None else f"{gt_coverage:.1%}"

    document = f"""<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Comparação SMALIRIS × MobSF</title>
<style>
:root{{--blue:#053f88;--ink:#0b1323;--muted:#526786;--bg:#f3f6fb;--line:#c7d4ea;--warn:#f6a730}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 system-ui,Segoe UI,sans-serif}}
main{{max-width:1280px;margin:auto;padding:28px}}h1{{margin:0;color:var(--blue)}}.sub{{color:var(--muted);margin:6px 0 24px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px}}.card,section{{background:white;border:1px solid var(--line);border-radius:12px;padding:18px;box-shadow:0 5px 16px #053f8810}}
.card strong{{display:block;font-size:28px;color:var(--blue)}}section{{margin-top:18px}}h2{{margin-top:0}}.table{{overflow:auto}}table{{border-collapse:collapse;width:100%;min-width:760px}}th,td{{padding:9px 10px;border-bottom:1px solid #e5ebf4;text-align:left;vertical-align:top}}th{{background:#eaf0f8;color:var(--blue)}}code{{background:#eaf0f8;padding:2px 5px;border-radius:4px}}
</style></head><body><main>
<h1>Comparação SMALIRIS × MobSF</h1><p class="sub">Comparador v{COMPARATOR_VERSION} · catálogo {esc(summary.get('catalog_version'))} · {esc(summary.get('generated_at'))}</p>
<div class="cards">{''.join(f'<div class="card"><span>{esc(label)}</span><strong>{esc(value)}</strong></div>' for label,value in cards)}</div>
<section><h2>Resultados por APK</h2><div class="table"><table><thead><tr><th>APK</th><th>Grupo</th><th>Pareamento</th><th>SMALIRIS</th><th>MobSF</th><th>Concordâncias</th><th>Divergências</th></tr></thead><tbody>{app_body}</tbody></table></div></section>
<section><h2>Divergências para revisão</h2><div class="table"><table><thead><tr><th>APK</th><th>Categoria</th><th>SMALIRIS</th><th>MobSF</th><th>Resultado</th></tr></thead><tbody>{divergence_body}</tbody></table></div></section>
{metrics_section}
<section><h2>Cobertura do gabarito</h2><p>{esc(ground_truth_info.get('labels_provided'))} de {esc(ground_truth_info.get('possible_labels'))} rótulos preenchidos ({gt_text}).</p></section>
<section><h2>Interpretação</h2><p>MobSF não é utilizado como gabarito. Categorias fora do escopo de uma ferramenta são marcadas como <code>nao_comparavel</code>. Falsos positivos e falsos negativos só são calculados quando um gabarito independente é fornecido.</p></section>
</main></body></html>"""
    path.write_text(document, encoding="utf-8")


def build_summary(
    smaliris_reports: list[ReportFile],
    mobsf_reports: list[ReportFile],
    app_rows: list[dict[str, Any]],
    category_rows: list[dict[str, Any]],
    catalog: dict[str, Any],
    warnings: list[str],
) -> dict[str, Any]:
    statuses = Counter(str(row["resultado"]) for row in category_rows)
    return {
        "comparator": "SMALIRIS Comparison Tool",
        "comparator_version": COMPARATOR_VERSION,
        "catalog_version": catalog.get("catalog_version"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "smaliris_reports": len(smaliris_reports),
        "mobsf_reports": len(mobsf_reports),
        "registered_apks": len(app_rows),
        "paired_apks": sum(1 for row in app_rows if row["smaliris_presente"] and row["mobsf_presente"]),
        "paired_by_sha256": sum(1 for row in app_rows if row["pareamento"] == "sha256"),
        "paired_by_filename": sum(1 for row in app_rows if row["pareamento"] == "filename_fallback"),
        "unmatched_apks": sum(1 for row in app_rows if row["pareamento"] == "unmatched"),
        "comparison_statuses": dict(sorted(statuses.items())),
        "divergence_count": sum(statuses[name] for name in DIVERGENCE_STATUSES),
        "warnings": warnings,
    }


def run_comparison(
    smaliris_root: Path,
    mobsf_root: Path,
    output_root: Path,
    catalog_path: Path = DEFAULT_CATALOG,
    ground_truth_path: Path | None = None,
) -> dict[str, Any]:
    warnings: list[str] = []
    catalog = load_json(catalog_path)
    smaliris_reports = discover_reports(smaliris_root, "smaliris", warnings)
    mobsf_reports = discover_reports(mobsf_root, "mobsf", warnings)
    if not smaliris_reports:
        raise ValueError(f"Nenhum manifest_analysis.json encontrado em {smaliris_root}")
    if not mobsf_reports:
        raise ValueError(f"Nenhum report.json encontrado em {mobsf_root}")

    pairs = pair_reports(smaliris_reports, mobsf_reports, warnings)
    app_rows, category_rows = make_comparison_rows(pairs, catalog)
    oracle = load_ground_truth(ground_truth_path)
    metrics_rows = classification_metrics(category_rows, oracle)
    ground_truth_info = ground_truth_summary(oracle, app_rows, catalog)
    summary = build_summary(
        smaliris_reports,
        mobsf_reports,
        app_rows,
        category_rows,
        catalog,
        warnings,
    )

    output_root.mkdir(parents=True, exist_ok=True)
    divergences = [
        row
        for row in category_rows
        if row["resultado"]
        in DIVERGENCE_STATUSES
        | {"inconclusivo", "relatorio_smaliris_ausente", "relatorio_mobsf_ausente"}
    ]
    manual_review_rows = build_manual_review_rows(category_rows)
    ground_truth_template = build_ground_truth_template(app_rows, catalog)
    write_csv(output_root / "comparacao_apks.csv", app_rows)
    write_csv(output_root / "comparacao_categorias.csv", category_rows)
    write_csv(output_root / "divergencias.csv", divergences, list(category_rows[0]) if category_rows else [])
    write_csv(
        output_root / "revisao_manual.csv",
        manual_review_rows,
        (
            list(category_rows[0])
            + [
                "tipo_revisao",
                "prioridade_revisao",
                "decisao_gabarito",
                "fonte_gabarito",
                "justificativa",
                "revisor",
                "data_revisao",
            ]
            if category_rows
            else []
        ),
    )
    write_csv(
        output_root / "metricas_gabarito.csv",
        metrics_rows,
        ["ferramenta", "categoria_id", "amostras", "vp", "fp", "fn", "vn", "precisao", "revocacao", "f1"],
    )
    (output_root / "ground_truth_template.json").write_text(
        json.dumps(ground_truth_template, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    report = {
        "summary": summary,
        "inputs": {
            "smaliris": str(smaliris_root.resolve()),
            "mobsf": str(mobsf_root.resolve()),
            "catalog": str(catalog_path.resolve()),
            "ground_truth": str(ground_truth_path.resolve()) if ground_truth_path else None,
        },
        "applications": app_rows,
        "comparisons": category_rows,
        "manual_review": manual_review_rows,
        "ground_truth_summary": ground_truth_info,
        "ground_truth_metrics": metrics_rows,
    }
    (output_root / "comparison_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, default=json_serializable),
        encoding="utf-8",
    )
    write_html(
        output_root / "comparison_report.html",
        summary,
        app_rows,
        category_rows,
        metrics_rows,
        ground_truth_info,
    )
    return report


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compara relatórios JSON da SMALIRIS e do MobSF por SHA-256."
    )
    parser.add_argument("--smaliris", required=True, type=Path, help="Pasta com manifest_analysis.json")
    parser.add_argument("--mobsf", required=True, type=Path, help="Pasta com report.json do MobSF")
    parser.add_argument("--output", default=Path("comparacao"), type=Path, help="Pasta de saída")
    parser.add_argument("--catalog", default=DEFAULT_CATALOG, type=Path, help="Catálogo de equivalências")
    parser.add_argument("--ground-truth", type=Path, help="Gabarito opcional em JSON")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report = run_comparison(
            args.smaliris,
            args.mobsf,
            args.output,
            args.catalog,
            args.ground_truth,
        )
    except (OSError, ValueError, json.JSONDecodeError, re.error) as exc:
        print(f"[-] Erro: {exc}", file=sys.stderr)
        return 1

    summary = report["summary"]
    print("[+] Comparação concluída")
    print(f"    Relatórios SMALIRIS: {summary['smaliris_reports']}")
    print(f"    Relatórios MobSF: {summary['mobsf_reports']}")
    print(f"    APKs pareados: {summary['paired_apks']}")
    print(f"      Por SHA-256: {summary['paired_by_sha256']}")
    print(f"      Por nome (fallback): {summary['paired_by_filename']}")
    print(f"    APKs sem par: {summary['unmatched_apks']}")
    print(f"    Divergências comparáveis: {summary['divergence_count']}")
    gt = report.get("ground_truth_summary") or {}
    print(f"    Rótulos no gabarito: {gt.get('labels_provided', 0)}/{gt.get('possible_labels', 0)}")
    print(f"    Revisões manuais pendentes: {len(report.get('manual_review') or [])}")
    print(f"    Saída: {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
