"""Extração e análise de segurança do AndroidManifest.xml."""

from __future__ import annotations

import itertools
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


ANDROID_URI = "http://schemas.android.com/apk/res/android"
COMPONENT_TYPES = (
    "activity",
    "activity-alias",
    "service",
    "receiver",
    "provider",
)

ACTION_VIEW = "android.intent.action.VIEW"
ACTION_MAIN = "android.intent.action.MAIN"
CATEGORY_BROWSABLE = "android.intent.category.BROWSABLE"
CATEGORY_DEFAULT = "android.intent.category.DEFAULT"
CATEGORY_LAUNCHER = "android.intent.category.LAUNCHER"

PATH_ATTRIBUTES = (
    "path",
    "pathPrefix",
    "pathPattern",
    "pathAdvancedPattern",
    "pathSuffix",
)

APKTOOL_SDK_PATTERN = re.compile(
    r"^\s*(minSdkVersion|targetSdkVersion):\s*['\"]?([^'\"#\s]+)"
)


def android_attr(name: str) -> str:
    """Converte um atributo Android para a representação QName do ElementTree."""
    return f"{{{ANDROID_URI}}}{name}"


def parse_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    return None


def parse_optional_int(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def read_apktool_sdk(apktool_yml_path: Path | None) -> dict[str, int]:
    """Lê somente os SDKs necessários do apktool.yml, sem depender de PyYAML."""
    if apktool_yml_path is None or not apktool_yml_path.is_file():
        return {}

    values: dict[str, int] = {}
    for line in apktool_yml_path.read_text(
        encoding="utf-8",
        errors="replace",
    ).splitlines():
        match = APKTOOL_SDK_PATTERN.match(line)
        if match is None:
            continue
        parsed = parse_optional_int(match.group(2))
        if parsed is not None:
            values[match.group(1)] = parsed
    return values


class ManifestAnalyzer:
    """Produz inventário e achados a partir de um manifesto decodificado."""

    def __init__(
        self,
        manifest_path: str | Path,
        apktool_yml_path: str | Path | None = None,
    ) -> None:
        self.manifest_path = Path(manifest_path)
        self.apktool_yml_path = (
            Path(apktool_yml_path) if apktool_yml_path is not None else None
        )
        if not self.manifest_path.is_file():
            raise FileNotFoundError(
                f"AndroidManifest.xml não encontrado: {self.manifest_path}"
            )

        try:
            self.root = ET.parse(self.manifest_path).getroot()
        except ET.ParseError as error:
            raise ValueError(f"AndroidManifest.xml inválido: {error}") from error

        self.package = self.root.get("package", "")
        self.application = self.root.find("application")
        if self.application is None:
            raise ValueError("Manifesto sem o elemento obrigatório <application>.")

        uses_sdk = self.root.find("uses-sdk")
        min_raw = (
            uses_sdk.get(android_attr("minSdkVersion"))
            if uses_sdk is not None
            else None
        )
        target_raw = (
            uses_sdk.get(android_attr("targetSdkVersion"))
            if uses_sdk is not None
            else None
        )
        manifest_min_sdk = parse_optional_int(min_raw)
        manifest_target_sdk = parse_optional_int(target_raw)
        apktool_sdk = read_apktool_sdk(self.apktool_yml_path)

        if manifest_min_sdk is not None:
            self.min_sdk = manifest_min_sdk
            self.min_sdk_source = "manifest"
        elif "minSdkVersion" in apktool_sdk:
            self.min_sdk = apktool_sdk["minSdkVersion"]
            self.min_sdk_source = "apktool.yml"
        else:
            self.min_sdk = 1
            self.min_sdk_source = "android-default"

        if manifest_target_sdk is not None:
            self.target_sdk = manifest_target_sdk
            self.target_sdk_source = "manifest"
        elif "targetSdkVersion" in apktool_sdk:
            self.target_sdk = apktool_sdk["targetSdkVersion"]
            self.target_sdk_source = "apktool.yml"
        else:
            self.target_sdk = self.min_sdk
            self.target_sdk_source = "min-sdk-default"
        self.app_permission = self.application.get(android_attr("permission"))
        self.app_enabled = parse_bool(
            self.application.get(android_attr("enabled"))
        )
        self.app_debuggable = parse_bool(
            self.application.get(android_attr("debuggable"))
        )
        self.declared_permission_levels = {
            permission.get(android_attr("name")): permission.get(
                android_attr("protectionLevel"), "normal"
            )
            for permission in self.root.findall("permission")
            if permission.get(android_attr("name"))
        }

    def analyze(self) -> dict[str, Any]:
        components: list[dict[str, Any]] = []
        findings = self._application_findings()

        for component_type in COMPONENT_TYPES:
            for element in self.application.findall(component_type):
                component = self._parse_component(component_type, element)
                components.append(component)
                findings.extend(self._component_findings(component))
                for intent_filter in component["intent_filters"]:
                    findings.extend(
                        self._deep_link_findings(component, intent_filter)
                    )

        return {
            "schema_version": "2.0",
            "manifest_path": str(self.manifest_path),
            "package": self.package,
            "sdk": {
                "min": self.min_sdk,
                "target": self.target_sdk,
                "source": {
                    "min": self.min_sdk_source,
                    "target": self.target_sdk_source,
                },
            },
            "application": {
                "enabled": self.app_enabled is not False,
                "permission": self.app_permission,
                "debuggable": self.app_debuggable,
                "uses_cleartext_traffic": parse_bool(
                    self.application.get(android_attr("usesCleartextTraffic"))
                ),
            },
            "requested_permissions": self._requested_permissions(),
            "declared_permissions": self._declared_permissions(),
            "components": components,
            "findings": findings,
            "summary": self._summary(components, findings),
            "limitations": [
                "O manifesto comprova exposição, não exploração prática.",
                "autoVerify=true não comprova que assetlinks.json foi validado.",
                "Validação de entradas e Intent Injection exigem correlação com o código.",
                "Permissões externas exigem uma base Android para classificar seu nível.",
            ],
        }

    def _application_findings(self) -> list[dict[str, Any]]:
        if self.app_debuggable is not True:
            return []
        return [
            {
                "rule_id": "APP-DEBUG-001",
                "title": "Aplicação com depuração habilitada",
                "severity": "high",
                "confidence": "high",
                "component": self.package or None,
                "component_type": "application",
                "evidence": (
                    'android:debuggable="true" está declarado no elemento '
                    "<application>."
                ),
                "recommendation": (
                    "Desabilitar a depuração na variante distribuída e garantir "
                    "android:debuggable=false no artefato de produção."
                ),
            }
        ]

    def _requested_permissions(self) -> list[str]:
        result: set[str] = set()
        for tag in ("uses-permission", "uses-permission-sdk-23"):
            for element in self.root.findall(tag):
                name = element.get(android_attr("name"))
                if name:
                    result.add(name)
        return sorted(result)

    def _declared_permissions(self) -> list[dict[str, str]]:
        return [
            {
                "name": name,
                "protection_level": protection_level,
            }
            for name, protection_level in sorted(
                self.declared_permission_levels.items()
            )
        ]

    def _parse_component(
        self,
        component_type: str,
        element: ET.Element,
    ) -> dict[str, Any]:
        intent_filters = [
            self._parse_intent_filter(item)
            for item in element.findall("intent-filter")
        ]
        exported, exported_source = self._effective_exported(
            component_type,
            element,
            bool(intent_filters),
        )

        component_enabled = parse_bool(element.get(android_attr("enabled")))
        enabled = self.app_enabled is not False and component_enabled is not False

        # Activity aliases têm sua própria regra: sem permission no alias,
        # nenhuma permissão é exigida para acionar o destino por meio dele.
        if component_type == "activity-alias":
            permission = element.get(android_attr("permission"))
        else:
            permission = element.get(
                android_attr("permission"),
                self.app_permission,
            )

        read_permission = None
        write_permission = None
        path_permissions: list[dict[str, str]] = []
        if component_type == "provider":
            read_permission = element.get(
                android_attr("readPermission"),
                permission,
            )
            write_permission = element.get(
                android_attr("writePermission"),
                permission,
            )
            path_permissions = self._parse_path_permissions(element)

        return {
            "type": component_type,
            "name": self._qualified_name(
                element.get(android_attr("name"), "")
            ),
            "target_activity": (
                self._qualified_name(
                    element.get(android_attr("targetActivity"), "")
                )
                if component_type == "activity-alias"
                else None
            ),
            "enabled": enabled,
            "exported": exported,
            "exported_source": exported_source,
            "permission": permission,
            "permission_assessment": self._permission_assessment(permission),
            "read_permission": read_permission,
            "write_permission": write_permission,
            "authorities": (
                element.get(android_attr("authorities"))
                if component_type == "provider"
                else None
            ),
            "grant_uri_permissions": (
                parse_bool(element.get(android_attr("grantUriPermissions")))
                if component_type == "provider"
                else None
            ),
            "path_permissions": path_permissions,
            "intent_filters": intent_filters,
        }

    def _effective_exported(
        self,
        component_type: str,
        element: ET.Element,
        has_intent_filter: bool,
    ) -> tuple[bool | None, str]:
        explicit = element.get(android_attr("exported"))
        if explicit is not None:
            return parse_bool(explicit), "explicit"

        if component_type == "provider":
            return (
                self.target_sdk < 17,
                "provider-default-by-target-sdk",
            )

        if has_intent_filter and self.target_sdk >= 31:
            return None, "invalid-missing-exported-for-target-31+"

        if has_intent_filter:
            return True, "inferred-from-intent-filter"

        return False, "default-no-filter"

    def _parse_intent_filter(self, element: ET.Element) -> dict[str, Any]:
        actions = self._child_names(element, "action")
        categories = self._child_names(element, "category")
        data_elements: list[dict[str, str]] = []

        data_attributes = (
            "scheme",
            "host",
            "port",
            *PATH_ATTRIBUTES,
            "mimeType",
        )
        for data_element in element.findall("data"):
            data = {
                name: value
                for name in data_attributes
                if (value := data_element.get(android_attr(name))) is not None
            }
            data_elements.append(data)

        schemes = sorted(
            {item["scheme"] for item in data_elements if item.get("scheme")}
        )
        hosts = sorted(
            {item["host"] for item in data_elements if item.get("host")}
        )
        ports = sorted(
            {item["port"] for item in data_elements if item.get("port")}
        )
        paths = [
            {"kind": path_attribute, "value": item[path_attribute]}
            for item in data_elements
            for path_attribute in PATH_ATTRIBUTES
            if item.get(path_attribute)
        ]

        auto_verify = (
            parse_bool(element.get(android_attr("autoVerify"))) is True
        )
        is_uri_intent = ACTION_VIEW in actions and bool(schemes)
        is_browsable_deep_link = (
            is_uri_intent and CATEGORY_BROWSABLE in categories
        )
        is_app_link_candidate = (
            is_browsable_deep_link
            and auto_verify
            and any(scheme in {"http", "https"} for scheme in schemes)
        )

        return {
            "actions": actions,
            "categories": categories,
            "data": data_elements,
            "schemes": schemes,
            "hosts": hosts,
            "ports": ports,
            "paths": paths,
            "auto_verify": auto_verify,
            "priority": element.get(android_attr("priority")),
            "is_uri_intent": is_uri_intent,
            "is_browsable_deep_link": is_browsable_deep_link,
            "is_app_link_candidate": is_app_link_candidate,
            # Compatibilidade com relatórios 1.0. Remover somente em uma versão 2.0.
            "is_deep_link": is_uri_intent,
            "uri_patterns": self._expand_uri_patterns(
                schemes,
                hosts,
                ports,
                paths,
            ),
        }

    @staticmethod
    def _parse_path_permissions(element: ET.Element) -> list[dict[str, str]]:
        result: list[dict[str, str]] = []
        attributes = (
            "path",
            "pathPrefix",
            "pathPattern",
            "permission",
            "readPermission",
            "writePermission",
        )
        for path_permission in element.findall("path-permission"):
            result.append(
                {
                    name: value
                    for name in attributes
                    if (value := path_permission.get(android_attr(name))) is not None
                }
            )
        return result

    @staticmethod
    def _child_names(element: ET.Element, tag: str) -> list[str]:
        return [
            value
            for child in element.findall(tag)
            if (value := child.get(android_attr("name"))) is not None
        ]

    @staticmethod
    def _expand_uri_patterns(
        schemes: list[str],
        hosts: list[str],
        ports: list[str],
        paths: list[dict[str, str]],
    ) -> list[str]:
        if not schemes:
            return []

        host_values = hosts or [""]
        port_values = ports or [""]
        path_values = [path["value"] for path in paths] or [""]
        patterns: list[str] = []

        for scheme, host, port, path in itertools.product(
            schemes,
            host_values,
            port_values,
            path_values,
        ):
            authority = host
            if port:
                authority = f"{authority}:{port}"
            patterns.append(f"{scheme}://{authority}{path}")

        # Evita relatórios gigantes em filtros artificiais ou maliciosos.
        return patterns[:100]

    def _permission_assessment(self, permission: str | None) -> dict[str, str | None]:
        if permission is None:
            return {"status": "absent", "protection_level": None}

        protection_level = self.declared_permission_levels.get(permission)
        if protection_level is None:
            return {
                "status": "external-or-platform-unknown",
                "protection_level": None,
            }

        normalized = protection_level.lower()
        if "signature" in normalized:
            status = "strong"
        elif "dangerous" in normalized:
            status = "user-granted"
        else:
            status = "weak"

        return {
            "status": status,
            "protection_level": protection_level,
        }

    def _component_findings(
        self,
        component: dict[str, Any],
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        if (
            component["exported_source"]
            == "invalid-missing-exported-for-target-31+"
        ):
            findings.append(
                self._finding(
                    "MANIFEST-001",
                    "Componente sem android:exported obrigatório",
                    "high",
                    component,
                    "O componente possui intent-filter e o targetSdk é 31 ou superior.",
                    "Declare android:exported explicitamente.",
                    "high",
                )
            )

        if component["exported"] is not True or not component["enabled"]:
            return findings

        if component["exported_source"] != "explicit":
            findings.append(
                self._finding(
                    "COMPONENT-INFO-001",
                    "Exportação inferida pelo Android",
                    "info",
                    component,
                    f"Estado calculado a partir de {component['exported_source']}.",
                    "Declare android:exported explicitamente para eliminar ambiguidade.",
                    "high",
                )
            )

        if component["type"] == "provider":
            if not component["read_permission"] or not component["write_permission"]:
                findings.append(
                    self._finding(
                        "PROVIDER-001",
                        "Content Provider exportado sem proteção completa",
                        "high",
                        component,
                        "Permissão de leitura ou escrita ausente no Provider exportado.",
                        "Defina readPermission/writePermission e revise path-permission.",
                        "high",
                    )
                )
            return findings

        if component["permission"] is None:
            if self._is_launcher_only(component):
                findings.append(
                    self._finding(
                        "COMPONENT-INFO-002",
                        "Activity de inicialização exportada",
                        "info",
                        component,
                        "A Activity contém somente o filtro MAIN/LAUNCHER.",
                        "Manter exportada somente se for o ponto de inicialização esperado.",
                        "high",
                    )
                )
            else:
                severity = "high" if component["type"] == "service" else "medium"
                findings.append(
                    self._finding(
                        "COMPONENT-001",
                        "Componente exportado sem permissão declarativa",
                        severity,
                        component,
                        "O componente está habilitado, exportado e não exige permission.",
                        "Confirmar a necessidade da exportação e validar o chamador e as entradas no código.",
                        "high",
                    )
                )
        elif component["permission_assessment"]["status"] == "weak":
            findings.append(
                self._finding(
                    "COMPONENT-002",
                    "Componente protegido por permissão fraca",
                    "medium",
                    component,
                    f"Permissão {component['permission']} com nível normal ou equivalente.",
                    "Use uma permissão signature quando o acesso for exclusivo a apps confiáveis.",
                    "high",
                )
            )

        return findings

    def _deep_link_findings(
        self,
        component: dict[str, Any],
        intent_filter: dict[str, Any],
    ) -> list[dict[str, Any]]:
        if not intent_filter["is_uri_intent"] or component["exported"] is not True:
            return []

        findings: list[dict[str, Any]] = []
        schemes = intent_filter["schemes"]
        hosts = intent_filter["hosts"]
        custom_schemes = [
            scheme for scheme in schemes if scheme not in {"http", "https"}
        ]
        web_schemes = [
            scheme for scheme in schemes if scheme in {"http", "https"}
        ]

        if custom_schemes:
            findings.append(
                self._finding(
                    "DEEPLINK-001",
                    "Filtro de URI com esquema personalizado",
                    "medium",
                    component,
                    "Esquemas não verificáveis pelo Android: "
                    + ", ".join(custom_schemes),
                    "Validar rigorosamente os parâmetros e preferir App Links verificados.",
                    "high",
                )
            )

        if (
            web_schemes
            and intent_filter["is_browsable_deep_link"]
            and not intent_filter["auto_verify"]
        ):
            findings.append(
                self._finding(
                    "DEEPLINK-002",
                    "Web deep link não verificado",
                    "medium",
                    component,
                    "O filtro HTTP(S) não declara android:autoVerify=true.",
                    "Configurar App Links e publicar assetlinks.json quando aplicável.",
                    "high",
                )
            )

        if intent_filter["is_app_link_candidate"]:
            findings.append(
                self._finding(
                    "DEEPLINK-INFO-001",
                    "Candidato a Android App Link",
                    "info",
                    component,
                    "O filtro HTTP(S) declara android:autoVerify=true.",
                    "Confirmar externamente o assetlinks.json e a assinatura do APK.",
                    "medium",
                )
            )

        if not intent_filter["is_browsable_deep_link"]:
            findings.append(
                self._finding(
                    "URI-INFO-001",
                    "Filtro de URI não navegável pelo browser",
                    "info",
                    component,
                    "O filtro possui VIEW e scheme, mas não possui BROWSABLE.",
                    "Manter essa distinção no relatório; outros apps ainda podem enviar uma Intent compatível.",
                    "high",
                )
            )

        if "http" in schemes:
            findings.append(
                self._finding(
                    "DEEPLINK-003",
                    "Deep link aceita esquema HTTP",
                    "low",
                    component,
                    "O filtro aceita URLs sem TLS.",
                    "Avaliar se somente HTTPS é suficiente para o caso de uso.",
                    "high",
                )
            )

        if not hosts or any("*" in host for host in hosts):
            findings.append(
                self._finding(
                    "DEEPLINK-004",
                    "Host de deep link excessivamente amplo",
                    "medium",
                    component,
                    "O filtro não restringe o host ou utiliza wildcard.",
                    "Restringir o filtro aos hosts estritamente necessários.",
                    "high",
                )
            )

        if len(schemes) > 1 and len(hosts) > 1:
            findings.append(
                self._finding(
                    "DEEPLINK-005",
                    "Combinações cruzadas no intent-filter",
                    "medium",
                    component,
                    f"Padrões efetivos calculados: {intent_filter['uri_patterns']}",
                    "Use filtros separados quando schemes e hosts formarem pares exclusivos.",
                    "high",
                )
            )

        if CATEGORY_DEFAULT not in intent_filter["categories"]:
            findings.append(
                self._finding(
                    "DEEPLINK-006",
                    "Filtro de deep link sem categoria DEFAULT",
                    "low",
                    component,
                    "O filtro contém VIEW/BROWSABLE, mas não DEFAULT.",
                    "Adicionar DEFAULT se o link precisar resolver por intent implícita.",
                    "high",
                )
            )

        return findings

    @staticmethod
    def _is_launcher_only(component: dict[str, Any]) -> bool:
        intent_filters = component["intent_filters"]
        return bool(intent_filters) and all(
            set(intent_filter["actions"]) <= {ACTION_MAIN}
            and set(intent_filter["categories"]) <= {CATEGORY_LAUNCHER}
            and not intent_filter["data"]
            for intent_filter in intent_filters
        )

    @staticmethod
    def _finding(
        rule_id: str,
        title: str,
        severity: str,
        component: dict[str, Any],
        evidence: str,
        recommendation: str,
        confidence: str,
    ) -> dict[str, Any]:
        return {
            "rule_id": rule_id,
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "component": component["name"],
            "component_type": component["type"],
            "evidence": evidence,
            "recommendation": recommendation,
        }

    @staticmethod
    def _summary(
        components: list[dict[str, Any]],
        findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        severity_counts = {
            severity: sum(
                finding["severity"] == severity for finding in findings
            )
            for severity in ("high", "medium", "low", "info")
        }
        return {
            "component_count": len(components),
            "exported_component_count": sum(
                component["exported"] is True for component in components
            ),
            "deep_link_filter_count": sum(
                intent_filter["is_uri_intent"]
                for component in components
                for intent_filter in component["intent_filters"]
            ),
            "uri_intent_filter_count": sum(
                intent_filter["is_uri_intent"]
                for component in components
                for intent_filter in component["intent_filters"]
            ),
            "browsable_deep_link_count": sum(
                intent_filter["is_browsable_deep_link"]
                for component in components
                for intent_filter in component["intent_filters"]
            ),
            "app_link_candidate_count": sum(
                intent_filter["is_app_link_candidate"]
                for component in components
                for intent_filter in component["intent_filters"]
            ),
            "finding_count": len(findings),
            "findings_by_severity": severity_counts,
        }

    def _qualified_name(self, name: str) -> str:
        if not name:
            return name
        if name.startswith("."):
            return f"{self.package}{name}"
        if "." not in name:
            return f"{self.package}.{name}"
        return name
