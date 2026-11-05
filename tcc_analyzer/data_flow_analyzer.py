"""Rastreamento conservador de valores entre registradores Smali."""

from __future__ import annotations

import re
from collections import Counter
from copy import deepcopy
from pathlib import Path
from typing import Any

from .api_catalog import (
    EXTERNAL_SOURCE,
    POSSIBLE_VALIDATION,
    PROPAGATOR,
    SENSITIVE_OPERATION,
    ApiCatalog,
    ApiRule,
)

INVOKE_PATTERN = re.compile(
    r"^(?P<opcode>invoke-\S+)\s+\{(?P<registers>[^}]*)\},\s*"
    r"(?P<descriptor>L[^;]+;)->(?P<signature>[^\s#]+)"
)
MOVE_RESULT_PATTERN = re.compile(
    r"^move-result(?:-object|-wide)?(?:/\S+)?\s+(?P<register>[vp]\d+)"
)
MOVE_PATTERN = re.compile(
    r"^move(?:-object|-wide)?(?:/\S+)?\s+"
    r"(?P<destination>[vp]\d+),\s*(?P<source>[vp]\d+)"
)
RETURN_PATTERN = re.compile(
    r"^return(?:-object|-wide)?\s+(?P<register>[vp]\d+)"
)
CONST_PATTERN = re.compile(
    r"^(?P<opcode>const(?:-string|-class|-wide)?(?:/\S+)?)\s+"
    r"(?P<destination>[vp]\d+),\s*(?P<value>.+)$"
)
NEW_INSTANCE_PATTERN = re.compile(
    r"^new-instance\s+(?P<destination>[vp]\d+),\s*"
    r"(?P<descriptor>L[^;]+;)"
)
NEW_ARRAY_PATTERN = re.compile(
    r"^new-array\s+(?P<destination>[vp]\d+),\s*"
    r"(?P<size>[vp]\d+),\s*(?P<descriptor>\S+)"
)
FILLED_NEW_ARRAY_PATTERN = re.compile(
    r"^filled-new-array(?:/range)?\s+\{(?P<registers>[^}]*)\},\s*"
    r"(?P<descriptor>\S+)"
)
INSTANCE_FIELD_PUT_PATTERN = re.compile(
    r"^iput(?:-object|-wide|-boolean|-byte|-char|-short)?\s+"
    r"(?P<source>[vp]\d+),\s*(?P<object>[vp]\d+),\s*"
    r"(?P<field>L[^;]+;->[^\s,]+)"
)
INSTANCE_FIELD_GET_PATTERN = re.compile(
    r"^iget(?:-object|-wide|-boolean|-byte|-char|-short)?\s+"
    r"(?P<destination>[vp]\d+),\s*(?P<object>[vp]\d+),\s*"
    r"(?P<field>L[^;]+;->[^\s,]+)"
)
STATIC_FIELD_PUT_PATTERN = re.compile(
    r"^sput(?:-object|-wide|-boolean|-byte|-char|-short)?\s+"
    r"(?P<source>[vp]\d+),\s*(?P<field>L[^;]+;->[^\s,]+)"
)
STATIC_FIELD_GET_PATTERN = re.compile(
    r"^sget(?:-object|-wide|-boolean|-byte|-char|-short)?\s+"
    r"(?P<destination>[vp]\d+),\s*(?P<field>L[^;]+;->[^\s,]+)"
)
ARRAY_PUT_PATTERN = re.compile(
    r"^aput(?:-object|-wide|-boolean|-byte|-char|-short)?\s+"
    r"(?P<source>[vp]\d+),\s*(?P<array>[vp]\d+),\s*"
    r"(?P<index>[vp]\d+)"
)
ARRAY_GET_PATTERN = re.compile(
    r"^aget(?:-object|-wide|-boolean|-byte|-char|-short)?\s+"
    r"(?P<destination>[vp]\d+),\s*(?P<array>[vp]\d+),\s*"
    r"(?P<index>[vp]\d+)"
)
DECLARED_STATIC_FIELD_PATTERN = re.compile(
    r"^\s*\.field\b(?P<modifiers>.*?)\s+"
    r"(?P<name>[^\s:]+):(?P<type>\S+)\s*=\s*(?P<value>.+?)\s*$"
)
OVERWRITE_PATTERN = re.compile(
    r"^(?:array-length|instance-of)\s+"
    r"(?P<register>[vp]\d+)(?:,|\s)"
)
REGISTER_PATTERN = re.compile(r"^[vp]\d+$")

EXTERNAL_TAINTED = "external-tainted"
INTERFACE_TAINTED = "interface-tainted"
CONSTANT = "constant"
UNKNOWN = "unknown"
USER_INTERFACE_SOURCE_KINDS = {
    "user_input",
    "ui_input",
    "interface_input",
}
CONTAINER_DESCRIPTORS = {
    "Landroid/content/Intent;",
    "Landroid/os/Bundle;",
    "Landroid/content/ContentValues;",
}
INTENT_DESCRIPTOR = "Landroid/content/Intent;"
COMPONENT_NAME_DESCRIPTOR = "Landroid/content/ComponentName;"
IPC_OPERATION_KINDS = {
    "ipc_activity",
    "ipc_service",
    "ipc_broadcast",
}
INTENT_SELECTOR_ATTRIBUTES = (
    "destination",
    "component",
    "action",
    "data",
)

class DataFlowAnalyzer:
    """Segue taint entre registradores sem declarar vulnerabilidade."""

    def __init__(
        self,
        decompiled_dir: str | Path,
        catalog: ApiCatalog | None = None,
        catalog_path: str | Path | None = None,
    ) -> None:
        self.decompiled_dir = Path(decompiled_dir)
        if not self.decompiled_dir.is_dir():
            raise FileNotFoundError(
                "Diretório descompilado não encontrado: "
                f"{self.decompiled_dir}"
            )
        self.decompiled_dir_resolved = self.decompiled_dir.resolve()
        if catalog is not None and catalog_path is not None:
            raise ValueError("Informe catalog ou catalog_path, não ambos.")
        self.catalog = catalog or ApiCatalog(catalog_path)
        self._line_cache: dict[Path, list[str]] = {}

    def analyze(self, analysis: dict[str, Any]) -> dict[str, Any]:
        """Anexa o resultado de fluxo aos entry points analisados."""
        self.application_package = analysis.get("package")
        self.known_components = {
            component.get("name")
            for component in analysis.get("components", [])
            if component.get("name")
        }
        analyzed_component_count = 0
        analyzed_entry_point_count = 0
        analyzed_method_count = 0
        flow_count = 0
        validated_flow_count = 0
        unvalidated_flow_count = 0
        argument_classification_counts: Counter[str] = Counter()
        ipc_transitions: list[dict[str, Any]] = []
        error_count = 0
        problems: list[dict[str, str | None]] = []

        for component in analysis.get("components", []):
            code_analysis = component.get("code_analysis") or {}
            component_result = {
                "status": "skipped",
                "reason": "code-analysis-not-available",
                "entry_point_count": 0,
                "analyzed_method_count": 0,
                "flow_count": 0,
                "validated_flow_count": 0,
                "unvalidated_flow_count": 0,
                "ipc_transition_count": 0,
            }
            component["data_flow_analysis"] = component_result

            if code_analysis.get("status") != "analyzed":
                continue

            analyzed_component_count += 1
            component_result.update(
                {
                    "status": "analyzed",
                    "reason": None,
                    "entry_point_count": len(
                        code_analysis.get("entry_points", [])
                    ),
                }
            )

            for entry_point in code_analysis.get("entry_points", []):
                try:
                    result = self.analyze_entry_point(
                        component,
                        entry_point,
                    )
                except (OSError, ValueError) as error:
                    error_count += 1
                    result = self._error_result(str(error))
                    problems.append(
                        {
                            "component": component.get("name"),
                            "entry_point": entry_point.get("signature"),
                            "reason": str(error),
                        }
                    )

                entry_point["data_flow_analysis"] = result
                analyzed_entry_point_count += result["status"] == "analyzed"
                analyzed_method_count += result["analyzed_method_count"]
                flow_count += result["flow_count"]
                validated_flow_count += result["validated_flow_count"]
                unvalidated_flow_count += result["unvalidated_flow_count"]

                component_result["analyzed_method_count"] += result[
                    "analyzed_method_count"
                ]
                component_result["flow_count"] += result["flow_count"]
                component_result["validated_flow_count"] += result[
                    "validated_flow_count"
                ]
                component_result["unvalidated_flow_count"] += result[
                    "unvalidated_flow_count"
                ]
                component_result["ipc_transition_count"] += result.get(
                    "ipc_transition_count",
                    0,
                )
                argument_classification_counts.update(
                    result.get("argument_classification_counts", {})
                )
                ipc_transitions.extend(result.get("ipc_transitions", []))

        ipc_transitions = self._deduplicate_ipc_transitions(ipc_transitions)
        for index, transition in enumerate(ipc_transitions, start=1):
            transition["transition_id"] = f"IPC-{index:04d}"
        ipc_kinds = Counter(
            transition.get("intent_kind", "unknown")
            for transition in ipc_transitions
        )
        controllable_ipc_count = sum(
            transition.get("selector_classification") == EXTERNAL_TAINTED
            for transition in ipc_transitions
        )
        internal_constant_ipc_count = sum(
            transition.get("explicit_internal_constant") is True
            for transition in ipc_transitions
        )

        summary = analysis.setdefault("summary", {})
        summary.update(
            {
                "data_flow_component_count": analyzed_component_count,
                "data_flow_entry_point_count": analyzed_entry_point_count,
                "data_flow_method_count": analyzed_method_count,
                "data_flow_confirmed_count": flow_count,
                "data_flow_validated_count": validated_flow_count,
                "data_flow_unvalidated_count": unvalidated_flow_count,
                "data_flow_error_count": error_count,
                "ipc_transition_count": len(ipc_transitions),
                "ipc_explicit_transition_count": ipc_kinds.get("explicit", 0),
                "ipc_implicit_transition_count": ipc_kinds.get("implicit", 0),
                "ipc_unknown_transition_count": ipc_kinds.get("unknown", 0),
                "ipc_controllable_transition_count": controllable_ipc_count,
                "ipc_internal_constant_transition_count": (
                    internal_constant_ipc_count
                ),
                "sensitive_argument_classifications": {
                    classification: argument_classification_counts.get(
                        classification,
                        0,
                    )
                    for classification in (
                        EXTERNAL_TAINTED,
                        INTERFACE_TAINTED,
                        CONSTANT,
                        UNKNOWN,
                    )
                },
            }
        )
        return {
            "phase": "bounded-register-data-flow",
            "status": "completed" if error_count == 0 else "partial",
            "component_count": analyzed_component_count,
            "entry_point_count": analyzed_entry_point_count,
            "analyzed_method_count": analyzed_method_count,
            "confirmed_flow_count": flow_count,
            "validated_flow_count": validated_flow_count,
            "unvalidated_flow_count": unvalidated_flow_count,
            "argument_classification_counts": {
                classification: argument_classification_counts.get(
                    classification,
                    0,
                )
                for classification in (
                    EXTERNAL_TAINTED,
                    INTERFACE_TAINTED,
                    CONSTANT,
                    UNKNOWN,
                )
            },
            "ipc_transition_count": len(ipc_transitions),
            "ipc_transitions": ipc_transitions,
            "error_count": error_count,
            "problems": problems,
            "definitive_security_verdicts_generated": False,
            "limitations": self._limitations(),
        }

    def analyze_entry_point(
        self,
        component: dict[str, Any],
        entry_point: dict[str, Any],
    ) -> dict[str, Any]:
        """Analisa um entry point e o subgrafo previamente resolvido."""
        specs = self._method_specs(component, entry_point)
        if not specs:
            return self._error_result("method-specification-not-available")

        root_key = next(
            key for key, spec in specs.items() if spec["depth"] == 0
        )
        flows: list[dict[str, Any]] = []
        method_runs: list[dict[str, Any]] = []
        discovered_sources: list[dict[str, Any]] = []
        touched_validations: list[dict[str, Any]] = []
        sensitive_argument_assessments: list[dict[str, Any]] = []
        executed_keys: set[tuple[str, str]] = set()
        instance_fields: dict[tuple[str, str], dict[str, Any]] = {}
        static_fields = self._declared_static_fields(specs)
        array_elements: dict[tuple[str, str], dict[str, Any]] = {}
        container_values: dict[tuple[str, str], dict[str, Any]] = {}
        intent_profiles: dict[str, dict[str, Any]] = {}
        component_name_profiles: dict[str, dict[str, Any]] = {}
        ipc_transitions: list[dict[str, Any]] = []
        local_container_ids: set[str] = set()
        descriptor_instances: dict[str, list[str]] = {}

        def run_method(
            key: tuple[str, str],
            initial_taints: dict[str, dict[str, Any]],
            active: tuple[tuple[str, str], ...],
        ) -> list[dict[str, Any]]:
            if key in active:
                return []
            spec = specs[key]
            executed_keys.add(key)
            registers = {
                register: deepcopy(state)
                for register, state in initial_taints.items()
            }
            if "static" not in spec.get("modifiers", []) and "p0" not in registers:
                receiver_id = f"this:{spec['descriptor']}"
                registers["p0"] = self._object_state(
                    receiver_id,
                    spec["descriptor"],
                    self._trace_step(
                        "method-receiver",
                        spec,
                        spec["start_line"],
                        f"Receptor p0 de {spec['signature']}",
                        destination="p0",
                    ),
                )
                self._remember_instance(
                    descriptor_instances,
                    spec["descriptor"],
                    receiver_id,
                )
            if spec["depth"] == 0:
                entry_taints = self._entry_point_parameter_taints(
                    component,
                    entry_point,
                    spec,
                )
                registers.update(entry_taints)
                for state in entry_taints.values():
                    if INTENT_DESCRIPTOR not in state.get(
                        "object_descriptors",
                        [],
                    ):
                        continue
                    for object_id in self._object_ids(state):
                        profile = {
                            attribute: deepcopy(state)
                            for attribute in INTENT_SELECTOR_ATTRIBUTES
                        }
                        profile.update(
                            {
                                "__kind_hint__": "unknown",
                                "__origin__": "entry-point",
                            }
                        )
                        intent_profiles[object_id] = profile

            initial_registers = sorted(registers, key=self._register_sort_key)
            for state in registers.values():
                discovered_sources.extend(state.get("sources", []))

            evidence_by_line: dict[int, list[dict[str, Any]]] = {}
            for item in spec.get("evidence", []):
                evidence_by_line.setdefault(item["line"], []).append(item)

            pending_result: dict[str, Any] | None = None
            returned_states: list[dict[str, Any]] = []
            method_flow_start = len(flows)
            method_source_start = len(discovered_sources)
            method_validation_start = len(touched_validations)
            lines = self._lines_for(spec["smali_path"])
            first = max(spec["start_line"] - 1, 0)
            last = min(spec["end_line"], len(lines))

            for line_number in range(first + 1, last + 1):
                instruction = lines[line_number - 1].strip()
                if not instruction or instruction.startswith(("#", ".", ":")):
                    continue

                move_result = MOVE_RESULT_PATTERN.match(instruction)
                if move_result is not None:
                    destination = move_result.group("register")
                    if pending_result is None:
                        registers.pop(destination, None)
                    else:
                        state = deepcopy(pending_result)
                        self._set_source_result_register(state, destination)
                        state["trace"].append(
                            self._trace_step(
                                "move-result",
                                spec,
                                line_number,
                                instruction,
                                destination=destination,
                            )
                        )
                        registers[destination] = state
                    pending_result = None
                    continue

                pending_result = None

                move = MOVE_PATTERN.match(instruction)
                if move is not None:
                    destination = move.group("destination")
                    source = move.group("source")
                    if source in registers:
                        state = deepcopy(registers[source])
                        state["trace"].append(
                            self._trace_step(
                                "move",
                                spec,
                                line_number,
                                instruction,
                                source=source,
                                destination=destination,
                            )
                        )
                        registers[destination] = state
                    else:
                        registers.pop(destination, None)
                    continue

                constant = CONST_PATTERN.match(instruction)
                if constant is not None:
                    destination = constant.group("destination")
                    registers[destination] = self._constant_state(
                        constant.group("value"),
                        self._trace_step(
                            "constant",
                            spec,
                            line_number,
                            instruction,
                            destination=destination,
                        ),
                    )
                    continue

                new_instance = NEW_INSTANCE_PATTERN.match(instruction)
                if new_instance is not None:
                    destination = new_instance.group("destination")
                    descriptor = new_instance.group("descriptor")
                    object_id = self._allocation_id(
                        "object",
                        spec,
                        line_number,
                        descriptor,
                    )
                    registers[destination] = self._object_state(
                        object_id,
                        descriptor,
                        self._trace_step(
                            "new-instance",
                            spec,
                            line_number,
                            instruction,
                            destination=destination,
                        ),
                    )
                    self._remember_instance(
                        descriptor_instances,
                        descriptor,
                        object_id,
                    )
                    if descriptor in CONTAINER_DESCRIPTORS:
                        local_container_ids.add(object_id)
                    if descriptor == INTENT_DESCRIPTOR:
                        intent_profiles.setdefault(object_id, {})
                    continue

                new_array = NEW_ARRAY_PATTERN.match(instruction)
                if new_array is not None:
                    destination = new_array.group("destination")
                    array_id = self._allocation_id(
                        "array",
                        spec,
                        line_number,
                        new_array.group("descriptor"),
                    )
                    registers[destination] = self._array_state(
                        array_id,
                        new_array.group("descriptor"),
                        self._trace_step(
                            "new-array",
                            spec,
                            line_number,
                            instruction,
                            destination=destination,
                        ),
                    )
                    continue

                filled_array = FILLED_NEW_ARRAY_PATTERN.match(instruction)
                if filled_array is not None:
                    element_registers = self._parse_registers(
                        filled_array.group("registers")
                    )
                    array_id = self._allocation_id(
                        "array",
                        spec,
                        line_number,
                        filled_array.group("descriptor"),
                    )
                    pending_result = self._array_state(
                        array_id,
                        filled_array.group("descriptor"),
                        self._trace_step(
                            "filled-new-array",
                            spec,
                            line_number,
                            instruction,
                        ),
                    )
                    for index, register in enumerate(element_registers):
                        element_state = deepcopy(
                            registers.get(register)
                            or self._unknown_state(
                                self._trace_step(
                                    "array-element-unknown",
                                    spec,
                                    line_number,
                                    instruction,
                                    source=register,
                                )
                            )
                        )
                        element_state["trace"].append(
                            self._trace_step(
                                "array-write",
                                spec,
                                line_number,
                                instruction,
                                source=register,
                            )
                        )
                        array_elements[(array_id, str(index))] = element_state
                    pending_result = self._resolve_storage_state(
                        pending_result,
                        container_values,
                        array_elements,
                    )
                    continue

                instance_put = INSTANCE_FIELD_PUT_PATTERN.match(instruction)
                if instance_put is not None:
                    source = instance_put.group("source")
                    object_register = instance_put.group("object")
                    state = deepcopy(
                        registers.get(source)
                        or self._unknown_state(
                            self._trace_step(
                                "instance-field-write-unknown",
                                spec,
                                line_number,
                                instruction,
                                source=source,
                            )
                        )
                    )
                    state["trace"].append(
                        self._trace_step(
                            "instance-field-write",
                            spec,
                            line_number,
                            instruction,
                            source=source,
                        )
                    )
                    object_ids = self._object_ids(
                        registers.get(object_register)
                    ) or [f"register:{spec['descriptor']}:{object_register}"]
                    for object_id in object_ids:
                        instance_fields[
                            (object_id, instance_put.group("field"))
                        ] = deepcopy(state)
                    continue

                instance_get = INSTANCE_FIELD_GET_PATTERN.match(instruction)
                if instance_get is not None:
                    destination = instance_get.group("destination")
                    object_register = instance_get.group("object")
                    object_state = registers.get(object_register)
                    field_states = self._instance_field_states(
                        instance_fields,
                        self._object_ids(object_state),
                        instance_get.group("field"),
                    )
                    if not field_states and object_state is not None and (
                        object_state.get("sources")
                    ):
                        field_states = [object_state]
                    field_state = self._merge_states(field_states)
                    if field_state is None:
                        registers.pop(destination, None)
                    else:
                        if object_state is not None:
                            field_state["trace"] = self._unique_references(
                                [
                                    *field_state.get("trace", []),
                                    *object_state.get("trace", []),
                                ]
                            )
                        field_state["trace"].append(
                            self._trace_step(
                                "instance-field-read",
                                spec,
                                line_number,
                                instruction,
                                destination=destination,
                            )
                        )
                        registers[destination] = field_state
                    continue

                static_put = STATIC_FIELD_PUT_PATTERN.match(instruction)
                if static_put is not None:
                    source = static_put.group("source")
                    state = deepcopy(
                        registers.get(source)
                        or self._unknown_state(
                            self._trace_step(
                                "static-field-write-unknown",
                                spec,
                                line_number,
                                instruction,
                                source=source,
                            )
                        )
                    )
                    state["trace"].append(
                        self._trace_step(
                            "static-field-write",
                            spec,
                            line_number,
                            instruction,
                            source=source,
                        )
                    )
                    static_fields[static_put.group("field")] = state
                    continue

                static_get = STATIC_FIELD_GET_PATTERN.match(instruction)
                if static_get is not None:
                    destination = static_get.group("destination")
                    field = static_get.group("field")
                    state = deepcopy(static_fields.get(field))
                    if state is None:
                        referenced_descriptor = self._field_value_descriptor(field)
                        if referenced_descriptor is not None:
                            object_id = f"static:{field}"
                            state = self._object_state(
                                object_id,
                                referenced_descriptor,
                                self._trace_step(
                                    "static-object-reference",
                                    spec,
                                    line_number,
                                    instruction,
                                    destination=destination,
                                ),
                            )
                            self._remember_instance(
                                descriptor_instances,
                                referenced_descriptor,
                                object_id,
                            )
                    if state is None:
                        registers.pop(destination, None)
                    else:
                        state["trace"].append(
                            self._trace_step(
                                "static-field-read",
                                spec,
                                line_number,
                                instruction,
                                destination=destination,
                            )
                        )
                        registers[destination] = state
                    continue

                array_put = ARRAY_PUT_PATTERN.match(instruction)
                if array_put is not None:
                    source = array_put.group("source")
                    array_register = array_put.group("array")
                    array_ids = self._array_ids(registers.get(array_register))
                    if not array_ids:
                        array_ids = [
                            f"register-array:{spec['descriptor']}:{array_register}"
                        ]
                    index_key = self._array_index_key(
                        registers.get(array_put.group("index"))
                    )
                    state = deepcopy(
                        registers.get(source)
                        or self._unknown_state(
                            self._trace_step(
                                "array-write-unknown",
                                spec,
                                line_number,
                                instruction,
                                source=source,
                            )
                        )
                    )
                    state["trace"].append(
                        self._trace_step(
                            "array-write",
                            spec,
                            line_number,
                            instruction,
                            source=source,
                        )
                    )
                    for array_id in array_ids:
                        array_elements[(array_id, index_key)] = deepcopy(state)
                    resolved_array = self._resolve_storage_state(
                        registers.get(array_register),
                        container_values,
                        array_elements,
                    )
                    if resolved_array is not None:
                        registers[array_register] = resolved_array
                    continue

                array_get = ARRAY_GET_PATTERN.match(instruction)
                if array_get is not None:
                    destination = array_get.group("destination")
                    array_register = array_get.group("array")
                    array_state = registers.get(array_register)
                    index_key = self._array_index_key(
                        registers.get(array_get.group("index"))
                    )
                    element_states = self._array_element_states(
                        array_elements,
                        self._array_ids(array_state),
                        index_key,
                    )
                    if not element_states and array_state is not None and (
                        array_state.get("sources")
                    ):
                        element_states = [array_state]
                    element_state = self._merge_states(element_states)
                    if element_state is None:
                        registers.pop(destination, None)
                    else:
                        element_state["trace"].append(
                            self._trace_step(
                                "array-read",
                                spec,
                                line_number,
                                instruction,
                                destination=destination,
                            )
                        )
                        registers[destination] = element_state
                    continue

                returned = RETURN_PATTERN.match(instruction)
                if returned is not None:
                    register = returned.group("register")
                    if register in registers:
                        state = self._resolve_storage_state(
                            registers[register],
                            container_values,
                            array_elements,
                        ) or deepcopy(registers[register])
                        state["trace"].append(
                            self._trace_step(
                                "return",
                                spec,
                                line_number,
                                instruction,
                                source=register,
                            )
                        )
                        returned_states.append(state)
                    continue

                invoke = INVOKE_PATTERN.match(instruction)
                if invoke is not None:
                    signature = invoke.group("signature")
                    invoked_method = signature.split("(", 1)[0]
                    invoked_descriptor = signature[len(invoked_method):]
                    catalog_rules = self.catalog.match(
                        invoke.group("descriptor"),
                        invoked_method,
                        invoked_descriptor,
                    )
                    invoke_registers = self._parse_registers(
                        invoke.group("registers")
                    )
                    ipc_semantic_result = self._apply_ipc_object_semantics(
                        descriptor=invoke.group("descriptor"),
                        signature=signature,
                        invoke_registers=invoke_registers,
                        registers=registers,
                        intent_profiles=intent_profiles,
                        component_name_profiles=component_name_profiles,
                        spec=spec,
                        line_number=line_number,
                        instruction=instruction,
                    )
                    container_operation = self._container_operation(
                        invoke.group("descriptor"),
                        invoked_method,
                    )
                    if container_operation is not None and invoke_registers:
                        operation_kind = container_operation["kind"]
                        if operation_kind.startswith("write"):
                            pending_result = self._apply_container_write(
                                operation=container_operation,
                                descriptor=invoke.group("descriptor"),
                                invoke_registers=invoke_registers,
                                registers=registers,
                                container_values=container_values,
                                array_elements=array_elements,
                                spec=spec,
                                line_number=line_number,
                                instruction=instruction,
                            )
                            continue
                        pending_result, handled = self._read_container(
                            operation=container_operation,
                            descriptor=invoke.group("descriptor"),
                            invoke_registers=invoke_registers,
                            registers=registers,
                            container_values=container_values,
                            array_elements=array_elements,
                            local_container_ids=local_container_ids,
                            spec=spec,
                            line_number=line_number,
                            instruction=instruction,
                        )
                        if handled:
                            continue

                    effective_registers = dict(registers)
                    for register in invoke_registers:
                        resolved_state = self._resolve_storage_state(
                            registers.get(register),
                            container_values,
                            array_elements,
                        )
                        if resolved_state is not None:
                            effective_registers[register] = resolved_state
                    tainted_registers = [
                        register
                        for register in invoke_registers
                        if register in effective_registers
                    ]
                    invocation_state = self._merge_states(
                        [
                            effective_registers[register]
                            for register in tainted_registers
                        ]
                    )
                    line_evidence = evidence_by_line.get(line_number, [])
                    source_evidence = self._category_evidence(
                        line_evidence,
                        EXTERNAL_SOURCE,
                    )
                    validation_evidence = self._category_evidence(
                        line_evidence,
                        POSSIBLE_VALIDATION,
                    )
                    sensitive_evidence = self._category_evidence(
                        line_evidence,
                        SENSITIVE_OPERATION,
                    )

                    if validation_evidence and invocation_state is not None:
                        for evidence in validation_evidence:
                            validation = self._validation_reference(
                                evidence,
                                tainted_registers,
                            )
                            touched_validations.append(validation)
                            self._mark_related_registers_validated(
                                registers,
                                invocation_state,
                                validation,
                            )
                        invocation_state = self._merge_states(
                            [
                                registers[register]
                                for register in tainted_registers
                                if register in registers
                            ]
                        )

                    if sensitive_evidence:
                        for evidence in sensitive_evidence:
                            argument_assessment = (
                                self._sensitive_argument_assessment(
                                    evidence,
                                    invoke_registers,
                                    effective_registers,
                                    component=component,
                                    entry_point=entry_point,
                                    intent_profiles=intent_profiles,
                                )
                            )
                            sensitive_argument_assessments.append(
                                argument_assessment
                            )
                            if argument_assessment.get("ipc_transition"):
                                ipc_transitions.append(
                                    argument_assessment["ipc_transition"]
                                )
                            sink_tainted_registers = [
                                argument["register"]
                                for argument in argument_assessment["arguments"]
                                if argument["classification"]
                                in {EXTERNAL_TAINTED, INTERFACE_TAINTED}
                                and argument.get("register")
                            ]
                            sink_state = self._merge_states(
                                [
                                    effective_registers[register]
                                    for register in sink_tainted_registers
                                ]
                            )
                            if sink_state is None:
                                continue
                            flows.append(
                                self._flow_record(
                                    evidence,
                                    sink_state,
                                    sink_tainted_registers,
                                    argument_assessment,
                                )
                            )

                    if source_evidence:
                        states = []
                        for evidence in source_evidence:
                            state = self._source_state(evidence)
                            states.append(state)
                            discovered_sources.extend(state["sources"])
                        pending_result = self._merge_states(states)
                    else:
                        target_key = (
                            invoke.group("descriptor"),
                            signature,
                        )
                        if target_key in specs and target_key not in {
                            *active,
                            key,
                        }:
                            child_taints = self._map_call_taints(
                                invoke.group("opcode"),
                                invoke_registers,
                                effective_registers,
                                spec,
                                line_number,
                                instruction,
                            )
                            child_returns = run_method(
                                target_key,
                                child_taints,
                                (*active, key),
                            )
                            pending_result = self._merge_states(child_returns)
                        else:
                            propagation_states = []
                            mutate_receiver_states = []
                            for rule in catalog_rules:
                                if rule.category != PROPAGATOR and (
                                    rule.taint_behavior
                                    in {"none", "return", "sink"}
                                ):
                                    continue
                                propagation_state = self._propagation_state(
                                    rule,
                                    invoke.group("opcode"),
                                    invoke_registers,
                                    effective_registers,
                                )
                                if propagation_state is None:
                                    continue
                                propagation_state["trace"].append(
                                    {
                                        **self._trace_step(
                                            "catalog-propagation",
                                            spec,
                                            line_number,
                                            instruction,
                                        ),
                                        "api": rule.api,
                                        "rule_id": rule.id,
                                        "taint_behavior": rule.taint_behavior,
                                    }
                                )
                                propagation_states.append(propagation_state)
                                if rule.taint_behavior == (
                                    "receiver_and_arguments_to_"
                                    "receiver_and_return"
                                ):
                                    mutate_receiver_states.append(
                                        propagation_state
                                    )
                            pending_result = self._merge_states(
                                propagation_states
                            )
                            if (
                                mutate_receiver_states
                                and invoke_registers
                                and not invoke.group("opcode").startswith(
                                    "invoke-static"
                                )
                            ):
                                receiver_state = self._merge_states(
                                    mutate_receiver_states
                                )
                                if receiver_state is not None:
                                    registers[invoke_registers[0]] = (
                                        receiver_state
                                    )
                    if pending_result is None and ipc_semantic_result is not None:
                        pending_result = deepcopy(ipc_semantic_result)
                    if (
                        invoke.group("signature").startswith("<init>(")
                        and invoke_registers
                    ):
                        receiver = invoke_registers[0]
                        constructor_state = self._merge_states(
                            [
                                effective_registers[register]
                                for register in invoke_registers[1:]
                                if register in effective_registers
                            ]
                        )
                        if constructor_state is not None:
                            constructor_state["trace"].append(
                                self._trace_step(
                                    "constructor-propagation",
                                    spec,
                                    line_number,
                                    instruction,
                                    destination=receiver,
                                )
                            )
                            receiver_state = registers.get(receiver)
                            registers[receiver] = self._merge_states(
                                [
                                    state
                                    for state in (
                                        receiver_state,
                                        constructor_state,
                                    )
                                    if state is not None
                                ]
                            ) or constructor_state
                            captured_state = deepcopy(constructor_state)
                            captured_state["trace"].append(
                                self._trace_step(
                                    "constructor-capture",
                                    spec,
                                    line_number,
                                    instruction,
                                    source=invoke_registers[1]
                                    if len(invoke_registers) > 1
                                    else None,
                                )
                            )
                            for object_id in self._object_ids(
                                registers.get(receiver)
                            ):
                                instance_fields[(object_id, "*")] = deepcopy(
                                    captured_state
                                )
                    continue

                overwrite = OVERWRITE_PATTERN.match(instruction)
                if overwrite is not None:
                    registers.pop(overwrite.group("register"), None)

            method_runs.append(
                {
                    "class_name": spec["class_name"],
                    "method_signature": spec["signature"],
                    "smali_path": spec["smali_path"],
                    "start_line": spec["start_line"],
                    "end_line": spec["end_line"],
                    "depth": spec["depth"],
                    "initial_tainted_registers": initial_registers,
                    "source_count": len(discovered_sources)
                    - method_source_start,
                    "touched_validation_count": len(touched_validations)
                    - method_validation_start,
                    "flow_count": len(flows) - method_flow_start,
                    "tainted_return_count": len(returned_states),
                }
            )
            return returned_states

        run_method(root_key, {}, ())
        for key, spec in sorted(
            specs.items(),
            key=lambda item: (item[1]["depth"], item[1]["start_line"]),
        ):
            if key not in executed_keys:
                callback_states: dict[str, dict[str, Any]] = {}
                if spec.get("call_type") == "synthetic-callback-reference":
                    object_ids = descriptor_instances.get(
                        spec["descriptor"],
                        [],
                    )
                    if object_ids:
                        callback_states["p0"] = self._object_state(
                            object_ids[0],
                            spec["descriptor"],
                            self._trace_step(
                                "callback-receiver",
                                spec,
                                spec["start_line"],
                                "Receptor capturado do callback sintético",
                                destination="p0",
                            ),
                            additional_object_ids=object_ids[1:],
                        )
                run_method(key, callback_states, ())

        flows = self._deduplicate_flows(flows)
        for index, flow in enumerate(flows, start=1):
            flow["flow_id"] = f"FLOW-{index:04d}"

        validation_counts = Counter(flow["status"] for flow in flows)
        validated_count = validation_counts.get(
            "confirmed-with-possible-validation",
            0,
        )
        unvalidated_count = validation_counts.get(
            "confirmed-unvalidated",
            0,
        )
        source_count = len(self._unique_references(discovered_sources))
        validation_count = len(self._unique_references(touched_validations))
        sink_evidence_count = sum(
            1
            for spec in specs.values()
            for item in spec.get("evidence", [])
            if item.get("category") == SENSITIVE_OPERATION
        )
        argument_classification_counts = Counter(
            assessment["classification"]
            for assessment in sensitive_argument_assessments
        )
        ipc_transitions = self._deduplicate_ipc_transitions(ipc_transitions)

        if unvalidated_count:
            data_flow_status = "confirmed-unvalidated"
        elif validated_count:
            data_flow_status = "confirmed-with-possible-validation"
        elif source_count and sink_evidence_count:
            data_flow_status = "source-and-sink-unconfirmed"
        elif source_count:
            data_flow_status = "source-without-sensitive-operation"
        else:
            data_flow_status = "no-external-source"

        method_runs.sort(
            key=lambda item: (
                item["depth"],
                item["smali_path"],
                item["start_line"],
            )
        )
        return {
            "status": "analyzed",
            "reason": None,
            "data_flow_status": data_flow_status,
            "analyzed_method_count": len(method_runs),
            "source_count": source_count,
            "touched_validation_count": validation_count,
            "sensitive_operation_count": sink_evidence_count,
            "flow_count": len(flows),
            "validated_flow_count": validated_count,
            "unvalidated_flow_count": unvalidated_count,
            "sensitive_argument_assessment_count": len(
                sensitive_argument_assessments
            ),
            "argument_classification_counts": {
                classification: argument_classification_counts.get(
                    classification,
                    0,
                )
                for classification in (
                    EXTERNAL_TAINTED,
                    INTERFACE_TAINTED,
                    CONSTANT,
                    UNKNOWN,
                )
            },
            "sensitive_argument_assessments": (
                sensitive_argument_assessments
            ),
            "ipc_transition_count": len(ipc_transitions),
            "ipc_transitions": ipc_transitions,
            "flows": flows,
            "methods": method_runs,
            "definitive_security_verdict": False,
            "limitations": self._limitations(),
        }

    def _method_specs(
        self,
        component: dict[str, Any],
        entry_point: dict[str, Any],
    ) -> dict[tuple[str, str], dict[str, Any]]:
        code_analysis = component.get("code_analysis") or {}
        smali = component.get("smali") or {}
        descriptor = smali.get("descriptor")
        if not descriptor:
            class_name = smali.get("class_name") or component.get("name")
            if class_name:
                descriptor = f"L{class_name.replace('.', '/')};"
        if not descriptor or not code_analysis.get("smali_path"):
            return {}

        root_key = (descriptor, entry_point["signature"])
        specs: dict[tuple[str, str], dict[str, Any]] = {
            root_key: {
                "descriptor": descriptor,
                "class_name": self._descriptor_to_class_name(descriptor),
                "signature": entry_point["signature"],
                "modifiers": entry_point.get("modifiers", []),
                "smali_path": code_analysis["smali_path"],
                "start_line": entry_point["start_line"],
                "end_line": entry_point["end_line"],
                "depth": 0,
                "call_chain": [
                    f"{self._descriptor_to_class_name(descriptor)}"
                    f"->{entry_point['signature']}"
                ],
                "evidence": entry_point.get("direct_evidence", []),
            }
        }
        for method in entry_point.get("call_graph", {}).get(
            "reachable_methods",
            [],
        ):
            key = (method["descriptor"], method["signature"])
            specs[key] = {
                "descriptor": method["descriptor"],
                "class_name": method["class_name"],
                "signature": method["signature"],
                "modifiers": method.get("modifiers", []),
                "smali_path": method["smali_path"],
                "start_line": method["start_line"],
                "end_line": method["end_line"],
                "depth": method["depth"],
                "call_chain": method.get("call_chain", []),
                "evidence": method.get("evidence", []),
                "call_type": method.get("call_type"),
                "called_at_line": method.get("called_at_line"),
            }
        return specs

    def _declared_static_fields(
        self,
        specs: dict[tuple[str, str], dict[str, Any]],
    ) -> dict[str, dict[str, Any]]:
        """Carrega constantes declaradas diretamente em campos ``static``."""
        result: dict[str, dict[str, Any]] = {}
        inspected: set[tuple[str, str]] = set()
        for spec in specs.values():
            file_key = (spec["descriptor"], spec["smali_path"])
            if file_key in inspected:
                continue
            inspected.add(file_key)
            for line_number, raw_line in enumerate(
                self._lines_for(spec["smali_path"]),
                start=1,
            ):
                match = DECLARED_STATIC_FIELD_PATTERN.match(raw_line)
                if match is None or "static" not in match.group("modifiers").split():
                    continue
                field = (
                    f"{spec['descriptor']}->{match.group('name')}:"
                    f"{match.group('type')}"
                )
                result[field] = self._constant_state(
                    match.group("value"),
                    self._trace_step(
                        "declared-static-constant",
                        spec,
                        line_number,
                        raw_line.strip(),
                    ),
                )
        return result

    @staticmethod
    def _allocation_id(
        kind: str,
        spec: dict[str, Any],
        line_number: int,
        descriptor: str,
    ) -> str:
        return (
            f"{kind}:{spec['smali_path']}:{spec['signature']}:"
            f"{line_number}:{descriptor}"
        )

    @staticmethod
    def _remember_instance(
        instances: dict[str, list[str]],
        descriptor: str,
        object_id: str,
    ) -> None:
        descriptor_ids = instances.setdefault(descriptor, [])
        if object_id not in descriptor_ids:
            descriptor_ids.append(object_id)

    @staticmethod
    def _constant_state(
        value: str,
        trace: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "classification": CONSTANT,
            "constant_values": [value],
            "sources": [],
            "validations": [],
            "trace": [trace],
            "object_ids": [],
            "array_ids": [],
        }

    @staticmethod
    def _unknown_state(trace: dict[str, Any]) -> dict[str, Any]:
        return {
            "classification": UNKNOWN,
            "constant_values": [],
            "sources": [],
            "validations": [],
            "trace": [trace],
            "object_ids": [],
            "array_ids": [],
        }

    @staticmethod
    def _object_state(
        object_id: str,
        descriptor: str,
        trace: dict[str, Any],
        *,
        additional_object_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        return {
            "classification": UNKNOWN,
            "constant_values": [],
            "sources": [],
            "validations": [],
            "trace": [trace],
            "object_ids": [object_id, *(additional_object_ids or [])],
            "object_descriptors": [descriptor],
            "array_ids": [],
        }

    @staticmethod
    def _array_state(
        array_id: str,
        descriptor: str,
        trace: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "classification": UNKNOWN,
            "constant_values": [],
            "sources": [],
            "validations": [],
            "trace": [trace],
            "object_ids": [],
            "array_ids": [array_id],
            "array_descriptors": [descriptor],
        }

    @staticmethod
    def _object_ids(state: dict[str, Any] | None) -> list[str]:
        if state is None:
            return []
        return list(dict.fromkeys(state.get("object_ids", [])))

    @staticmethod
    def _array_ids(state: dict[str, Any] | None) -> list[str]:
        if state is None:
            return []
        return list(dict.fromkeys(state.get("array_ids", [])))

    @staticmethod
    def _instance_field_states(
        fields: dict[tuple[str, str], dict[str, Any]],
        object_ids: list[str],
        field: str,
    ) -> list[dict[str, Any]]:
        exact = [
            fields[(object_id, field)]
            for object_id in object_ids
            if (object_id, field) in fields
        ]
        if exact:
            return exact
        return [
            fields[(object_id, "*")]
            for object_id in object_ids
            if (object_id, "*") in fields
        ]

    @staticmethod
    def _field_value_descriptor(field: str) -> str | None:
        if ":" not in field:
            return None
        descriptor = field.rsplit(":", 1)[1]
        return descriptor if descriptor.startswith("L") and descriptor.endswith(";") else None

    @staticmethod
    def _array_index_key(state: dict[str, Any] | None) -> str:
        if state is None or state.get("classification") != CONSTANT:
            return "*"
        values = state.get("constant_values", [])
        return values[0] if len(values) == 1 else "*"

    @staticmethod
    def _array_element_states(
        elements: dict[tuple[str, str], dict[str, Any]],
        array_ids: list[str],
        index_key: str,
    ) -> list[dict[str, Any]]:
        exact = [
            elements[(array_id, index_key)]
            for array_id in array_ids
            if (array_id, index_key) in elements
        ]
        if exact:
            return exact
        return [
            elements[(array_id, "*")]
            for array_id in array_ids
            if (array_id, "*") in elements
        ]

    def _apply_ipc_object_semantics(
        self,
        *,
        descriptor: str,
        signature: str,
        invoke_registers: list[str],
        registers: dict[str, dict[str, Any]],
        intent_profiles: dict[str, dict[str, Any]],
        component_name_profiles: dict[str, dict[str, Any]],
        spec: dict[str, Any],
        line_number: int,
        instruction: str,
    ) -> dict[str, Any] | None:
        """Modela seletores de Intent sem confundi-los com seus extras."""
        if not invoke_registers:
            return None
        method = signature.split("(", 1)[0]
        receiver = invoke_registers[0]

        if descriptor == COMPONENT_NAME_DESCRIPTOR and method == "<init>":
            object_ids, receiver_state = self._ensure_semantic_object(
                descriptor,
                receiver,
                registers,
                spec,
                line_number,
                instruction,
            )
            positions = self._component_name_argument_positions(signature)
            target_state = self._state_for_positions(
                positions,
                invoke_registers,
                registers,
            )
            if target_state is not None:
                target_state["trace"].append(
                    self._trace_step(
                        "component-name-target",
                        spec,
                        line_number,
                        instruction,
                        destination=receiver,
                    )
                )
                for object_id in object_ids:
                    component_name_profiles[object_id] = deepcopy(target_state)
                registers[receiver] = self._attach_storage_identity(
                    target_state,
                    receiver_state,
                )
            return None

        if descriptor != INTENT_DESCRIPTOR:
            return None

        object_ids, receiver_state = self._ensure_semantic_object(
            descriptor,
            receiver,
            registers,
            spec,
            line_number,
            instruction,
        )
        for object_id in object_ids:
            intent_profiles.setdefault(
                object_id,
                {"__kind_hint__": "unknown", "__origin__": "unknown"},
            )

        attribute: str | None = None
        positions: list[int] = []
        kind_hint: str | None = None

        if method == "<init>":
            for object_id in object_ids:
                intent_profiles[object_id] = {
                    "__kind_hint__": "unknown",
                    "__origin__": "allocated",
                }
            if signature.startswith("<init>(Landroid/content/Intent;"):
                copied_profile = self._merged_intent_profile(
                    registers.get(invoke_registers[1])
                    if len(invoke_registers) > 1
                    else None,
                    intent_profiles,
                )
                if copied_profile:
                    for object_id in object_ids:
                        intent_profiles[object_id] = deepcopy(copied_profile)
                return None
            if signature.startswith(
                "<init>(Landroid/content/Context;Ljava/lang/Class;"
            ):
                attribute, positions, kind_hint = "destination", [2], "explicit"
            elif signature.startswith("<init>(Ljava/lang/String;Landroid/net/Uri;"):
                self._write_intent_attribute(
                    object_ids,
                    "action",
                    self._state_for_positions([1], invoke_registers, registers),
                    intent_profiles,
                    spec,
                    line_number,
                    instruction,
                )
                attribute, positions, kind_hint = "data", [2], "implicit"
            elif signature.startswith("<init>(Ljava/lang/String;"):
                attribute, positions, kind_hint = "action", [1], "implicit"
            else:
                return None
        elif method == "setClass":
            attribute, positions, kind_hint = "destination", [2], "explicit"
        elif method == "setClassName":
            attribute, kind_hint = "destination", "explicit"
            positions = (
                [2]
                if signature.startswith("setClassName(Landroid/content/Context;")
                else [1, 2]
            )
        elif method == "setComponent":
            attribute, positions, kind_hint = "component", [1], "explicit"
        elif method == "setAction":
            attribute, positions, kind_hint = "action", [1], "implicit"
        elif method in {"setData", "setDataAndType", "setDataAndNormalize"}:
            attribute, positions, kind_hint = "data", [1], "implicit"
        else:
            return None

        attribute_state = self._state_for_positions(
            positions,
            invoke_registers,
            registers,
        )
        if attribute == "component" and attribute_state is not None:
            component_states = [
                component_name_profiles[object_id]
                for object_id in self._object_ids(attribute_state)
                if object_id in component_name_profiles
            ]
            attribute_state = self._merge_states(component_states) or attribute_state

        self._write_intent_attribute(
            object_ids,
            attribute,
            attribute_state,
            intent_profiles,
            spec,
            line_number,
            instruction,
        )
        for object_id in object_ids:
            profile = intent_profiles[object_id]
            current_hint = profile.get("__kind_hint__")
            origin = profile.get("__origin__")
            if kind_hint == "explicit":
                profile["__kind_hint__"] = "explicit"
            elif current_hint != "explicit" and origin == "allocated":
                profile["__kind_hint__"] = kind_hint

        if attribute_state is None:
            return deepcopy(receiver_state)
        updated_receiver = self._attach_storage_identity(
            attribute_state,
            receiver_state,
        )
        registers[receiver] = updated_receiver
        return deepcopy(updated_receiver) if method != "<init>" else None

    def _ensure_semantic_object(
        self,
        descriptor: str,
        receiver: str,
        registers: dict[str, dict[str, Any]],
        spec: dict[str, Any],
        line_number: int,
        instruction: str,
    ) -> tuple[list[str], dict[str, Any]]:
        state = deepcopy(registers.get(receiver))
        if state is None:
            object_id = self._allocation_id(
                "semantic-object",
                spec,
                line_number,
                descriptor,
            )
            state = self._object_state(
                object_id,
                descriptor,
                self._trace_step(
                    "semantic-object-reference",
                    spec,
                    line_number,
                    instruction,
                    destination=receiver,
                ),
            )
        object_ids = self._object_ids(state)
        if not object_ids:
            object_ids = [
                self._allocation_id(
                    "semantic-object",
                    spec,
                    line_number,
                    descriptor,
                )
            ]
            state["object_ids"] = object_ids
        descriptors = state.setdefault("object_descriptors", [])
        if descriptor not in descriptors:
            descriptors.append(descriptor)
        registers[receiver] = deepcopy(state)
        return object_ids, state

    def _state_for_positions(
        self,
        positions: list[int],
        invoke_registers: list[str],
        registers: dict[str, dict[str, Any]],
    ) -> dict[str, Any] | None:
        return self._merge_states(
            [
                registers[invoke_registers[position]]
                for position in positions
                if 0 <= position < len(invoke_registers)
                and invoke_registers[position] in registers
            ]
        )

    @staticmethod
    def _component_name_argument_positions(signature: str) -> list[int]:
        if signature.startswith("<init>(Landroid/content/Context;"):
            return [2]
        if signature.startswith("<init>(Ljava/lang/String;Ljava/lang/String;"):
            return [1, 2]
        return [1]

    def _write_intent_attribute(
        self,
        object_ids: list[str],
        attribute: str,
        state: dict[str, Any] | None,
        intent_profiles: dict[str, dict[str, Any]],
        spec: dict[str, Any],
        line_number: int,
        instruction: str,
    ) -> None:
        if state is None:
            state = self._unknown_state(
                self._trace_step(
                    "intent-selector-unknown",
                    spec,
                    line_number,
                    instruction,
                )
            )
        else:
            state = deepcopy(state)
        state["trace"].append(
            self._trace_step(
                "intent-selector-write",
                spec,
                line_number,
                instruction,
            )
        )
        for object_id in object_ids:
            intent_profiles.setdefault(object_id, {})[attribute] = deepcopy(state)

    def _merged_intent_profile(
        self,
        state: dict[str, Any] | None,
        intent_profiles: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        profiles = [
            intent_profiles[object_id]
            for object_id in self._object_ids(state)
            if object_id in intent_profiles
        ]
        if not profiles:
            return {}
        result: dict[str, Any] = {
            "__origin__": "copy",
            "__kind_hint__": (
                profiles[0].get("__kind_hint__", "unknown")
                if len({profile.get("__kind_hint__") for profile in profiles}) == 1
                else "unknown"
            ),
        }
        for attribute in INTENT_SELECTOR_ATTRIBUTES:
            merged = self._merge_states(
                [
                    profile[attribute]
                    for profile in profiles
                    if isinstance(profile.get(attribute), dict)
                ]
            )
            if merged is not None:
                result[attribute] = merged
        return result

    @staticmethod
    def _container_operation(
        descriptor: str,
        method: str,
    ) -> dict[str, Any] | None:
        """Descreve leituras e escritas conhecidas em contêineres Android."""
        if descriptor == "Landroid/content/Intent;":
            if method in {"putExtras", "replaceExtras"}:
                return {
                    "kind": "write-all",
                    "value_position": 1,
                    "returns_receiver": True,
                    "replace": method == "replaceExtras",
                }
            if method == "putExtra" or (
                method.startswith("put") and method.endswith("Extra")
            ):
                return {
                    "kind": "write",
                    "key_position": 1,
                    "value_position": 2,
                    "returns_receiver": True,
                }
            if method == "getExtras":
                return {
                    "kind": "read-all",
                    "result_descriptor": "Landroid/os/Bundle;",
                }
            if method.startswith("get") and method.endswith("Extra"):
                return {
                    "kind": "read",
                    "key_position": 1,
                    "default_position": 2,
                }

        if descriptor == "Landroid/os/Bundle;":
            if method == "putAll":
                return {
                    "kind": "write-all",
                    "value_position": 1,
                    "returns_receiver": False,
                    "replace": False,
                }
            if method == "putNull":
                return {
                    "kind": "write-null",
                    "key_position": 1,
                    "returns_receiver": False,
                }
            if method.startswith("put"):
                return {
                    "kind": "write",
                    "key_position": 1,
                    "value_position": 2,
                    "returns_receiver": False,
                }
            if method == "get" or (
                method.startswith("get")
                and method not in {"getClassLoader", "getPairValue"}
            ):
                return {
                    "kind": "read",
                    "key_position": 1,
                    "default_position": 2,
                }

        if descriptor == "Landroid/content/ContentValues;":
            if method == "putAll":
                return {
                    "kind": "write-all",
                    "value_position": 1,
                    "returns_receiver": False,
                    "replace": False,
                }
            if method == "putNull":
                return {
                    "kind": "write-null",
                    "key_position": 1,
                    "returns_receiver": False,
                }
            if method == "put":
                return {
                    "kind": "write",
                    "key_position": 1,
                    "value_position": 2,
                    "returns_receiver": False,
                }
            if method == "get" or method.startswith("getAs"):
                return {
                    "kind": "read",
                    "key_position": 1,
                }
        return None

    @staticmethod
    def _container_key(state: dict[str, Any] | None) -> str:
        if state is None or state.get("classification") != CONSTANT:
            return "*"
        values = state.get("constant_values", [])
        return values[0] if len(values) == 1 else "*"

    @staticmethod
    def _container_value_states(
        values: dict[tuple[str, str], dict[str, Any]],
        object_ids: list[str],
        key: str,
    ) -> list[dict[str, Any]]:
        if key == "*":
            return [
                state
                for (object_id, _), state in values.items()
                if object_id in object_ids
            ]
        exact = [
            values[(object_id, key)]
            for object_id in object_ids
            if (object_id, key) in values
        ]
        if exact:
            return exact
        return [
            values[(object_id, "*")]
            for object_id in object_ids
            if (object_id, "*") in values
        ]

    def _attach_storage_identity(
        self,
        state: dict[str, Any],
        base_state: dict[str, Any],
    ) -> dict[str, Any]:
        result = deepcopy(state)
        result["trace"] = self._unique_references(
            [
                *base_state.get("trace", []),
                *result.get("trace", []),
            ]
        )
        for name in (
            "object_ids",
            "object_descriptors",
            "array_ids",
            "array_descriptors",
        ):
            result[name] = list(
                dict.fromkeys(
                    [
                        *base_state.get(name, []),
                        *result.get(name, []),
                    ]
                )
            )
        return result

    def _resolve_storage_state(
        self,
        state: dict[str, Any] | None,
        container_values: dict[tuple[str, str], dict[str, Any]],
        array_elements: dict[tuple[str, str], dict[str, Any]],
    ) -> dict[str, Any] | None:
        """Obtém o estado agregado do conteúdo armazenado em um objeto."""
        if state is None:
            return None
        stored_states: list[dict[str, Any]] = []
        object_ids = self._object_ids(state)
        array_ids = self._array_ids(state)
        if object_ids:
            stored_states.extend(
                self._container_value_states(
                    container_values,
                    object_ids,
                    "*",
                )
            )
        if array_ids:
            stored_states.extend(
                element_state
                for (array_id, _), element_state in array_elements.items()
                if array_id in array_ids
            )
        stored_state = self._merge_states(stored_states)
        if stored_state is None:
            return deepcopy(state)
        return self._attach_storage_identity(stored_state, state)

    def _ensure_container_ids(
        self,
        descriptor: str,
        receiver: str,
        registers: dict[str, dict[str, Any]],
        spec: dict[str, Any],
        line_number: int,
        instruction: str,
    ) -> tuple[list[str], dict[str, Any]]:
        state = deepcopy(registers.get(receiver))
        if state is None:
            object_id = self._allocation_id(
                "container",
                spec,
                line_number,
                descriptor,
            )
            state = self._object_state(
                object_id,
                descriptor,
                self._trace_step(
                    "container-reference",
                    spec,
                    line_number,
                    instruction,
                    destination=receiver,
                ),
            )
            registers[receiver] = deepcopy(state)
            return [object_id], state

        object_ids = self._object_ids(state)
        if not object_ids:
            object_id = self._allocation_id(
                "container",
                spec,
                line_number,
                descriptor,
            )
            object_ids = [object_id]
            state["object_ids"] = object_ids
        descriptors = state.setdefault("object_descriptors", [])
        if descriptor not in descriptors:
            descriptors.append(descriptor)
        registers[receiver] = deepcopy(state)
        return object_ids, state

    def _apply_container_write(
        self,
        *,
        operation: dict[str, Any],
        descriptor: str,
        invoke_registers: list[str],
        registers: dict[str, dict[str, Any]],
        container_values: dict[tuple[str, str], dict[str, Any]],
        array_elements: dict[tuple[str, str], dict[str, Any]],
        spec: dict[str, Any],
        line_number: int,
        instruction: str,
    ) -> dict[str, Any] | None:
        receiver = invoke_registers[0]
        object_ids, receiver_state = self._ensure_container_ids(
            descriptor,
            receiver,
            registers,
            spec,
            line_number,
            instruction,
        )
        has_known_content = any(
            object_id == stored_id
            for object_id in object_ids
            for stored_id, _ in container_values
        )
        if receiver_state.get("sources") and not has_known_content:
            external_state = deepcopy(receiver_state)
            for object_id in object_ids:
                container_values[(object_id, "*")] = deepcopy(
                    external_state
                )

        if operation.get("replace"):
            for storage_key in list(container_values):
                if storage_key[0] in object_ids:
                    del container_values[storage_key]

        if operation["kind"] == "write-all":
            value_position = operation["value_position"]
            value_state = (
                self._resolve_storage_state(
                    registers.get(invoke_registers[value_position]),
                    container_values,
                    array_elements,
                )
                if value_position < len(invoke_registers)
                else None
            )
            source_ids = self._object_ids(value_state)
            copied_values = [
                (stored_key, deepcopy(stored_state))
                for (source_id, stored_key), stored_state in container_values.items()
                if source_id in source_ids
            ]
            if copied_values:
                for object_id in object_ids:
                    for stored_key, stored_state in copied_values:
                        container_values[(object_id, stored_key)] = deepcopy(
                            stored_state
                        )
            else:
                state = deepcopy(
                    value_state
                    or self._unknown_state(
                        self._trace_step(
                            "container-write-unknown",
                            spec,
                            line_number,
                            instruction,
                        )
                    )
                )
                state["trace"].append(
                    self._trace_step(
                        "container-write",
                        spec,
                        line_number,
                        instruction,
                        source=(
                            invoke_registers[value_position]
                            if value_position < len(invoke_registers)
                            else None
                        ),
                        destination=receiver,
                    )
                )
                for object_id in object_ids:
                    container_values[(object_id, "*")] = deepcopy(state)
        else:
            key_position = operation.get("key_position")
            key = self._container_key(
                registers.get(invoke_registers[key_position])
                if isinstance(key_position, int)
                and key_position < len(invoke_registers)
                else None
            )
            if operation["kind"] == "write-null":
                state = self._constant_state(
                    "null",
                    self._trace_step(
                        "container-null",
                        spec,
                        line_number,
                        instruction,
                    ),
                )
                source_register = None
            else:
                value_position = operation.get("value_position")
                source_register = (
                    invoke_registers[value_position]
                    if isinstance(value_position, int)
                    and value_position < len(invoke_registers)
                    else None
                )
                state = deepcopy(
                    self._resolve_storage_state(
                        registers.get(source_register),
                        container_values,
                        array_elements,
                    )
                    or self._unknown_state(
                        self._trace_step(
                            "container-write-unknown",
                            spec,
                            line_number,
                            instruction,
                            source=source_register,
                        )
                    )
                )
            state["trace"].append(
                self._trace_step(
                    "container-write",
                    spec,
                    line_number,
                    instruction,
                    source=source_register,
                    destination=receiver,
                )
            )
            for object_id in object_ids:
                container_values[(object_id, key)] = deepcopy(state)

        summary = self._resolve_storage_state(
            receiver_state,
            container_values,
            array_elements,
        ) or receiver_state
        registers[receiver] = summary
        return deepcopy(summary) if operation.get("returns_receiver") else None

    def _read_container(
        self,
        *,
        operation: dict[str, Any],
        descriptor: str,
        invoke_registers: list[str],
        registers: dict[str, dict[str, Any]],
        container_values: dict[tuple[str, str], dict[str, Any]],
        array_elements: dict[tuple[str, str], dict[str, Any]],
        local_container_ids: set[str],
        spec: dict[str, Any],
        line_number: int,
        instruction: str,
    ) -> tuple[dict[str, Any] | None, bool]:
        receiver = invoke_registers[0]
        receiver_state = registers.get(receiver)
        object_ids = self._object_ids(receiver_state)
        key_position = operation.get("key_position")
        key = (
            self._container_key(
                registers.get(invoke_registers[key_position])
            )
            if isinstance(key_position, int)
            and key_position < len(invoke_registers)
            else "*"
        )
        states = self._container_value_states(
            container_values,
            object_ids,
            key,
        )
        state = self._merge_states(states)
        if state is None and descriptor == "Landroid/content/ContentValues;":
            if receiver_state is not None and receiver_state.get("sources"):
                state = deepcopy(receiver_state)
        known_local = bool(set(object_ids) & local_container_ids)
        if state is None and not known_local:
            return None, False
        if state is None:
            default_position = operation.get("default_position")
            if (
                isinstance(default_position, int)
                and default_position < len(invoke_registers)
            ):
                state = deepcopy(
                    self._resolve_storage_state(
                        registers.get(invoke_registers[default_position]),
                        container_values,
                        array_elements,
                    )
                    or self._unknown_state(
                        self._trace_step(
                            "container-default-unknown",
                            spec,
                            line_number,
                            instruction,
                        )
                    )
                )
            else:
                state = self._unknown_state(
                    self._trace_step(
                        "container-read-unknown",
                        spec,
                        line_number,
                        instruction,
                    )
                )
        state["trace"].append(
            self._trace_step(
                "container-read",
                spec,
                line_number,
                instruction,
                source=receiver,
            )
        )
        if operation["kind"] == "read-all" and receiver_state is not None:
            state = self._attach_storage_identity(state, receiver_state)
            result_descriptor = operation.get("result_descriptor")
            if result_descriptor:
                state["object_descriptors"] = [result_descriptor]
        return state, True

    def _entry_point_parameter_taints(
        self,
        component: dict[str, Any],
        entry_point: dict[str, Any],
        spec: dict[str, Any],
    ) -> dict[str, dict[str, Any]]:
        method_name = entry_point.get("name")
        component_type = component.get("type")
        parameter_registers: list[str] = []

        if component_type == "service" and method_name in {
            "onStartCommand",
            "onBind",
        }:
            parameter_registers = ["p1"]
        elif component_type == "receiver" and method_name == "onReceive":
            parameter_registers = ["p2"]
        elif component_type in {"activity", "activity-alias"} and (
            method_name == "onNewIntent"
        ):
            parameter_registers = ["p1"]
        elif component_type == "provider":
            parameter_registers = self._parameter_registers(
                entry_point.get("signature", ""),
                first_register=1,
            )

        result: dict[str, dict[str, Any]] = {}
        for register in parameter_registers:
            source = {
                "kind": "entry_point_parameter",
                "api": "Android entry point parameter",
                "source_kind": "untrusted_input",
                "register": register,
                "line": spec["start_line"],
                "instruction": (
                    f"Parâmetro externo {register} de "
                    f"{entry_point.get('signature')}"
                ),
                "class_name": spec["class_name"],
                "method_signature": spec["signature"],
                "smali_path": spec["smali_path"],
            }
            is_intent_parameter = (
                component_type in {"service", "receiver", "activity", "activity-alias"}
            )
            object_id = (
                f"entry-intent:{spec['descriptor']}:{spec['signature']}:{register}"
                if is_intent_parameter
                else None
            )
            result[register] = {
                "classification": EXTERNAL_TAINTED,
                "constant_values": [],
                "sources": [source],
                "validations": [],
                "trace": [
                    self._trace_step(
                        "entry-point-source",
                        spec,
                        spec["start_line"],
                        source["instruction"],
                        destination=register,
                    )
                ],
                "object_ids": [object_id] if object_id else [],
                "object_descriptors": (
                    [INTENT_DESCRIPTOR] if is_intent_parameter else []
                ),
                "array_ids": [],
            }
        return result

    @staticmethod
    def _parameter_registers(
        signature: str,
        first_register: int,
    ) -> list[str]:
        if "(" not in signature or ")" not in signature:
            return []
        descriptors = signature.split("(", 1)[1].split(")", 1)[0]
        result: list[str] = []
        index = first_register
        position = 0
        while position < len(descriptors):
            result.append(f"p{index}")
            current = descriptors[position]
            if current == "L":
                end = descriptors.find(";", position)
                position = len(descriptors) if end < 0 else end + 1
            elif current == "[":
                position += 1
                while position < len(descriptors) and descriptors[position] == "[":
                    position += 1
                if position < len(descriptors) and descriptors[position] == "L":
                    end = descriptors.find(";", position)
                    position = len(descriptors) if end < 0 else end + 1
                else:
                    position += 1
            else:
                position += 1
            index += 2 if current in {"J", "D"} else 1
        return result

    def _map_call_taints(
        self,
        opcode: str,
        invoke_registers: list[str],
        registers: dict[str, dict[str, Any]],
        spec: dict[str, Any],
        line_number: int,
        instruction: str,
    ) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        parameter_index = 0
        for actual_register in invoke_registers:
            parameter_register = f"p{parameter_index}"
            parameter_index += 1
            if actual_register not in registers:
                continue
            state = deepcopy(registers[actual_register])
            state["trace"].append(
                self._trace_step(
                    "method-argument",
                    spec,
                    line_number,
                    instruction,
                    source=actual_register,
                    destination=parameter_register,
                )
            )
            result[parameter_register] = state

        # Chamadas estáticas não possuem o registrador p0 reservado para this.
        # A enumeração acima já começa em p0, portanto não exige deslocamento.
        _ = opcode
        return result

    def _lines_for(self, smali_path: str) -> list[str]:
        path = (self.decompiled_dir / smali_path).resolve()
        try:
            path.relative_to(self.decompiled_dir_resolved)
        except ValueError as error:
            raise ValueError(
                f"Caminho Smali fora do diretório descompilado: {smali_path}"
            ) from error
        if path not in self._line_cache:
            self._line_cache[path] = path.read_text(
                encoding="utf-8",
                errors="replace",
            ).splitlines()
        return self._line_cache[path]

    @staticmethod
    def _parse_registers(value: str) -> list[str]:
        value = value.strip()
        if not value:
            return []
        if ".." in value:
            start_text, end_text = [
                item.strip() for item in value.split("..", 1)
            ]
            if (
                REGISTER_PATTERN.match(start_text)
                and REGISTER_PATTERN.match(end_text)
                and start_text[0] == end_text[0]
            ):
                start = int(start_text[1:])
                end = int(end_text[1:])
                if 0 <= end - start <= 64:
                    return [f"{start_text[0]}{index}" for index in range(start, end + 1)]
            return []
        return [
            register.strip()
            for register in value.split(",")
            if REGISTER_PATTERN.match(register.strip())
        ]

    @staticmethod
    def _category_evidence(
        evidence: list[dict[str, Any]],
        category: str,
    ) -> list[dict[str, Any]]:
        return [item for item in evidence if item.get("category") == category]

    def _sensitive_argument_assessment(
        self,
        evidence: dict[str, Any],
        invoke_registers: list[str],
        registers: dict[str, dict[str, Any]],
        *,
        component: dict[str, Any],
        entry_point: dict[str, Any],
        intent_profiles: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        """Classifica cada argumento crítico, mesmo sem taint confirmado."""
        positions = evidence.get("sensitive_arguments")
        if not positions or "*" in positions:
            selected_positions = list(range(len(invoke_registers)))
        else:
            selected_positions = [
                position
                for position in positions
                if isinstance(position, int)
                and 0 <= position < len(invoke_registers)
            ]
        arguments = []
        for position in selected_positions:
            register = invoke_registers[position]
            state = registers.get(register)
            argument = {
                "position": position,
                "register": register,
                "classification": self._state_classification(state),
            }
            constant_values = (
                state.get("constant_values", []) if state is not None else []
            )
            if constant_values:
                argument["constant_values"] = list(
                    dict.fromkeys(constant_values)
                )
            arguments.append(argument)

        classifications = [
            argument["classification"] for argument in arguments
        ]
        if EXTERNAL_TAINTED in classifications:
            classification = EXTERNAL_TAINTED
        elif INTERFACE_TAINTED in classifications:
            classification = INTERFACE_TAINTED
        elif classifications and all(
            item == CONSTANT for item in classifications
        ):
            classification = CONSTANT
        else:
            classification = UNKNOWN

        result = {
            "api": evidence.get("api"),
            "rule_id": evidence.get("rule_id"),
            "operation_kind": evidence.get("operation_kind"),
            "severity": evidence.get("severity"),
            "classification": classification,
            "arguments": arguments,
            "line": evidence.get("line"),
            "instruction": evidence.get("instruction"),
            "class_name": evidence.get("class_name"),
            "method_signature": evidence.get("method_signature"),
            "smali_path": evidence.get("smali_path"),
        }
        if evidence.get("operation_kind") in IPC_OPERATION_KINDS:
            intent_state = None
            for argument in arguments:
                state = registers.get(argument.get("register"))
                if state is not None and INTENT_DESCRIPTOR in state.get(
                    "object_descriptors",
                    [],
                ):
                    intent_state = state
                    break
            result["ipc_transition"] = self._ipc_transition(
                evidence=evidence,
                component=component,
                entry_point=entry_point,
                intent_state=intent_state,
                intent_profiles=intent_profiles,
            )
        return result

    def _ipc_transition(
        self,
        *,
        evidence: dict[str, Any],
        component: dict[str, Any],
        entry_point: dict[str, Any],
        intent_state: dict[str, Any] | None,
        intent_profiles: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        profile = self._merged_intent_profile(intent_state, intent_profiles)
        kind_hint = profile.get("__kind_hint__", "unknown")
        explicit_states = [
            profile[attribute]
            for attribute in ("destination", "component")
            if isinstance(profile.get(attribute), dict)
        ]
        implicit_states = [
            profile[attribute]
            for attribute in ("action", "data")
            if isinstance(profile.get(attribute), dict)
        ]
        # Um perfil pode manter o hint ``unknown`` após aliases ou retornos
        # entre métodos. A presença de destino ou ComponentName, porém, já
        # comprova semanticamente que o Intent é explícito.
        if kind_hint == "explicit" or explicit_states:
            intent_kind = "explicit"
        elif kind_hint == "implicit" or implicit_states:
            intent_kind = "implicit"
        else:
            intent_kind = "unknown"

        selector_states = (
            explicit_states
            if intent_kind == "explicit"
            else implicit_states
            if intent_kind == "implicit"
            else [*explicit_states, *implicit_states]
        )
        selector_state = self._merge_states(selector_states)
        selector_classification = self._state_classification(selector_state)
        attributes = {
            attribute: self._state_snapshot(profile[attribute])
            for attribute in INTENT_SELECTOR_ATTRIBUTES
            if isinstance(profile.get(attribute), dict)
        }
        destination_states = explicit_states
        destination_state = self._merge_states(destination_states)
        destination_values = list(
            dict.fromkeys(
                destination_state.get("constant_values", [])
                if destination_state is not None
                else []
            )
        )
        destination_candidates = self._destination_candidates(
            destination_values
        )
        known_components = getattr(self, "known_components", set())
        matched_components = sorted(
            candidate
            for candidate in destination_candidates
            if candidate in known_components
        )
        package = getattr(self, "application_package", None)
        destination_internal: bool | None
        if not destination_values:
            destination_internal = None
        elif matched_components:
            destination_internal = True
        elif package and any(
            candidate.startswith(f"{package}.")
            for candidate in destination_candidates
        ):
            destination_internal = True
        else:
            destination_internal = False

        explicit_internal_constant = (
            intent_kind == "explicit"
            and selector_classification == CONSTANT
            and destination_internal is True
        )
        operation_kind = evidence.get("operation_kind") or "ipc_unknown"
        return {
            "transition_id": None,
            "transition_type": operation_kind.removeprefix("ipc_"),
            "api": evidence.get("api"),
            "source_component": component.get("name"),
            "source_entry_point": entry_point.get("signature"),
            "intent_kind": intent_kind,
            "selector_classification": selector_classification,
            "selector_controllable": (
                selector_classification == EXTERNAL_TAINTED
            ),
            "attributes": attributes,
            "destination_values": destination_values,
            "destination_candidates": destination_candidates,
            "destination_components": matched_components,
            "destination_internal": destination_internal,
            "explicit_internal_constant": explicit_internal_constant,
            "line": evidence.get("line"),
            "instruction": evidence.get("instruction"),
            "class_name": evidence.get("class_name"),
            "method_signature": evidence.get("method_signature"),
            "smali_path": evidence.get("smali_path"),
        }

    @staticmethod
    def _state_snapshot(state: dict[str, Any]) -> dict[str, Any]:
        return {
            "classification": DataFlowAnalyzer._state_classification(state),
            "constant_values": list(
                dict.fromkeys(state.get("constant_values", []))
            ),
            "source_kinds": sorted(
                {
                    source.get("source_kind") or source.get("kind") or "unknown"
                    for source in state.get("sources", [])
                }
            ),
        }

    def _destination_candidates(self, values: list[str]) -> list[str]:
        cleaned = [value.strip().strip('"\'') for value in values]
        result: list[str] = []
        package = getattr(self, "application_package", None)
        package_values = [
            value for value in cleaned if "." in value and not value.startswith("L")
        ]
        for value in cleaned:
            if value.startswith("L") and value.endswith(";"):
                candidate = self._descriptor_to_class_name(value)
                result.append(candidate)
                continue
            if value.startswith(".") and package:
                result.append(f"{package}{value}")
                continue
            if "." not in value and package:
                result.append(f"{package}.{value}")
            if "." in value:
                result.append(value)
        for package_value in package_values:
            for class_value in cleaned:
                if class_value.startswith("."):
                    result.append(f"{package_value}{class_value}")
                elif "." not in class_value:
                    result.append(f"{package_value}.{class_value}")
        return list(dict.fromkeys(result))

    @staticmethod
    def _state_classification(state: dict[str, Any] | None) -> str:
        if state is None:
            return UNKNOWN
        source_kinds = {
            source.get("source_kind")
            for source in state.get("sources", [])
        }
        if any(
            source_kind not in USER_INTERFACE_SOURCE_KINDS
            for source_kind in source_kinds
        ):
            return EXTERNAL_TAINTED
        if source_kinds & USER_INTERFACE_SOURCE_KINDS:
            return INTERFACE_TAINTED
        return state.get("classification", UNKNOWN)

    def _propagation_state(
        self,
        rule: ApiRule,
        opcode: str,
        invoke_registers: list[str],
        registers: dict[str, dict[str, Any]],
    ) -> dict[str, Any] | None:
        if not invoke_registers:
            return None
        is_static = opcode.startswith("invoke-static")
        receiver = [] if is_static else invoke_registers[:1]
        arguments = invoke_registers if is_static else invoke_registers[1:]

        if rule.taint_behavior == "receiver_to_return":
            candidates = receiver
        elif rule.taint_behavior == "arguments_to_return":
            candidates = arguments
        elif rule.taint_behavior in {
            "receiver_and_arguments_to_return",
            "receiver_and_arguments_to_receiver_and_return",
        }:
            candidates = [*receiver, *arguments]
        else:
            return None
        return self._merge_states(
            [registers[register] for register in candidates if register in registers]
        )

    @staticmethod
    def _source_state(evidence: dict[str, Any]) -> dict[str, Any]:
        source = {
            "kind": "api-return",
            "api": evidence.get("api"),
            "rule_id": evidence.get("rule_id"),
            "source_kind": evidence.get("source_kind"),
            "register": None,
            "line": evidence.get("line"),
            "instruction": evidence.get("instruction"),
            "class_name": evidence.get("class_name"),
            "method_signature": evidence.get("method_signature"),
            "smali_path": evidence.get("smali_path"),
        }
        classification = (
            INTERFACE_TAINTED
            if evidence.get("source_kind") in USER_INTERFACE_SOURCE_KINDS
            else EXTERNAL_TAINTED
        )
        return {
            "classification": classification,
            "constant_values": [],
            "sources": [source],
            "validations": [],
            "trace": [
                {
                    "kind": "api-source",
                    "line": evidence.get("line"),
                    "instruction": evidence.get("instruction"),
                    "class_name": evidence.get("class_name"),
                    "method_signature": evidence.get("method_signature"),
                    "smali_path": evidence.get("smali_path"),
                }
            ],
            "object_ids": [],
            "array_ids": [],
        }

    @staticmethod
    def _set_source_result_register(
        state: dict[str, Any],
        register: str,
    ) -> None:
        for source in state["sources"]:
            if source.get("register") is None:
                source["register"] = register

    @staticmethod
    def _validation_reference(
        evidence: dict[str, Any],
        tainted_registers: list[str],
    ) -> dict[str, Any]:
        return {
            "api": evidence.get("api"),
            "rule_id": evidence.get("rule_id"),
            "validation_kind": evidence.get("validation_kind"),
            "line": evidence.get("line"),
            "instruction": evidence.get("instruction"),
            "class_name": evidence.get("class_name"),
            "method_signature": evidence.get("method_signature"),
            "smali_path": evidence.get("smali_path"),
            "tainted_registers": tainted_registers,
        }

    def _mark_related_registers_validated(
        self,
        registers: dict[str, dict[str, Any]],
        invocation_state: dict[str, Any],
        validation: dict[str, Any],
    ) -> None:
        source_keys = {
            self._reference_key(source)
            for source in invocation_state["sources"]
        }
        for state in registers.values():
            if not source_keys.intersection(
                self._reference_key(source) for source in state["sources"]
            ):
                continue
            state["validations"] = self._unique_references(
                [*state["validations"], validation]
            )
            state["trace"].append(
                {
                    "kind": "possible-validation",
                    **validation,
                }
            )

    def _flow_record(
        self,
        sink: dict[str, Any],
        state: dict[str, Any],
        tainted_registers: list[str],
        argument_assessment: dict[str, Any],
    ) -> dict[str, Any]:
        validations = self._unique_references(state["validations"])
        status = (
            "confirmed-with-possible-validation"
            if validations
            else "confirmed-unvalidated"
        )
        approximate_object_propagation = any(
            step.get("kind") in {
                "constructor-propagation",
                "constructor-capture",
            }
            for step in state.get("trace", [])
        )
        storage_steps = {
            step.get("kind")
            for step in state.get("trace", [])
            if step.get("kind")
            in {
                "instance-field-read",
                "instance-field-write",
                "static-field-read",
                "static-field-write",
                "array-read",
                "array-write",
                "container-read",
                "container-write",
                "constructor-capture",
            }
        }
        sink_reference = {
            "api": sink.get("api"),
            "rule_id": sink.get("rule_id"),
            "operation_kind": sink.get("operation_kind"),
            "severity": sink.get("severity"),
            "sensitive_arguments": sink.get("sensitive_arguments", []),
            "line": sink.get("line"),
            "instruction": sink.get("instruction"),
            "class_name": sink.get("class_name"),
            "method_signature": sink.get("method_signature"),
            "smali_path": sink.get("smali_path"),
            "tainted_registers": tainted_registers,
            "argument_classification": argument_assessment[
                "classification"
            ],
            "arguments": deepcopy(argument_assessment["arguments"]),
        }
        ipc_transition = argument_assessment.get("ipc_transition")
        if ipc_transition is not None:
            sink_reference["ipc_transition"] = deepcopy(ipc_transition)
        result = {
            "flow_id": None,
            "status": status,
            "confidence": (
                "high"
                if not validations and not approximate_object_propagation
                else "medium"
            ),
            "tracking_precision": (
                "approximate-object-propagation"
                if approximate_object_propagation
                else (
                    "container-dependency"
                    if storage_steps
                    & {"container-read", "container-write"}
                    else (
                        "field-or-array-dependency"
                        if storage_steps
                        else "register-dependency"
                    )
                )
            ),
            "storage_propagation": sorted(storage_steps),
            "argument_classification": argument_assessment[
                "classification"
            ],
            "argument_assessments": deepcopy(
                argument_assessment["arguments"]
            ),
            "sources": self._unique_references(state["sources"]),
            "possible_validations": validations,
            "sink": sink_reference,
            "tainted_registers_at_sink": tainted_registers,
            "trace": [
                *state["trace"],
                {"kind": "sensitive-operation", **sink_reference},
            ],
            "definitive_security_verdict": False,
        }
        if ipc_transition is not None:
            result["ipc_transition"] = deepcopy(ipc_transition)
        return result

    @staticmethod
    def _trace_step(
        kind: str,
        spec: dict[str, Any],
        line: int,
        instruction: str,
        source: str | None = None,
        destination: str | None = None,
    ) -> dict[str, Any]:
        result = {
            "kind": kind,
            "line": line,
            "instruction": instruction,
            "class_name": spec["class_name"],
            "method_signature": spec["signature"],
            "smali_path": spec["smali_path"],
        }
        if source is not None:
            result["source_register"] = source
        if destination is not None:
            result["destination_register"] = destination
        return result

    def _merge_states(
        self,
        states: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        if not states:
            return None
        sources = self._unique_references(
            [source for state in states for source in state.get("sources", [])]
        )
        classifications = {
            self._state_classification(state) for state in states
        }
        if any(self._is_external_source(source) for source in sources):
            classification = EXTERNAL_TAINTED
        elif sources:
            classification = INTERFACE_TAINTED
        elif classifications == {CONSTANT}:
            classification = CONSTANT
        else:
            classification = UNKNOWN
        return {
            "classification": classification,
            "constant_values": list(
                dict.fromkeys(
                    value
                    for state in states
                    for value in state.get("constant_values", [])
                )
            ),
            "sources": sources,
            "validations": self._unique_references(
                [
                    validation
                    for state in states
                    for validation in state.get("validations", [])
                ]
            ),
            "trace": self._unique_references(
                [step for state in states for step in state.get("trace", [])]
            ),
            "object_ids": list(
                dict.fromkeys(
                    object_id
                    for state in states
                    for object_id in state.get("object_ids", [])
                )
            ),
            "object_descriptors": list(
                dict.fromkeys(
                    descriptor
                    for state in states
                    for descriptor in state.get("object_descriptors", [])
                )
            ),
            "array_ids": list(
                dict.fromkeys(
                    array_id
                    for state in states
                    for array_id in state.get("array_ids", [])
                )
            ),
            "array_descriptors": list(
                dict.fromkeys(
                    descriptor
                    for state in states
                    for descriptor in state.get("array_descriptors", [])
                )
            ),
        }

    @staticmethod
    def _is_external_source(source: dict[str, Any]) -> bool:
        return source.get("source_kind") not in USER_INTERFACE_SOURCE_KINDS

    def _deduplicate_flows(
        self,
        flows: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        seen: set[tuple[Any, ...]] = set()
        for flow in sorted(
            flows,
            key=lambda item: (
                item["sink"].get("smali_path") or "",
                item["sink"].get("line") or 0,
                item["sink"].get("api") or "",
            ),
        ):
            key = (
                flow["sink"].get("smali_path"),
                flow["sink"].get("line"),
                flow["sink"].get("api"),
                tuple(
                    self._reference_key(source)
                    for source in flow["sources"]
                ),
            )
            if key not in seen:
                seen.add(key)
                result.append(flow)
        return result

    @staticmethod
    def _deduplicate_ipc_transitions(
        transitions: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        seen: set[tuple[Any, ...]] = set()
        for transition in sorted(
            transitions,
            key=lambda item: (
                item.get("source_component") or "",
                item.get("source_entry_point") or "",
                item.get("smali_path") or "",
                item.get("line") or 0,
                item.get("api") or "",
            ),
        ):
            key = (
                transition.get("source_component"),
                transition.get("source_entry_point"),
                transition.get("smali_path"),
                transition.get("line"),
                transition.get("api"),
            )
            if key in seen:
                continue
            seen.add(key)
            result.append(transition)
        return result

    @staticmethod
    def _descriptor_to_class_name(descriptor: str) -> str:
        return descriptor[1:-1].replace("/", ".")

    @staticmethod
    def _register_sort_key(register: str) -> tuple[str, int]:
        return register[0], int(register[1:])

    @staticmethod
    def _reference_key(reference: dict[str, Any]) -> tuple[Any, ...]:
        return (
            reference.get("kind"),
            reference.get("api"),
            reference.get("smali_path"),
            reference.get("method_signature"),
            reference.get("line"),
            reference.get("register"),
            reference.get("source_register"),
            reference.get("destination_register"),
        )

    @classmethod
    def _unique_references(
        cls,
        references: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        seen: set[tuple[Any, ...]] = set()
        for reference in references:
            key = cls._reference_key(reference)
            if key not in seen:
                seen.add(key)
                result.append(deepcopy(reference))
        return result

    @staticmethod
    def _limitations() -> list[str]:
        return [
            "O fluxo confirmado representa dependência entre registradores, não exploração prática.",
            "A análise é sensível à ordem textual e não calcula dominadores de todos os desvios condicionais.",
            "Campos e arrays são rastreados por aliases de alocação; aliases complexos, reflection e serialização ainda podem interromper o fluxo.",
            "Intent, Bundle e ContentValues são rastreados por identidade e chave; APIs de contêiner não reconhecidas permanecem aproximadas.",
            "Capturas de construtores de callbacks são aproximadas quando o campo exato não pode ser associado ao argumento.",
            "Código nativo e carregamento dinâmico não são analisados.",
            "Parâmetros wide de chamadas internas podem exigir revisão manual do mapeamento de registradores.",
            "Uma possível validação encontrada no caminho precisa ter sua eficácia revisada manualmente.",
        ]

    @classmethod
    def _error_result(cls, reason: str) -> dict[str, Any]:
        return {
            "status": "error",
            "reason": reason,
            "data_flow_status": "not-analyzed",
            "analyzed_method_count": 0,
            "source_count": 0,
            "touched_validation_count": 0,
            "sensitive_operation_count": 0,
            "flow_count": 0,
            "validated_flow_count": 0,
            "unvalidated_flow_count": 0,
            "sensitive_argument_assessment_count": 0,
            "argument_classification_counts": {
                EXTERNAL_TAINTED: 0,
                INTERFACE_TAINTED: 0,
                CONSTANT: 0,
                UNKNOWN: 0,
            },
            "sensitive_argument_assessments": [],
            "ipc_transition_count": 0,
            "ipc_transitions": [],
            "flows": [],
            "methods": [],
            "definitive_security_verdict": False,
            "limitations": cls._limitations(),
        }
