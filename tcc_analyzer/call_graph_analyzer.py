"""Travessia limitada de chamadas internas iniciadas em entry points Smali."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .smali_locator import SmaliLocator


INVOKE_PATTERN = re.compile(
    r"^invoke-\S+\s+\{[^}]*\},\s*"
    r"(?P<descriptor>L[^;]+;)->(?P<signature>[^\s#]+)"
)
SYNTHETIC_REFERENCE_PATTERN = re.compile(
    r"^(?P<opcode>new-instance|sget-object)\s+.*?,\s*"
    r"(?P<descriptor>L[^;]+\$[^;]+;)"
)
SUPER_DESCRIPTOR_PATTERN = re.compile(
    r"^\s*\.super\s+(?P<descriptor>L[^;]+;)\s*$"
)
CALLBACK_METHOD_NAMES = {
    "accept",
    "call",
    "doInBackground",
    "invoke",
    "invokeSuspend",
    "onActivityResult",
    "onChanged",
    "onClick",
    "onComplete",
    "onError",
    "onFailure",
    "onItemClick",
    "onLongClick",
    "onNext",
    "onPostExecute",
    "onResponse",
    "onResult",
    "onSuccess",
    "resumeWith",
    "run",
}
IGNORED_INTERNAL_METHODS = {"<clinit>", "<init>"}

EvidenceDetector = Callable[[Path, int, int], list[dict[str, Any]]]
MethodExtractor = Callable[
    [Path, str],
    tuple[list[dict[str, Any]], list[str], int],
]


@dataclass(frozen=True)
class CallTarget:
    """Alvo interno descoberto em uma instrução Smali."""

    descriptor: str
    signature: str
    called_at_line: int
    instruction: str
    call_type: str


class CallGraphAnalyzer:
    """Segue chamadas da aplicação com profundidade e ciclos controlados."""

    def __init__(
        self,
        decompiled_dir: str | Path,
        evidence_detector: EvidenceDetector,
        method_extractor: MethodExtractor,
        application_package: str | None = None,
        max_depth: int = 3,
    ) -> None:
        if max_depth < 0:
            raise ValueError("max_depth não pode ser negativo.")

        self.decompiled_dir = Path(decompiled_dir)
        self.locator = SmaliLocator(self.decompiled_dir)
        self.evidence_detector = evidence_detector
        self.method_extractor = method_extractor
        self.application_package = application_package
        self.max_depth = max_depth
        self._method_cache: dict[Path, list[dict[str, Any]]] = {}

    def analyze(
        self,
        root_smali_file: str | Path,
        root_descriptor: str,
        root_method: dict[str, Any],
    ) -> dict[str, Any]:
        """Constrói o subgrafo alcançável a partir de um entry point."""
        root_smali_file = Path(root_smali_file)
        root_key = (root_descriptor, root_method["signature"])
        root_label = self._method_label(
            root_descriptor,
            root_method["signature"],
        )
        reachable_methods: list[dict[str, Any]] = []
        unresolved_calls: list[dict[str, Any]] = []
        cycles: list[dict[str, Any]] = []
        truncated_calls: list[dict[str, Any]] = []
        visited = {root_key}
        duplicate_call_count = 0

        def visit(
            smali_file: Path,
            descriptor: str,
            method: dict[str, Any],
            depth: int,
            called_at_line: int,
            call_type: str,
            call_instruction: str,
            call_chain: list[str],
            active_path: set[tuple[str, str]],
        ) -> None:
            nonlocal duplicate_call_count

            relative_path = self.locator.relative_path(smali_file).as_posix()
            raw_evidence = self.evidence_detector(
                smali_file,
                method["start_line"],
                method["end_line"],
            )
            method_evidence = [
                self._enrich_evidence(
                    item,
                    descriptor,
                    method["signature"],
                    relative_path,
                    depth,
                    call_chain,
                )
                for item in raw_evidence
            ]
            reachable_methods.append(
                {
                    "class_name": self.descriptor_to_class_name(descriptor),
                    "descriptor": descriptor,
                    "method": method["name"],
                    "signature": method["signature"],
                    "modifiers": method.get("modifiers", []),
                    "smali_path": relative_path,
                    "start_line": method["start_line"],
                    "end_line": method["end_line"],
                    "depth": depth,
                    "called_at_line": called_at_line,
                    "call_type": call_type,
                    "call_instruction": call_instruction,
                    "call_chain": call_chain,
                    "evidence_count": len(method_evidence),
                    "evidence": method_evidence,
                }
            )

            targets = self._discover_targets(smali_file, method)
            if depth >= self.max_depth:
                for target in targets:
                    resolved = self._resolve_target(target)
                    if resolved["ignored"]:
                        continue
                    if (
                        resolved["method"] is None
                        or resolved["smali_file"] is None
                    ):
                        unresolved_calls.append(
                            self._call_record(
                                target,
                                caller_descriptor=descriptor,
                                caller_signature=method["signature"],
                                target_depth=depth + 1,
                                call_chain=[
                                    *call_chain,
                                    self._method_label(
                                        target.descriptor,
                                        target.signature,
                                    ),
                                ],
                                reason=resolved["reason"],
                            )
                        )
                        continue
                    truncated_calls.append(
                        self._call_record(
                            target,
                            caller_descriptor=descriptor,
                            caller_signature=method["signature"],
                            target_depth=depth + 1,
                            call_chain=[
                                *call_chain,
                                self._method_label(
                                    target.descriptor,
                                    target.signature,
                                ),
                            ],
                            reason="max-depth-reached",
                        )
                    )
                return

            for target in targets:
                target_key = (target.descriptor, target.signature)
                target_label = self._method_label(
                    target.descriptor,
                    target.signature,
                )
                target_chain = [*call_chain, target_label]

                if target_key in active_path:
                    cycles.append(
                        self._call_record(
                            target,
                            caller_descriptor=descriptor,
                            caller_signature=method["signature"],
                            target_depth=depth + 1,
                            call_chain=target_chain,
                            reason="cycle-detected",
                        )
                    )
                    continue

                if target_key in visited:
                    duplicate_call_count += 1
                    continue

                resolved = self._resolve_target(target)
                if resolved["ignored"]:
                    continue
                if resolved["method"] is None or resolved["smali_file"] is None:
                    unresolved_calls.append(
                        self._call_record(
                            target,
                            caller_descriptor=descriptor,
                            caller_signature=method["signature"],
                            target_depth=depth + 1,
                            call_chain=target_chain,
                            reason=resolved["reason"],
                        )
                    )
                    continue

                resolved_descriptor = resolved["descriptor"]
                resolved_key = (resolved_descriptor, target.signature)
                if resolved_key in active_path:
                    cycles.append(
                        self._call_record(
                            target,
                            caller_descriptor=descriptor,
                            caller_signature=method["signature"],
                            target_depth=depth + 1,
                            call_chain=target_chain,
                            reason="cycle-detected",
                        )
                    )
                    continue
                if resolved_key in visited:
                    duplicate_call_count += 1
                    continue

                visited.add(resolved_key)
                visit(
                    resolved["smali_file"],
                    resolved_descriptor,
                    resolved["method"],
                    depth + 1,
                    target.called_at_line,
                    target.call_type,
                    target.instruction,
                    target_chain,
                    {*active_path, resolved_key},
                )

        root_targets = self._discover_targets(root_smali_file, root_method)
        if self.max_depth == 0:
            for target in root_targets:
                resolved = self._resolve_target(target)
                if resolved["ignored"]:
                    continue
                if (
                    resolved["method"] is None
                    or resolved["smali_file"] is None
                ):
                    unresolved_calls.append(
                        self._call_record(
                            target,
                            caller_descriptor=root_descriptor,
                            caller_signature=root_method["signature"],
                            target_depth=1,
                            call_chain=[
                                root_label,
                                self._method_label(
                                    target.descriptor,
                                    target.signature,
                                ),
                            ],
                            reason=resolved["reason"],
                        )
                    )
                    continue
                truncated_calls.append(
                    self._call_record(
                        target,
                        caller_descriptor=root_descriptor,
                        caller_signature=root_method["signature"],
                        target_depth=1,
                        call_chain=[
                            root_label,
                            self._method_label(
                                target.descriptor,
                                target.signature,
                            ),
                        ],
                        reason="max-depth-reached",
                    )
                )
        else:
            for target in root_targets:
                target_key = (target.descriptor, target.signature)
                target_label = self._method_label(
                    target.descriptor,
                    target.signature,
                )
                target_chain = [root_label, target_label]

                if target_key == root_key:
                    cycles.append(
                        self._call_record(
                            target,
                            caller_descriptor=root_descriptor,
                            caller_signature=root_method["signature"],
                            target_depth=1,
                            call_chain=target_chain,
                            reason="cycle-detected",
                        )
                    )
                    continue

                if target_key in visited:
                    duplicate_call_count += 1
                    continue

                resolved = self._resolve_target(target)
                if resolved["ignored"]:
                    continue
                if resolved["method"] is None or resolved["smali_file"] is None:
                    unresolved_calls.append(
                        self._call_record(
                            target,
                            caller_descriptor=root_descriptor,
                            caller_signature=root_method["signature"],
                            target_depth=1,
                            call_chain=target_chain,
                            reason=resolved["reason"],
                        )
                    )
                    continue

                resolved_descriptor = resolved["descriptor"]
                resolved_key = (resolved_descriptor, target.signature)
                if resolved_key == root_key:
                    cycles.append(
                        self._call_record(
                            target,
                            caller_descriptor=root_descriptor,
                            caller_signature=root_method["signature"],
                            target_depth=1,
                            call_chain=target_chain,
                            reason="cycle-detected",
                        )
                    )
                    continue
                if resolved_key in visited:
                    duplicate_call_count += 1
                    continue

                visited.add(resolved_key)
                visit(
                    resolved["smali_file"],
                    resolved_descriptor,
                    resolved["method"],
                    1,
                    target.called_at_line,
                    target.call_type,
                    target.instruction,
                    target_chain,
                    {root_key, resolved_key},
                )

        indirect_evidence = [
            item
            for method in reachable_methods
            for item in method["evidence"]
        ]
        return {
            "status": "analyzed",
            "reason": None,
            "max_depth": self.max_depth,
            "reachable_method_count": len(reachable_methods),
            "indirect_evidence_count": len(indirect_evidence),
            "unresolved_call_count": len(unresolved_calls),
            "cycle_count": len(cycles),
            "truncated_call_count": len(truncated_calls),
            "duplicate_call_count": duplicate_call_count,
            "reachable_methods": reachable_methods,
            "indirect_evidence": indirect_evidence,
            "unresolved_calls": unresolved_calls,
            "cycles": cycles,
            "truncated_calls": truncated_calls,
        }

    def _discover_targets(
        self,
        smali_file: Path,
        method: dict[str, Any],
    ) -> list[CallTarget]:
        lines = smali_file.read_text(
            encoding="utf-8",
            errors="replace",
        ).splitlines()
        targets: list[CallTarget] = []
        seen: set[tuple[str, str, int, str]] = set()
        first_index = max(method["start_line"] - 1, 0)
        last_index = min(method["end_line"], len(lines))

        for line_number in range(first_index + 1, last_index + 1):
            instruction = lines[line_number - 1].strip()
            invoke_match = INVOKE_PATTERN.match(instruction)
            if invoke_match is not None:
                descriptor = invoke_match.group("descriptor")
                signature = invoke_match.group("signature")
                method_name = signature.split("(", maxsplit=1)[0]
                if (
                    self._is_application_class(descriptor)
                    and method_name not in IGNORED_INTERNAL_METHODS
                ):
                    self._append_target(
                        targets,
                        seen,
                        CallTarget(
                            descriptor=descriptor,
                            signature=signature,
                            called_at_line=line_number,
                            instruction=instruction,
                            call_type="invoke",
                        ),
                    )

            synthetic_match = SYNTHETIC_REFERENCE_PATTERN.match(instruction)
            if synthetic_match is None:
                continue

            descriptor = synthetic_match.group("descriptor")
            if not self._is_application_class(descriptor):
                continue

            for callback in self._synthetic_callbacks(descriptor):
                self._append_target(
                    targets,
                    seen,
                    CallTarget(
                        descriptor=descriptor,
                        signature=callback["signature"],
                        called_at_line=line_number,
                        instruction=instruction,
                        call_type="synthetic-callback-reference",
                    ),
                )

        return targets

    def _synthetic_callbacks(
        self,
        descriptor: str,
    ) -> list[dict[str, Any]]:
        smali_file = self.locator.locate(descriptor)
        if smali_file is None:
            return []
        return [
            method
            for method in self._methods_for_file(smali_file)
            if method["name"] in CALLBACK_METHOD_NAMES
        ]

    def _resolve_target(self, target: CallTarget) -> dict[str, Any]:
        descriptor = target.descriptor
        inspected_descriptors: set[str] = set()

        while descriptor not in inspected_descriptors:
            inspected_descriptors.add(descriptor)
            smali_file = self.locator.locate(descriptor)
            if smali_file is None:
                return {
                    "descriptor": descriptor,
                    "smali_file": None,
                    "method": None,
                    "reason": "class-not-found",
                    "ignored": False,
                }

            try:
                methods = self._methods_for_file(smali_file)
            except OSError:
                return {
                    "descriptor": descriptor,
                    "smali_file": smali_file,
                    "method": None,
                    "reason": "smali-read-error",
                    "ignored": False,
                }

            method = next(
                (
                    candidate
                    for candidate in methods
                    if candidate["signature"] == target.signature
                ),
                None,
            )
            if method is not None:
                return {
                    "descriptor": descriptor,
                    "smali_file": smali_file,
                    "method": method,
                    "reason": None,
                    "ignored": False,
                }

            super_descriptor = self._super_descriptor(smali_file)
            if (
                not super_descriptor
                or not self._is_application_class(super_descriptor)
            ):
                return {
                    "descriptor": descriptor,
                    "smali_file": None,
                    "method": None,
                    "reason": "inherited-framework-method",
                    "ignored": True,
                }
            descriptor = super_descriptor

        return {
            "descriptor": descriptor,
            "smali_file": None,
            "method": None,
            "reason": "inheritance-cycle-detected",
            "ignored": False,
        }

    @staticmethod
    def _super_descriptor(smali_file: Path) -> str | None:
        for line in smali_file.read_text(
            encoding="utf-8",
            errors="replace",
        ).splitlines():
            match = SUPER_DESCRIPTOR_PATTERN.match(line)
            if match is not None:
                return match.group("descriptor")
        return None

    def _methods_for_file(self, smali_file: Path) -> list[dict[str, Any]]:
        resolved = smali_file.resolve()
        if resolved not in self._method_cache:
            methods, _, _ = self.method_extractor(smali_file, "unknown")
            self._method_cache[resolved] = methods
        return self._method_cache[resolved]

    def _is_application_class(self, descriptor: str) -> bool:
        if self.application_package:
            prefix = f"L{self.application_package.replace('.', '/')}/"
            return descriptor.startswith(prefix)
        return self.locator.locate(descriptor) is not None

    @staticmethod
    def _append_target(
        targets: list[CallTarget],
        seen: set[tuple[str, str, int, str]],
        target: CallTarget,
    ) -> None:
        key = (
            target.descriptor,
            target.signature,
            target.called_at_line,
            target.call_type,
        )
        if key not in seen:
            seen.add(key)
            targets.append(target)

    @staticmethod
    def _enrich_evidence(
        evidence: dict[str, Any],
        descriptor: str,
        signature: str,
        smali_path: str,
        depth: int,
        call_chain: list[str],
    ) -> dict[str, Any]:
        return {
            **evidence,
            "origin": "indirect",
            "depth": depth,
            "class_name": CallGraphAnalyzer.descriptor_to_class_name(
                descriptor
            ),
            "method_signature": signature,
            "smali_path": smali_path,
            "call_chain": call_chain,
        }

    @staticmethod
    def _call_record(
        target: CallTarget,
        caller_descriptor: str,
        caller_signature: str,
        target_depth: int,
        call_chain: list[str],
        reason: str | None,
    ) -> dict[str, Any]:
        return {
            "caller": CallGraphAnalyzer._method_label(
                caller_descriptor,
                caller_signature,
            ),
            "target_class": CallGraphAnalyzer.descriptor_to_class_name(
                target.descriptor
            ),
            "target_signature": target.signature,
            "called_at_line": target.called_at_line,
            "instruction": target.instruction,
            "call_type": target.call_type,
            "target_depth": target_depth,
            "call_chain": call_chain,
            "reason": reason,
        }

    @staticmethod
    def descriptor_to_class_name(descriptor: str) -> str:
        return descriptor[1:-1].replace("/", ".")

    @staticmethod
    def _method_label(descriptor: str, signature: str) -> str:
        return (
            f"{CallGraphAnalyzer.descriptor_to_class_name(descriptor)}"
            f"->{signature}"
        )

    @staticmethod
    def empty_result(
        status: str,
        reason: str,
        max_depth: int,
    ) -> dict[str, Any]:
        return {
            "status": status,
            "reason": reason,
            "max_depth": max_depth,
            "reachable_method_count": 0,
            "indirect_evidence_count": 0,
            "unresolved_call_count": 0,
            "cycle_count": 0,
            "truncated_call_count": 0,
            "duplicate_call_count": 0,
            "reachable_methods": [],
            "indirect_evidence": [],
            "unresolved_calls": [],
            "cycles": [],
            "truncated_calls": [],
        }
