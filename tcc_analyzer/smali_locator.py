"""Localização de classes nos diretórios Smali gerados pelo Apktool."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable


SMALI_ROOT_PATTERN = re.compile(r"smali_classes(?P<index>[1-9]\d*)$")


class SmaliLocator:
    """Mapeia nomes de classes Android para seus respectivos arquivos Smali."""

    def __init__(self, decompiled_dir: str | Path) -> None:
        self.decompiled_dir = Path(decompiled_dir)
        if not self.decompiled_dir.is_dir():
            raise FileNotFoundError(
                f"Diretório descompilado não encontrado: {self.decompiled_dir}"
            )

    def smali_roots(self) -> list[Path]:
        """Retorna os diretórios Smali em ordem de DEX: smali, classes2, etc."""
        roots = [
            child
            for child in self.decompiled_dir.iterdir()
            if child.is_dir() and self._smali_root_index(child.name) is not None
        ]
        return sorted(
            roots,
            key=lambda path: self._smali_root_index(path.name) or 0,
        )

    def locate(
        self,
        class_name: str,
        package_name: str | None = None,
    ) -> Path | None:
        """Localiza uma classe por nome qualificado, relativo ou descriptor Smali.

        Exemplos aceitos:
        - ``owasp.sat.agoat.DownloadInvoiceService``
        - ``.DownloadInvoiceService`` com ``package_name``
        - ``Lowasp/sat/agoat/DownloadInvoiceService;``
        """
        qualified_name = self.normalize_class_name(class_name, package_name)
        relative_path = Path(*qualified_name.split(".")).with_suffix(".smali")

        for smali_root in self.smali_roots():
            candidate = smali_root / relative_path
            if candidate.is_file():
                return candidate

        return None

    def locate_many(
        self,
        class_names: Iterable[str],
        package_name: str | None = None,
    ) -> dict[str, Path | None]:
        """Localiza várias classes preservando os nomes recebidos como chaves."""
        return {
            class_name: self.locate(class_name, package_name)
            for class_name in class_names
        }

    def relative_path(self, smali_file: str | Path) -> Path:
        """Retorna um caminho de evidência relativo ao diretório descompilado."""
        smali_file = Path(smali_file)
        try:
            return smali_file.relative_to(self.decompiled_dir)
        except ValueError as error:
            raise ValueError(
                f"O arquivo não pertence ao diretório analisado: {smali_file}"
            ) from error

    @staticmethod
    def normalize_class_name(
        class_name: str,
        package_name: str | None = None,
    ) -> str:
        """Normaliza nome Java, nome relativo ou descriptor para nome qualificado."""
        normalized = class_name.strip()
        if not normalized:
            raise ValueError("O nome da classe não pode ser vazio.")

        if normalized.startswith("L") and normalized.endswith(";"):
            normalized = normalized[1:-1].replace("/", ".")

        if "\\" in normalized or "/" in normalized:
            raise ValueError(f"Nome de classe inválido: {class_name}")

        if normalized.startswith("."):
            if not package_name:
                raise ValueError(
                    "package_name é obrigatório para nomes relativos de classe."
                )
            normalized = f"{package_name}{normalized}"
        elif "." not in normalized:
            if not package_name:
                raise ValueError(
                    "package_name é obrigatório para nomes de classe sem pacote."
                )
            normalized = f"{package_name}.{normalized}"

        parts = normalized.split(".")
        if any(not part or part in {".", ".."} for part in parts):
            raise ValueError(f"Nome de classe inválido: {class_name}")

        return normalized

    @staticmethod
    def class_descriptor(class_name: str, package_name: str | None = None) -> str:
        """Converte um nome de classe para o descriptor utilizado no Smali."""
        qualified_name = SmaliLocator.normalize_class_name(
            class_name,
            package_name,
        )
        return f"L{qualified_name.replace('.', '/')};"

    @staticmethod
    def _smali_root_index(directory_name: str) -> int | None:
        if directory_name == "smali":
            return 1
        match = SMALI_ROOT_PATTERN.fullmatch(directory_name)
        return int(match.group("index")) if match is not None else None
