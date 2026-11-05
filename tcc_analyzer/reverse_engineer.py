"""Integração com o Apktool para descompilar e recompilar APKs."""

from __future__ import annotations

import platform
import re
import shutil
import subprocess
from pathlib import Path
from typing import Sequence


class APKReverseEngineer:
    """Executa operações de engenharia reversa por meio do Apktool."""

    def __init__(
        self,
        apktool_path: str = "apktool",
        output_base: str | Path = "output",
    ) -> None:
        self.output_base = Path(output_base)
        self.output_base.mkdir(parents=True, exist_ok=True)

        resolved = shutil.which(apktool_path)
        if resolved is None:
            raise FileNotFoundError(
                f"Apktool não encontrado. Verifique se '{apktool_path}' está "
                "no PATH ou informe o caminho completo do executável."
            )

        self.apktool_path = resolved
        self.is_windows = platform.system() == "Windows"
        self.last_decompile_log = ""

    def _run_command(self, arguments: Sequence[str | Path]) -> tuple[bool, str]:
        """Executa um comando externo e transmite sua saída para o terminal."""
        command_parts = [str(part) for part in arguments]
        command: str | list[str]

        if self.is_windows:
            # Arquivos .bat precisam ser interpretados pelo shell do Windows.
            command = subprocess.list2cmdline(command_parts)
        else:
            command = command_parts

        try:
            process = subprocess.Popen(
                command,
                shell=self.is_windows,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
        except OSError as error:
            return False, str(error)

        log_lines: list[str] = []
        if process.stdout is not None:
            for line in process.stdout:
                line = line.rstrip()
                if line:
                    print(f"    {line}")
                    log_lines.append(line)

        process.wait()
        full_log = "\n".join(log_lines)
        success = process.returncode == 0

        if not success and not full_log:
            full_log = f"O processo terminou com código {process.returncode}."

        return success, full_log

    def decompile(self, apk_path: str | Path, force: bool = True) -> Path | None:
        """Descompila o APK e retorna o diretório criado pelo Apktool."""
        apk_path = Path(apk_path)
        if not apk_path.is_file():
            raise FileNotFoundError(f"APK não encontrado: {apk_path}")
        if apk_path.suffix.lower() != ".apk":
            raise ValueError(f"O arquivo informado não possui extensão .apk: {apk_path}")

        output_dir = self.output_base / apk_path.stem
        command = [self.apktool_path, "d", apk_path, "-o", output_dir]
        if force:
            command.append("-f")

        print(f"[+] Descompilando {apk_path.name}...")
        success, log = self._run_command(command)
        self.last_decompile_log = log

        if success:
            print(f"[+] Descompilação concluída: {output_dir}")
            return output_dir

        print(f"[-] Erro ao descompilar:\n{log}")
        return None

    def version(self) -> str | None:
        """Retorna a versão efetivamente informada pelo Apktool."""
        match = re.search(r"Using Apktool\s+([^\s]+)", self.last_decompile_log)
        if match is not None:
            return match.group(1)

        command_parts = [self.apktool_path, "--version"]
        command: str | list[str] = (
            subprocess.list2cmdline(command_parts)
            if self.is_windows
            else command_parts
        )
        try:
            completed = subprocess.run(
                command,
                shell=self.is_windows,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        for line in completed.stdout.splitlines():
            version_match = re.search(r"\b(\d+\.\d+(?:\.\d+)?)\b", line)
            if version_match is not None:
                return version_match.group(1)
        return None

    @staticmethod
    def get_manifest_path(decompiled_dir: str | Path) -> Path | None:
        """Retorna o AndroidManifest.xml extraído, quando existente."""
        manifest_path = Path(decompiled_dir) / "AndroidManifest.xml"
        return manifest_path if manifest_path.is_file() else None

    def rebuild(
        self,
        decompiled_dir: str | Path,
        output_apk: str | Path | None = None,
    ) -> bool:
        """Recompila um diretório previamente descompilado."""
        decompiled_dir = Path(decompiled_dir)
        if not decompiled_dir.is_dir():
            raise FileNotFoundError(
                f"Diretório descompilado não encontrado: {decompiled_dir}"
            )

        command: list[str | Path] = [self.apktool_path, "b", decompiled_dir]
        if output_apk is not None:
            command.extend(["-o", Path(output_apk)])

        print(f"[+] Recompilando {decompiled_dir.name}...")
        success, log = self._run_command(command)

        if success:
            print("[+] Recompilação concluída.")
        else:
            print(f"[-] Erro ao recompilar:\n{log}")

        return success
