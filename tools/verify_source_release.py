#!/usr/bin/env python3
"""Valida de forma independente o unico ZIP final do ERPT-BR."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import os
import re
import stat
import struct
import unicodedata
import zipfile
import zlib
from pathlib import Path, PurePosixPath
from typing import BinaryIO


SOURCE_FILES = frozenset(
    {
        "ERPT-BR.cmd",
        "interno/INSTALAR_AMBIENTE.cmd",
        "interno/ABRIR_INTERFACE.cmd",
        "README.md",
        "MIGRACAO.md",
        "docs/INCIDENTE-0.9.1.md",
        "SECURITY.md",
        "THIRD_PARTY_NOTICES.md",
        "LICENSE",
        "patcher/__init__.py",
        "patcher/bnk.py",
        "patcher/engine.py",
        "patcher/diagnostics.py",
        "patcher/patch_data.py",
        "patcher/patcher_gui.py",
        "patcher/patcher.ico",
        "patcher/requirements-win64.lock",
    }
)
WHEEL_SHA256 = {
    "wheelhouse/customtkinter-5.2.2-py3-none-any.whl": (
        "14ad3e7cd3cb3b9eb642b9d4e8711ae80d3f79fb82545ad11258eeffb2e6b37c"
    ),
    "wheelhouse/darkdetect-0.8.0-py3-none-any.whl": (
        "a7509ccf517eaad92b31c214f593dbcf138ea8a43b2935406bbd565e15527a85"
    ),
    "wheelhouse/packaging-26.3-py3-none-any.whl": (
        "d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c"
    ),
    "wheelhouse/pycryptodome-3.23.0-cp37-abi3-win_amd64.whl": (
        "c75b52aacc6c0c260f204cbdd834f76edc9fb0d8e0da9fbf8352ef58202564e2"
    ),
}
FINAL_VERSION = "v0.9.4"
FINAL_ARCHIVE_NAME = "ERPT-BR-v0.9.4-Windows.zip"
PAYLOAD_ARCHIVE_NAME = "patch_data_v094.zip"
PAYLOAD_ARCHIVE_SIZE = 588_468_447
PAYLOAD_SHA256 = "430e9693a9b3313826e9f7c890cf592eb5b468d145bb405e8a4586002b877680"
PAYLOAD_TREE_SHA256 = "8544e551832c929eecad0cf9898204fd673bd4a37a0a6f37433865afbb3556cb"
PAYLOAD_FILE_COUNT = 9_241
PAYLOAD_WEM_COUNT = 8_969
PAYLOAD_BNK_COUNT = 272
PAYLOAD_UNCOMPRESSED_SIZE = 605_706_607
PAYLOAD_MAX_FILE_SIZE = 74_956_066
STREAM_CHUNK_SIZE = 1024 * 1024

EXPECTED_FILES = SOURCE_FILES | frozenset(WHEEL_SHA256) | {PAYLOAD_ARCHIVE_NAME}
FORBIDDEN_SUFFIXES = {".exe", ".dll", ".bat", ".ps1", ".scr", ".com"}
# These limits continue to apply to every ordinary source/wheel member.  The
# immutable payload gets its own exact, narrower exception below.
MAX_MEMBER_SIZE = 5 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED = 8 * 1024 * 1024
MAX_TOTAL_COMPRESSED = 8 * 1024 * 1024
MAX_ARCHIVE_SIZE = 8 * 1024 * 1024
MAX_FINAL_ARCHIVE_SIZE = PAYLOAD_ARCHIVE_SIZE + MAX_ARCHIVE_SIZE
FORBIDDEN_SOURCE_PATTERNS = {
    "exec(compile(": "execucao dinamica de codigo",
    "taskkill": "encerramento forcado de processos",
    "shellexecutew": "auto-elevacao UAC",
    "pyinstaller": "empacotador executavel",
    "nuitka": "empacotador executavel",
    "invoke-expression": "execucao dinamica do PowerShell",
    "-encodedcommand": "comando PowerShell codificado",
    "-executionpolicy bypass": "contorno da politica do PowerShell",
    "--ignore-security-hash": "contorno do hash de seguranca do WinGet",
    "installallusers=1": "instalacao global com elevacao",
    "-verb runas": "auto-elevacao UAC",
    "http://": "download sem HTTPS",
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_stream(stream: BinaryIO) -> tuple[int, str]:
    size = 0
    digest = hashlib.sha256()
    while chunk := stream.read(STREAM_CHUNK_SIZE):
        size += len(chunk)
        digest.update(chunk)
    return size, digest.hexdigest()


def _verify_gui_controls(gui_source: str) -> None:
    """Impede promover uma GUI que volte ao modo BHD estrito por acidente."""

    required = (
        'PATCHER_VERSION = "0.9.4"',
        "INSTALLATION_SUSPENDED = False",
        "BHD_INTEGRITY_SCOPED_MOD",
        "bhd_integrity_mode=BHD_INTEGRITY_SCOPED_MOD",
        '"easyanticheat_eos.exe": "Easy Anti-Cheat EOS"',
    )
    missing = [control for control in required if control not in gui_source]
    if missing:
        raise SystemExit(
            f"Controles obrigatorios ausentes da interface: {missing}"
        )


def _safe_payload_relative(name: str) -> str:
    prefix = "patch_data/"
    if not name.startswith(prefix):
        raise SystemExit(f"Layout inesperado no payload: {name!r}")
    relative = name[len(prefix) :]
    if not relative or "\\" in relative or ":" in relative or "\x00" in relative:
        raise SystemExit(f"Caminho inseguro no payload: {name!r}")
    parts = relative.split("/")
    path = PurePosixPath(*parts)
    if (
        path.is_absolute()
        or any(part in {"", ".", ".."} for part in parts)
        or path.as_posix() != relative
        or any(part.endswith((" ", ".")) for part in parts)
        or path.suffix.casefold() not in {".wem", ".bnk"}
    ):
        raise SystemExit(f"Caminho inseguro no payload: {name!r}")
    return relative


def _verify_nested_payload(
    outer: zipfile.ZipFile, payload_info: zipfile.ZipInfo
) -> None:
    """Authenticate and inflate the nested payload using bounded streaming."""

    try:
        with outer.open(payload_info, "r") as payload_stream:
            size, digest = _sha256_stream(payload_stream)
    except (OSError, EOFError, RuntimeError, zipfile.BadZipFile, zlib.error) as exc:
        raise SystemExit("Falha de integridade ou CRC no payload embutido.") from exc
    if size != PAYLOAD_ARCHIVE_SIZE or digest != PAYLOAD_SHA256:
        raise SystemExit(
            "Payload embutido divergente: "
            f"tamanho={size}, SHA-256={digest}"
        )

    tree_digest = hashlib.sha256()
    wem_count = 0
    bnk_count = 0
    total_size = 0
    max_file_size = 0
    try:
        # ZipExtFile is seekable here because the outer payload member is
        # ZIP_STORED.  This lets us inspect the nested ZIP without a 588 MB
        # allocation or a second temporary artifact.
        with outer.open(payload_info, "r") as payload_stream:
            if not payload_stream.seekable():
                raise SystemExit("O payload embutido nao permite validacao aninhada.")
            with zipfile.ZipFile(payload_stream, "r") as payload:
                if payload.comment:
                    raise SystemExit("O payload embutido contem comentario inesperado.")
                infos = payload.infolist()
                if len(infos) != PAYLOAD_FILE_COUNT:
                    raise SystemExit(
                        "Quantidade de arquivos divergente no payload embutido: "
                        f"esperado {PAYLOAD_FILE_COUNT}, obtido {len(infos)}"
                    )
                normalized: list[tuple[str, zipfile.ZipInfo]] = []
                seen: set[str] = set()
                for info in infos:
                    relative = _safe_payload_relative(info.filename)
                    canonical = unicodedata.normalize("NFC", relative).casefold()
                    if canonical in seen:
                        raise SystemExit(
                            f"Nome duplicado no payload embutido: {relative!r}"
                        )
                    seen.add(canonical)
                    unix_mode = (info.external_attr >> 16) & 0xFFFF
                    if (
                        info.is_dir()
                        or stat.S_IFMT(unix_mode) not in (0, stat.S_IFREG)
                        or info.flag_bits & 0x1
                        or info.compress_type
                        not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                        or info.file_size < 0
                        or info.file_size > PAYLOAD_MAX_FILE_SIZE
                    ):
                        raise SystemExit(
                            f"Membro inseguro no payload embutido: {info.filename!r}"
                        )
                    total_size += info.file_size
                    if total_size > PAYLOAD_UNCOMPRESSED_SIZE:
                        raise SystemExit(
                            "O payload embutido excede o tamanho descompactado fixado."
                        )
                    max_file_size = max(max_file_size, info.file_size)
                    if relative.casefold().endswith(".wem"):
                        wem_count += 1
                    else:
                        bnk_count += 1
                    normalized.append((relative, info))

                expected_order = sorted(
                    normalized,
                    key=lambda item: (
                        unicodedata.normalize("NFC", item[0]).casefold(),
                        item[0],
                    ),
                )
                if normalized != expected_order:
                    raise SystemExit(
                        "As entradas do payload embutido estao fora da ordem canonica."
                    )

                for relative, info in normalized:
                    encoded = relative.encode("utf-8")
                    tree_digest.update(struct.pack("<I", len(encoded)))
                    tree_digest.update(encoded)
                    tree_digest.update(struct.pack("<Q", info.file_size))
                    inflated = 0
                    header = bytearray()
                    with payload.open(info, "r") as member:
                        while chunk := member.read(STREAM_CHUNK_SIZE):
                            inflated += len(chunk)
                            tree_digest.update(chunk)
                            if len(header) < 12:
                                header.extend(chunk[: 12 - len(header)])
                    if inflated != info.file_size:
                        raise SystemExit(
                            f"Leitura incompleta no payload embutido: {relative!r}"
                        )
                    if relative.casefold().endswith(".wem"):
                        if (
                            len(header) < 12
                            or header[:4] != b"RIFF"
                            or header[8:12] != b"WAVE"
                        ):
                            raise SystemExit(
                                f"Cabecalho WEM invalido no payload: {relative!r}"
                            )
                    elif len(header) < 4 or header[:4] != b"BKHD":
                        raise SystemExit(
                            f"Cabecalho BNK invalido no payload: {relative!r}"
                        )
    except SystemExit:
        raise
    except (OSError, EOFError, RuntimeError, zipfile.BadZipFile, zlib.error) as exc:
        raise SystemExit(
            "Falha ao abrir ou descompactar o payload embutido."
        ) from exc

    if (
        wem_count != PAYLOAD_WEM_COUNT
        or bnk_count != PAYLOAD_BNK_COUNT
        or total_size != PAYLOAD_UNCOMPRESSED_SIZE
        or max_file_size != PAYLOAD_MAX_FILE_SIZE
    ):
        raise SystemExit(
            "Estatisticas divergentes no payload embutido: "
            f"WEM={wem_count}, BNK={bnk_count}, bytes={total_size}, "
            f"maior={max_file_size}"
        )
    actual_tree = tree_digest.hexdigest()
    if actual_tree != PAYLOAD_TREE_SHA256:
        raise SystemExit(
            "SHA-256 da arvore do payload embutido divergiu: "
            f"esperado {PAYLOAD_TREE_SHA256}, obtido {actual_tree}"
        )


def verify(path: str) -> None:
    archive_path = Path(path)
    if archive_path.name != FINAL_ARCHIVE_NAME:
        raise SystemExit(f"Nome obrigatorio do ZIP final: {FINAL_ARCHIVE_NAME}")
    try:
        metadata = archive_path.lstat()
    except OSError as exc:
        raise SystemExit(f"Release ausente ou ilegivel: {archive_path}") from exc
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    file_attributes = getattr(metadata, "st_file_attributes", 0)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or bool(reparse_flag and file_attributes & reparse_flag)
    ):
        raise SystemExit("O release precisa ser um arquivo regular, nao um link.")
    if metadata.st_size > MAX_FINAL_ARCHIVE_SIZE:
        raise SystemExit("O arquivo ZIP excede o limite fisico do release.")

    with contextlib.ExitStack() as stack:
        try:
            archive_stream = stack.enter_context(archive_path.open("rb"))
        except OSError as exc:
            raise SystemExit(f"Release ausente ou ilegivel: {archive_path}") from exc
        opened = os.fstat(archive_stream.fileno())
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size > MAX_FINAL_ARCHIVE_SIZE
            or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
        ):
            raise SystemExit("O release mudou ou excede o limite antes da leitura.")
        archive = stack.enter_context(zipfile.ZipFile(archive_stream, "r"))
        infos = archive.infolist()
        if len(infos) != len(EXPECTED_FILES):
            raise SystemExit("O ZIP contem uma quantidade inesperada de membros.")
        names = [info.filename for info in infos]
        if not names or len(names) != len(set(names)):
            raise SystemExit("O ZIP esta vazio ou contem nomes duplicados.")
        if len(names) != len({name.casefold() for name in names}):
            raise SystemExit("O ZIP contem nomes duplicados por diferenca de caixa.")

        roots: set[str] = set()
        relative_names: set[str] = set()
        relative_casefolds: set[str] = set()
        members: dict[str, zipfile.ZipInfo] = {}
        total_uncompressed = 0
        total_compressed = 0
        for info in infos:
            name = info.filename
            pure = PurePosixPath(name)
            if (
                pure.is_absolute()
                or ".." in pure.parts
                or "\\" in name
                or ":" in name
                or len(pure.parts) < 2
            ):
                raise SystemExit(f"Caminho inseguro no release: {name}")
            roots.add(pure.parts[0])
            relative = PurePosixPath(*pure.parts[1:]).as_posix()
            folded_relative = relative.casefold()
            if folded_relative in relative_casefolds:
                raise SystemExit(f"Destino relativo duplicado no release: {relative}")
            relative_names.add(relative)
            relative_casefolds.add(folded_relative)
            members[relative] = info

            if info.flag_bits & 0x1:
                raise SystemExit(f"Membro criptografado proibido no release: {name}")
            if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                raise SystemExit(f"Compressao inesperada no release: {name}")
            if relative == PAYLOAD_ARCHIVE_NAME:
                if (
                    info.file_size != PAYLOAD_ARCHIVE_SIZE
                    or info.compress_size != PAYLOAD_ARCHIVE_SIZE
                    or info.compress_type != zipfile.ZIP_STORED
                ):
                    raise SystemExit(
                        "O payload precisa ter tamanho exato e usar ZIP_STORED."
                    )
            else:
                if (
                    info.file_size > MAX_MEMBER_SIZE
                    or info.compress_size > MAX_MEMBER_SIZE
                ):
                    raise SystemExit(f"Membro grande demais no release: {name}")
                total_uncompressed += info.file_size
                total_compressed += info.compress_size
                if (
                    total_uncompressed > MAX_TOTAL_UNCOMPRESSED
                    or total_compressed > MAX_TOTAL_COMPRESSED
                ):
                    raise SystemExit(
                        "O tamanho total declarado do release excede o limite."
                    )
            unix_mode = (info.external_attr >> 16) & 0xFFFF
            file_type = stat.S_IFMT(unix_mode)
            if info.is_dir() or file_type not in (0, stat.S_IFREG):
                raise SystemExit(f"Link/diretorio/arquivo especial proibido: {name}")
            if pure.suffix.casefold() in FORBIDDEN_SUFFIXES:
                raise SystemExit(f"Binario/script proibido no release: {name}")

        if len(roots) != 1:
            raise SystemExit("O ZIP precisa ter uma unica pasta raiz.")
        root = next(iter(roots))
        expected_root = f"ERPT-BR-{FINAL_VERSION}"
        if root != expected_root:
            raise SystemExit(f"Pasta raiz inesperada no release: {root!r}")
        if relative_names != EXPECTED_FILES:
            missing = sorted(EXPECTED_FILES - relative_names)
            extra = sorted(relative_names - EXPECTED_FILES)
            raise SystemExit(
                f"Allowlist do release divergente; ausentes={missing}, extras={extra}"
            )
        root_commands = sorted(
            relative
            for relative in relative_names
            if "/" not in relative
            and PurePosixPath(relative).suffix.casefold() == ".cmd"
        )
        if root_commands != ["ERPT-BR.cmd"]:
            raise SystemExit(
                "O release precisa expor somente ERPT-BR.cmd na pasta principal."
            )

        # Force decompression and CRC validation for every allowlisted member,
        # including documentation and the icon.  Keeping the bytes also avoids
        # parsing a different view if the archive is replaced during validation.
        try:
            member_bytes = {
                relative: archive.read(info)
                for relative, info in members.items()
                if relative != PAYLOAD_ARCHIVE_NAME
            }
        except (OSError, EOFError, RuntimeError, zipfile.BadZipFile, zlib.error) as exc:
            raise SystemExit(
                "Falha de integridade, descompressao ou CRC em membro do release."
            ) from exc

        _verify_nested_payload(archive, members[PAYLOAD_ARCHIVE_NAME])

        for relative in SOURCE_FILES:
            if PurePosixPath(relative).suffix.casefold() not in {".py", ".cmd"}:
                continue
            try:
                source = member_bytes[relative].decode("utf-8")
            except UnicodeDecodeError as exc:
                raise SystemExit(f"Fonte nao UTF-8 no release: {relative}") from exc
            folded_source = source.casefold()
            for pattern, label in FORBIDDEN_SOURCE_PATTERNS.items():
                if pattern in folded_source:
                    raise SystemExit(f"{label} encontrado em {relative}: {pattern}")

        for relative, expected in WHEEL_SHA256.items():
            actual = _sha256(member_bytes[relative])
            if actual != expected:
                raise SystemExit(
                    f"SHA-256 incorreto para {relative}: esperado {expected}, obtido {actual}"
                )

        one_click = member_bytes["ERPT-BR.cmd"].decode("utf-8")
        installer = member_bytes["interno/INSTALAR_AMBIENTE.cmd"].decode("utf-8")
        launcher = member_bytes["interno/ABRIR_INTERFACE.cmd"].decode("utf-8")
        required_installer_controls = (
            'for %%I in ("%~dp0..") do set "ERPT_PACKAGE_ROOT=%%~fI\\"',
            '"%ERPT_PY%" %ERPT_PY_SWITCH% -I -S -c',
            '"%ERPT_PY%" %ERPT_PY_SWITCH% -I -S -m venv --clear --copies',
            "sys.implementation.name == 'cpython'",
            "sys.version_info[:2] == (3,13)",
            "sys.version_info[2] >= 15",
            "sys.version_info.releaselevel == 'final'",
            "%LOCALAPPDATA%\\Programs\\Python\\Launcher\\py.exe",
            "%SystemRoot%\\py.exe",
            "%LOCALAPPDATA%\\Programs\\Python\\Python313\\python.exe",
            "%ERPT_PACKAGE_ROOT%wheelhouse",
            "%ERPT_PACKAGE_ROOT%patcher\\requirements-win64.lock",
            'Scripts\\python.exe" -I -S -c',
            "sys.prefix=sys.exec_prefix=sys.argv[1]",
            "runpy.run_module('pip',run_name='__main__')",
            "--no-index",
            "--require-hashes",
            "--only-binary=:all:",
        )
        missing_controls = [
            item for item in required_installer_controls if item not in installer
        ]
        if missing_controls:
            raise SystemExit(
                f"Controles obrigatorios ausentes do instalador: {missing_controls}"
            )
        if 'Scripts\\pythonw.exe" -I -S -c' not in launcher:
            raise SystemExit(
                "O launcher nao inicia o Python sem processamento automatico de site."
            )
        if (
            "%LOCALAPPDATA%\\Programs\\Python\\Launcher\\py.exe" not in launcher
            or "%LOCALAPPDATA%\\Programs\\Python\\Python313\\python.exe"
            not in launcher
            or '"%ERPT_PY%" %ERPT_PY_SWITCH% -I -S -c' not in launcher
            or "sys.version_info[:2] != (3,13)" not in launcher
            or "sys.version_info[2] < 15" not in launcher
            or '"%ERPT_VENV%\\Scripts\\python.exe" -I -S -c' not in launcher
            or launcher.count("sys.version_info[:2] == (3,13)") < 3
            or 'call "%~dp0INSTALAR_AMBIENTE.cmd"' not in launcher
            or "if defined ERPTBR_INSTALL_ONLY exit /b 0" not in launcher
            or "import tkinter,customtkinter; from Crypto.Cipher import AES"
            not in launcher
            or "if defined ERPTBR_REPAIR_ATTEMPTED" not in launcher
            or "if not defined ERPTBR_INTERNAL_CALL" not in launcher
            or "if not defined ERPTBR_INTERNAL_CALL" not in installer
            or 'for %%I in ("%~dp0..") do set "ERPT_PACKAGE_ROOT=%%~fI\\"'
            not in launcher
        ):
            raise SystemExit(
                "O launcher nao valida a compatibilidade do Python e do venv."
            )

        required_one_click_controls = (
            "%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "%LOCALAPPDATA%\\Microsoft\\WindowsApps\\winget.exe",
            "%SystemRoot%\\System32\\curl.exe",
            'for /f "delims=" %%G in (\'%ERPT_POWERSHELL%',
            "https://www.python.org/ftp/python/3.13.15/python-3.13.15-amd64.exe",
            "29452944",
            "EDEC09C4853AEAE9AC36EFB8C9F95B6B8E2FEE65EEE56D9767A8B7C69C574403",
            "CN=Python Software Foundation, O=Python Software Foundation, L=Beaverton, S=Oregon, C=US",
            "Microsoft.PowerShell.Utility\\Get-FileHash",
            "Microsoft.PowerShell.Security\\Get-AuthenticodeSignature -LiteralPath",
            "Modules\\Microsoft.PowerShell.Utility\\Microsoft.PowerShell.Utility.psd1",
            "Modules\\Microsoft.PowerShell.Security\\Microsoft.PowerShell.Security.psd1",
            "[IO.FileStream]::new",
            "[IO.FileOptions]::DeleteOnClose",
            "--exact --id Python.Python.3.13 --version 3.13.15 --source winget",
            "--scope user --architecture x64 --silent --disable-interactivity",
            "InstallAllUsers=0",
            "InstallLauncherAllUsers=0",
            "Include_freethreaded=0",
            "PrependPath=0",
            "AppendPath=0",
            'if not exist "%ERPT_WINGET%" goto :install_direct',
            "interno\\INSTALAR_AMBIENTE.cmd",
            "interno\\ABRIR_INTERFACE.cmd",
            "patcher\\bnk.py",
            "patcher\\diagnostics.py",
            'call "%~dp0interno\\ABRIR_INTERFACE.cmd"',
            "if defined ERPTBR_INSTALL_ONLY goto :success_install_only",
            "Local\\ERPTBR_Installer_",
            'set "ERPTBR_INTERNAL_CALL=1"',
            ":invalid_package",
        )
        missing_one_click = [
            item for item in required_one_click_controls if item not in one_click
        ]
        if missing_one_click:
            raise SystemExit(
                "Controles obrigatorios ausentes da instalacao de um clique: "
                f"{missing_one_click}"
            )
        if one_click.count("goto :install_direct") != 1:
            raise SystemExit(
                "O fallback direto so pode ser alcancado quando o WinGet esta ausente."
            )
        for relative, expected in WHEEL_SHA256.items():
            bootstrap_relative = relative.replace("/", "\\")
            if bootstrap_relative not in one_click or expected not in one_click:
                raise SystemExit(
                    f"Preflight do bootstrap nao fixa nome/hash de {relative}."
                )
        preflight_order = (
            one_click.find("rem Recusa ZIP automatico"),
            one_click.find("call :find_python"),
            one_click.find('"%ERPT_WINGET%" install'),
        )
        if not (
            -1 not in preflight_order
            and preflight_order[0] < preflight_order[1] < preflight_order[2]
        ):
            raise SystemExit(
                "O pacote precisa ser autenticado antes de instalar o Python."
            )
        authentication_order = (
            one_click.find(
                "$hash=(Microsoft.PowerShell.Utility\\Get-FileHash -LiteralPath $path"
            ),
            one_click.find(
                "$signature=Microsoft.PowerShell.Security\\Get-AuthenticodeSignature "
                "-LiteralPath $path"
            ),
            one_click.find("$process=Start-Process -FilePath $path"),
        )
        if not (
            -1 not in authentication_order
            and authentication_order[0]
            < authentication_order[1]
            < authentication_order[2]
        ):
            raise SystemExit(
                "Hash e assinatura precisam anteceder a execucao do instalador oficial."
            )

        version = FINAL_VERSION.removeprefix("v")
        init_source = member_bytes["patcher/__init__.py"].decode("utf-8")
        gui_source = member_bytes["patcher/patcher_gui.py"].decode("utf-8")
        if f'__version__ = "{version}"' not in init_source or (
            f'PATCHER_VERSION = "{version}"' not in gui_source
        ):
            raise SystemExit("Versao da pasta raiz diverge do codigo empacotado.")
        _verify_gui_controls(gui_source)
        lock_source = member_bytes["patcher/requirements-win64.lock"].decode("utf-8")
        for expected in WHEEL_SHA256.values():
            if f"--hash=sha256:{expected}" not in lock_source:
                raise SystemExit(
                    f"Hash de wheel ausente do requirements-win64.lock: {expected}"
                )

        try:
            final_opened = os.fstat(archive_stream.fileno())
            current = archive_path.lstat()
        except OSError as exc:
            raise SystemExit("O release mudou durante a validacao.") from exc
        current_attributes = getattr(current, "st_file_attributes", 0)
        if (
            not stat.S_ISREG(final_opened.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or final_opened.st_nlink != 1
            or current.st_nlink != 1
            or final_opened.st_size != metadata.st_size
            or current.st_size != metadata.st_size
            or (final_opened.st_dev, final_opened.st_ino)
            != (metadata.st_dev, metadata.st_ino)
            or (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino)
            or stat.S_ISLNK(current.st_mode)
            or bool(reparse_flag and current_attributes & reparse_flag)
        ):
            raise SystemExit("O release mudou durante a validacao.")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive")
    args = parser.parse_args()
    verify(args.archive)
    print("ZIP final verificado: fontes, wheels e payload aninhado autenticados.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
