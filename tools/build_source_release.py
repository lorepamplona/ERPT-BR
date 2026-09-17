#!/usr/bin/env python3
"""Monta o unico ZIP de distribuicao do ERPT-BR para Windows."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import struct
import unicodedata
import uuid
import zipfile
from pathlib import Path, PurePosixPath
from typing import Sequence


SOURCE_FILES = (
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
)

WHEELS = {
    "customtkinter-5.2.2-py3-none-any.whl": "14ad3e7cd3cb3b9eb642b9d4e8711ae80d3f79fb82545ad11258eeffb2e6b37c",
    "darkdetect-0.8.0-py3-none-any.whl": "a7509ccf517eaad92b31c214f593dbcf138ea8a43b2935406bbd565e15527a85",
    "packaging-26.3-py3-none-any.whl": "d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c",
    "pycryptodome-3.23.0-cp37-abi3-win_amd64.whl": "c75b52aacc6c0c260f204cbdd834f76edc9fb0d8e0da9fbf8352ef58202564e2",
}

FINAL_VERSION = "v0.9.5"
FINAL_ARCHIVE_NAME = "ERPT-BR-v0.9.5-Windows.zip"
# The reviewed payload ZIP remains an authenticated build input only.
# Its members are inflated and written directly below patch_data/ in v0.9.5;
# this archive is never copied into the user-facing release.
PAYLOAD_ARCHIVE_SIZE = 588_468_447
PAYLOAD_SHA256 = "430e9693a9b3313826e9f7c890cf592eb5b468d145bb405e8a4586002b877680"
PAYLOAD_TREE_SHA256 = "8544e551832c929eecad0cf9898204fd673bd4a37a0a6f37433865afbb3556cb"
PAYLOAD_FILE_COUNT = 9_241
PAYLOAD_WEM_COUNT = 8_969
PAYLOAD_BNK_COUNT = 272
PAYLOAD_UNCOMPRESSED_SIZE = 605_706_607
PAYLOAD_MAX_FILE_SIZE = 74_956_066
COPY_CHUNK_SIZE = 1024 * 1024
ARCHIVE_TIMESTAMP = (2020, 1, 1, 0, 0, 0)
TEXT_SUFFIXES = frozenset({".cmd", ".lock", ".md", ".py"})


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(COPY_CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def zip_info(
    name: str, *, compression: int = zipfile.ZIP_DEFLATED
) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=ARCHIVE_TIMESTAMP)
    info.compress_type = compression
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    return info


def require_regular_file(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise SystemExit(
            f"Arquivo obrigatorio ausente ou ilegivel: {path}: {exc}"
        ) from exc
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    file_attributes = getattr(metadata, "st_file_attributes", 0)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or bool(reparse_flag and file_attributes & reparse_flag)
    ):
        raise SystemExit(f"Arquivo obrigatorio nao e regular: {path}")


def validate_payload(path: Path) -> tuple[int, int]:
    """Authenticate the immutable payload without ever loading it into memory."""

    require_regular_file(path)
    before = path.lstat()
    if before.st_nlink != 1:
        raise SystemExit(f"Payload precisa ser um arquivo regular exclusivo: {path}")
    if before.st_size != PAYLOAD_ARCHIVE_SIZE:
        raise SystemExit(
            "Tamanho incorreto do payload: "
            f"esperado {PAYLOAD_ARCHIVE_SIZE}, obtido {before.st_size}"
        )
    actual = sha256(path)
    after = path.lstat()
    if (
        (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
        or after.st_nlink != 1
        or after.st_size != before.st_size
    ):
        raise SystemExit("O payload mudou durante a validacao.")
    if actual != PAYLOAD_SHA256:
        raise SystemExit(
            f"SHA-256 incorreto do payload: esperado {PAYLOAD_SHA256}, obtido {actual}"
        )
    return before.st_dev, before.st_ino


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
        or unicodedata.normalize("NFC", relative) != relative
        or any(part.endswith((" ", ".")) for part in parts)
        or path.suffix.casefold() not in {".wem", ".bnk"}
    ):
        raise SystemExit(f"Caminho inseguro no payload: {name!r}")
    return relative


def _validated_payload_entries(
    infos: list[zipfile.ZipInfo],
) -> list[tuple[str, zipfile.ZipInfo]]:
    if len(infos) != PAYLOAD_FILE_COUNT:
        raise SystemExit(
            "Quantidade de arquivos divergente no payload de entrada: "
            f"esperado {PAYLOAD_FILE_COUNT}, obtido {len(infos)}"
        )

    normalized: list[tuple[str, zipfile.ZipInfo]] = []
    seen: set[str] = set()
    wem_count = 0
    bnk_count = 0
    total_size = 0
    max_file_size = 0
    for info in infos:
        relative = _safe_payload_relative(info.filename)
        canonical = unicodedata.normalize("NFC", relative).casefold()
        if canonical in seen:
            raise SystemExit(f"Nome duplicado no payload de entrada: {relative!r}")
        seen.add(canonical)
        unix_mode = (info.external_attr >> 16) & 0xFFFF
        if (
            info.is_dir()
            or stat.S_IFMT(unix_mode) not in (0, stat.S_IFREG)
            or info.flag_bits & 0x1
            or info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
            or info.file_size < 0
            or info.file_size > PAYLOAD_MAX_FILE_SIZE
            or info.compress_size < 0
            or info.compress_size > PAYLOAD_ARCHIVE_SIZE
        ):
            raise SystemExit(
                f"Membro inseguro no payload de entrada: {info.filename!r}"
            )
        total_size += info.file_size
        if total_size > PAYLOAD_UNCOMPRESSED_SIZE:
            raise SystemExit("O payload de entrada excede o tamanho autenticado.")
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
        raise SystemExit("As entradas do payload estao fora da ordem canonica.")
    if (
        wem_count != PAYLOAD_WEM_COUNT
        or bnk_count != PAYLOAD_BNK_COUNT
        or total_size != PAYLOAD_UNCOMPRESSED_SIZE
        or max_file_size != PAYLOAD_MAX_FILE_SIZE
    ):
        raise SystemExit(
            "Estatisticas divergentes no payload de entrada: "
            f"WEM={wem_count}, BNK={bnk_count}, bytes={total_size}, "
            f"maior={max_file_size}"
        )
    return normalized


def write_payload_members(
    archive: zipfile.ZipFile,
    *,
    payload: Path,
    package_root: str,
    expected_identity: tuple[int, int],
) -> None:
    """Stream the authenticated payload tree directly into the final ZIP."""

    tree_digest = hashlib.sha256()
    try:
        source = payload.open("rb")
    except OSError as exc:
        raise SystemExit(f"Payload ausente ou ilegivel: {payload}") from exc
    try:
        opened = os.fstat(source.fileno())
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size != PAYLOAD_ARCHIVE_SIZE
            or (opened.st_dev, opened.st_ino) != expected_identity
        ):
            raise SystemExit("O payload mudou antes do empacotamento.")

        try:
            with zipfile.ZipFile(source, "r") as source_archive:
                if source_archive.comment:
                    raise SystemExit(
                        "O payload de entrada contem comentario inesperado."
                    )
                entries = _validated_payload_entries(source_archive.infolist())
                for relative, info in entries:
                    encoded = relative.encode("utf-8")
                    tree_digest.update(struct.pack("<I", len(encoded)))
                    tree_digest.update(encoded)
                    tree_digest.update(struct.pack("<Q", info.file_size))
                    written = 0
                    header = bytearray()
                    target_info = zip_info(
                        f"{package_root}/patch_data/{relative}",
                        compression=zipfile.ZIP_DEFLATED,
                    )
                    target_info.file_size = info.file_size
                    with source_archive.open(info, "r") as input_member, archive.open(
                        target_info, "w"
                    ) as output_member:
                        while chunk := input_member.read(COPY_CHUNK_SIZE):
                            output_member.write(chunk)
                            tree_digest.update(chunk)
                            written += len(chunk)
                            if len(header) < 12:
                                header.extend(chunk[: 12 - len(header)])
                    if written != info.file_size:
                        raise SystemExit(
                            f"Leitura incompleta no payload: {relative!r}"
                        )
                    if relative.casefold().endswith(".wem"):
                        valid_header = (
                            len(header) >= 12
                            and header[:4] == b"RIFF"
                            and header[8:12] == b"WAVE"
                        )
                    else:
                        valid_header = len(header) >= 4 and header[:4] == b"BKHD"
                    if not valid_header:
                        raise SystemExit(
                            f"Cabecalho de audio invalido no payload: {relative!r}"
                        )
        except SystemExit:
            raise
        except (OSError, EOFError, RuntimeError, zipfile.BadZipFile) as exc:
            raise SystemExit(
                "Falha de integridade, CRC ou descompactacao no payload de entrada."
            ) from exc
        opened_after = os.fstat(source.fileno())
    finally:
        source.close()
    try:
        current = payload.lstat()
    except OSError as exc:
        raise SystemExit("O payload mudou durante o empacotamento.") from exc
    if (
        tree_digest.hexdigest() != PAYLOAD_TREE_SHA256
        or not stat.S_ISREG(opened_after.st_mode)
        or opened_after.st_nlink != 1
        or opened_after.st_size != PAYLOAD_ARCHIVE_SIZE
        or not stat.S_ISREG(current.st_mode)
        or current.st_nlink != 1
        or current.st_size != PAYLOAD_ARCHIVE_SIZE
        or (opened_after.st_dev, opened_after.st_ino) != expected_identity
        or (current.st_dev, current.st_ino) != expected_identity
    ):
        raise SystemExit("O payload mudou durante o empacotamento.")


def release_bytes(path: Path) -> bytes:
    """Return checkout-independent bytes for the Windows source package."""

    data = path.read_bytes()
    suffix = path.suffix.casefold()
    if suffix not in TEXT_SUFFIXES and path.name.casefold() != "license":
        return data
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit(f"Arquivo de texto nao UTF-8: {path}") from exc
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    if suffix == ".cmd":
        normalized = normalized.replace("\n", "\r\n")
    return normalized.encode("utf-8")


def build(
    root: Path,
    wheelhouse: Path,
    payload: Path,
    output: Path,
    version: str,
) -> None:
    if not re.fullmatch(r"v\d+\.\d+\.\d+", version):
        raise SystemExit(f"Versao invalida: {version!r}")
    if version != FINAL_VERSION:
        raise SystemExit(
            f"Este empacotador final esta fixado em {FINAL_VERSION}, nao {version}."
        )
    if output.name != FINAL_ARCHIVE_NAME:
        raise SystemExit(
            f"Nome obrigatorio do ZIP final: {FINAL_ARCHIVE_NAME}"
        )
    plain_version = version.removeprefix("v")
    init_source = (root / "patcher/__init__.py").read_text(encoding="utf-8")
    gui_source = (root / "patcher/patcher_gui.py").read_text(encoding="utf-8")
    init_match = re.search(r'^__version__\s*=\s*"([^"]+)"', init_source, re.MULTILINE)
    gui_match = re.search(r'^PATCHER_VERSION\s*=\s*"([^"]+)"', gui_source, re.MULTILINE)
    if (
        not init_match
        or not gui_match
        or {init_match.group(1), gui_match.group(1)} != {plain_version}
    ):
        raise SystemExit(
            "A tag, patcher.__version__ e PATCHER_VERSION precisam coincidir."
        )
    for command_file in (
        "interno/INSTALAR_AMBIENTE.cmd",
        "interno/ABRIR_INTERFACE.cmd",
    ):
        content = (root / command_file).read_text(encoding="utf-8")
        if f"venv-{plain_version}" not in content:
            raise SystemExit(f"Versao do ambiente desatualizada em {command_file}.")
    package_root = f"ERPT-BR-{version}"
    members: list[tuple[str, bytes]] = []
    for relative in SOURCE_FILES:
        source = root / relative
        require_regular_file(source)
        members.append((f"{package_root}/{relative}", release_bytes(source)))

    actual_wheels = {item.name for item in wheelhouse.glob("*.whl")}
    if actual_wheels != set(WHEELS):
        missing = sorted(set(WHEELS) - actual_wheels)
        extra = sorted(actual_wheels - set(WHEELS))
        raise SystemExit(f"Wheelhouse divergente; ausentes={missing}, extras={extra}")
    for name, expected in WHEELS.items():
        wheel = wheelhouse / name
        require_regular_file(wheel)
        actual = sha256(wheel)
        if actual != expected:
            raise SystemExit(f"SHA-256 incorreto para {name}: {actual}")
        members.append((f"{package_root}/wheelhouse/{name}", wheel.read_bytes()))

    payload_identity = validate_payload(payload)
    output.parent.mkdir(parents=True, exist_ok=True)
    if os.path.lexists(output):
        raise SystemExit(f"O artefato de saida ja existe e foi preservado: {output}")
    temporary = output.with_name(f".{output.name}.{uuid.uuid4().hex}.tmp")
    temporary_identity: tuple[int, int] | None = None
    try:
        with zipfile.ZipFile(
            temporary,
            "x",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
            allowZip64=True,
        ) as archive:
            metadata = temporary.lstat()
            temporary_identity = (metadata.st_dev, metadata.st_ino)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise SystemExit(f"Scratch de release inseguro: {temporary}")
            for name, data in sorted(members):
                if name.casefold().endswith(".exe"):
                    raise SystemExit(f"Executavel proibido no release: {name}")
                archive.writestr(zip_info(name), data)
            write_payload_members(
                archive,
                payload=payload,
                package_root=package_root,
                expected_identity=payload_identity,
            )
        if os.path.lexists(output):
            raise SystemExit(
                f"O artefato de saida apareceu durante o build e foi preservado: {output}"
            )
        os.rename(temporary, output)
    finally:
        try:
            metadata = temporary.lstat()
            if (
                temporary_identity is not None
                and stat.S_ISREG(metadata.st_mode)
                and metadata.st_nlink == 1
                and (metadata.st_dev, metadata.st_ino) == temporary_identity
            ):
                temporary.unlink()
        except (FileNotFoundError, IsADirectoryError, PermissionError, OSError):
            pass


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument(
        "--payload",
        type=Path,
        required=True,
        help=(
            "ZIP de audio autenticado usado somente como entrada; os WEM/BNK "
            "serao gravados diretamente em patch_data/"
        ),
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    build(
        args.root.resolve(),
        args.wheelhouse.resolve(),
        args.payload.absolute(),
        args.output.resolve(),
        args.version,
    )
    print(f"Criado: {args.output} ({sha256(args.output)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
