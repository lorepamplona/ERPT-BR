#!/usr/bin/env python3
"""Build a deterministic, data-only ERPT-BR payload candidate.

The candidate combines the WEM files from an already authenticated historical
``patch_data`` tree with BNKs produced by ``rebuild_bnk_payload.py``.  It never
opens game archives and it refuses to overwrite any output.  The resulting
bundle contains:

* ``patch_data/``: the fully validated extracted tree plus its cache marker;
* the deterministic ZIP consumed by :mod:`patcher.patch_data`;
* a provenance manifest with a SHA-256 for every payload file; and
* a short human-readable report.

No production constant is changed by this tool.  The emitted ``PayloadSpec``
must be reviewed and deliberately promoted in a later change.
"""

from __future__ import annotations

import argparse
import ctypes
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import struct
import sys
from typing import Iterable, Mapping, Sequence
import unicodedata
import uuid
import zipfile
import zlib


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from patcher import patch_data  # noqa: E402


BUNDLE_SCHEMA = 1
REBUILD_SCHEMA = 1
REBUILD_ALGORITHM = "vanilla-authoritative-wwise135-v2"
EXPECTED_WEM_COUNT = 8_969
EXPECTED_BNK_COUNT = 272
EXPECTED_PHYSICAL_BANK_COUNT = 136
EXPECTED_BUILD_ID = "25080141"
EXPECTED_GAME_VERSION = "1.17.1"
EXPECTED_CHANGED_SOUND_OBJECTS = 1_010
EXPECTED_FILTERED_SOUND_OBJECTS = 216
EXPECTED_CHANGED_SOUND_IDS_SHA256 = (
    "0d0472d678ebbc7db72baa27f850678af077746f22361bd0c9101cc9d7647f3c"
)
EXPECTED_FILTERED_SOUND_IDS_SHA256 = (
    "f0cb9b857ccef7749f0a2b8bcf768399ceafcd7261ccd1e048b8df546497e292"
)
EXPECTED_VCMAIN_FILTERED_IDS_SHA256 = (
    "3d71be4e357b09d33870b8e1f1389067d152bcd8bdfde055d4b40f9fa673c7d3"
)
EXPECTED_REBUILD_MANIFEST_SHA256 = (
    "211697c3d5af07e40bbc4f9cce091cfd5769c3865d31ee6a7a5ae9bfca370111"
)
EXPECTED_REBUILT_BANKS_SHA256 = (
    "77d9276e641169274233147d95a325a6413ffb3495105df73be857fa7ed27636"
)
EXPECTED_REBUILT_ALIAS_TREE_SHA256 = (
    "1d05c510d6c900fa90a7b46c8e300f47d3a99eff70f32f5bf42d67b1fd5dc120"
)
DEFAULT_VERSION = "v0.9.4-rc.1"
DEFAULT_ARCHIVE_NAME = "patch_data_v094_rc1_wwise135_v2.zip"
DEFAULT_URL = (
    "https://github.com/lorepamplona/ERPT-BR/releases/download/"
    "v0.9.4-rc.1/patch_data_v094_rc1_wwise135_v2.zip"
)
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
COPY_BUFFER_SIZE = 8 * 1024 * 1024
ZIP_COMPRESSION_LEVEL = 9
MAX_JSON_SIZE = 16 * 1024 * 1024
WINDOWS_RESERVED_NAMES = {
    "aux",
    "con",
    "nul",
    "prn",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}


class CandidateBuildError(RuntimeError):
    """A fail-closed candidate packaging error."""


@dataclass(frozen=True)
class FileSnapshot:
    device: int
    inode: int
    size: int
    mtime_ns: int
    ctime_ns: int
    handle_ctime_ns: int


@dataclass(frozen=True)
class DirectorySnapshot:
    path: Path
    device: int
    inode: int


@dataclass(frozen=True)
class CandidateFile:
    relative: str
    source: Path
    role: str
    size: int
    sha256: str
    snapshot: FileSnapshot


@dataclass(frozen=True)
class BundleDirectorySnapshot:
    relative: str
    device: int
    inode: int


@dataclass(frozen=True)
class BundleFileSnapshot:
    relative: str
    sha256: str
    snapshot: FileSnapshot


@dataclass(frozen=True)
class BundleSnapshot:
    directories: tuple[BundleDirectorySnapshot, ...]
    files: tuple[BundleFileSnapshot, ...]


def _is_reparse(metadata: os.stat_result) -> bool:
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(metadata, "st_file_attributes", 0)
    return bool(flag and attributes & flag)


def _snapshot_regular(path: Path, *, label: str) -> FileSnapshot:
    try:
        before = path.lstat()
    except OSError as exc:
        raise CandidateBuildError(f"{label} ausente ou ilegível: {path}: {exc}") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or _is_reparse(before)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
    ):
        raise CandidateBuildError(
            f"{label} precisa ser arquivo regular exclusivo, sem link/reparse: {path}"
        )
    # On Windows metadata from a freshly closed writer can settle on the next
    # handle open.  Pin the identity through that handle and then require the
    # path to still resolve to exactly the same settled object.
    try:
        with path.open("rb") as stream:
            metadata = os.fstat(stream.fileno())
    except OSError as exc:
        raise CandidateBuildError(f"{label} não pôde ser aberto: {path}: {exc}") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or _is_reparse(metadata)
        or metadata.st_nlink != 1
        or (metadata.st_dev, metadata.st_ino) != (before.st_dev, before.st_ino)
    ):
        raise CandidateBuildError(f"{label} foi trocado ao abrir: {path}")
    try:
        after = path.lstat()
    except OSError as exc:
        raise CandidateBuildError(f"{label} mudou após a abertura: {path}: {exc}") from exc
    if (
        stat.S_ISLNK(after.st_mode)
        or _is_reparse(after)
        or not stat.S_ISREG(after.st_mode)
        or after.st_nlink != 1
        or (after.st_dev, after.st_ino) != (metadata.st_dev, metadata.st_ino)
        or after.st_size != metadata.st_size
        or after.st_mtime_ns != metadata.st_mtime_ns
        or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    ):
        raise CandidateBuildError(f"{label} mudou durante a inspeção: {path}")
    return FileSnapshot(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        size=metadata.st_size,
        mtime_ns=metadata.st_mtime_ns,
        ctime_ns=after.st_ctime_ns,
        handle_ctime_ns=metadata.st_ctime_ns,
    )


def _assert_snapshot(path: Path, expected: FileSnapshot, *, label: str) -> None:
    if _snapshot_regular(path, label=label) != expected:
        raise CandidateBuildError(f"{label} mudou durante o empacotamento: {path}")


def _absolute_path(path: Path) -> Path:
    """Return a lexical absolute path without following a link/reparse point."""

    return Path(os.path.abspath(os.fspath(path)))


def _snapshot_directory(path: Path, *, label: str) -> DirectorySnapshot:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CandidateBuildError(f"{label} ausente ou ilegível: {path}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata) or not stat.S_ISDIR(
        metadata.st_mode
    ):
        raise CandidateBuildError(
            f"{label} precisa ser diretório real, sem link/reparse: {path}"
        )
    return DirectorySnapshot(path, metadata.st_dev, metadata.st_ino)


def _assert_directory_snapshot(snapshot: DirectorySnapshot, *, label: str) -> None:
    current = _snapshot_directory(snapshot.path, label=label)
    if (current.device, current.inode) != (snapshot.device, snapshot.inode):
        raise CandidateBuildError(f"{label} foi trocado: {snapshot.path}")


def _directory_components(path: Path) -> tuple[Path, ...]:
    absolute = _absolute_path(path)
    return tuple((*reversed(absolute.parents), absolute))


def _safe_directory_chain(
    path: Path,
    *,
    label: str,
    create: bool = False,
) -> tuple[DirectorySnapshot, ...]:
    """Validate every ancestor without resolving through links.

    Missing components may be created one at a time.  Each component is then
    identity-pinned so a later swap is detected before publication.
    """

    snapshots: list[DirectorySnapshot] = []
    for component in _directory_components(path):
        try:
            snapshot = _snapshot_directory(component, label=label)
        except CandidateBuildError:
            if not create or os.path.lexists(component):
                raise
            try:
                component.mkdir()
            except FileExistsError:
                pass
            except OSError as exc:
                raise CandidateBuildError(
                    f"Falha ao criar {label}: {component}: {exc}"
                ) from exc
            snapshot = _snapshot_directory(component, label=label)
        snapshots.append(snapshot)
    _assert_directory_chain(tuple(snapshots), label=label)
    return tuple(snapshots)


def _assert_directory_chain(
    snapshots: Sequence[DirectorySnapshot], *, label: str
) -> None:
    for snapshot in snapshots:
        _assert_directory_snapshot(snapshot, label=label)


def _assert_open_snapshot(
    metadata: os.stat_result,
    expected: FileSnapshot,
    *,
    label: str,
) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or _is_reparse(metadata)
        or metadata.st_nlink != 1
        or metadata.st_dev != expected.device
        or metadata.st_ino != expected.inode
        or metadata.st_size != expected.size
        or metadata.st_mtime_ns != expected.mtime_ns
        or metadata.st_ctime_ns != expected.handle_ctime_ns
    ):
        raise CandidateBuildError(f"{label} mudou durante o empacotamento")


def _hash_regular(
    path: Path,
    *,
    label: str,
    expected: FileSnapshot | None = None,
) -> tuple[str, FileSnapshot]:
    snapshot = expected or _snapshot_regular(path, label=label)
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            _assert_open_snapshot(opened, snapshot, label=f"{label} ao abrir")
            while chunk := stream.read(COPY_BUFFER_SIZE):
                digest.update(chunk)
            after = os.fstat(stream.fileno())
    except OSError as exc:
        raise CandidateBuildError(f"Falha ao ler {label}: {path}: {exc}") from exc
    _assert_open_snapshot(after, snapshot, label=f"{label} durante o hash")
    _assert_snapshot(path, snapshot, label=label)
    return digest.hexdigest(), snapshot


def _read_json_regular(path: Path, *, label: str) -> tuple[dict, str]:
    snapshot = _snapshot_regular(path, label=label)
    if snapshot.size > MAX_JSON_SIZE:
        raise CandidateBuildError(
            f"{label} excede o limite de {MAX_JSON_SIZE} bytes: {path}"
        )
    digest = hashlib.sha256()
    data = bytearray()
    try:
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            _assert_open_snapshot(opened, snapshot, label=f"{label} ao abrir")
            while chunk := stream.read(COPY_BUFFER_SIZE):
                data.extend(chunk)
                digest.update(chunk)
            after = os.fstat(stream.fileno())
    except OSError as exc:
        raise CandidateBuildError(f"Falha ao ler {label}: {path}: {exc}") from exc
    _assert_open_snapshot(after, snapshot, label=f"{label} durante a leitura")
    _assert_snapshot(path, snapshot, label=label)
    try:
        document = json.loads(bytes(data).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateBuildError(f"{label} não é JSON UTF-8 válido: {path}") from exc
    if not isinstance(document, dict):
        raise CandidateBuildError(f"{label} precisa conter um objeto JSON: {path}")
    return document, digest.hexdigest()


def _validate_historical_marker(historical_payload: Path) -> str:
    marker_path = historical_payload / patch_data.MARKER_FILENAME
    marker, marker_sha256 = _read_json_regular(
        marker_path, label="Marker do payload histórico"
    )
    expected = _marker_data(patch_data.PRODUCTION_PAYLOAD)
    if marker != expected:
        raise CandidateBuildError(
            "O marker do payload histórico não corresponde exatamente ao "
            "PayloadSpec v0.8.1 fixado."
        )
    return marker_sha256


def _safe_relative(relative: str) -> str:
    if not relative or "\\" in relative or ":" in relative or "\x00" in relative:
        raise CandidateBuildError(f"Caminho de payload inseguro: {relative!r}")
    raw_parts = relative.split("/")
    path = PurePosixPath(*raw_parts)
    if (
        path.is_absolute()
        or any(part in {"", ".", ".."} for part in raw_parts)
        or path.as_posix() != relative
        or any(
            part.endswith((" ", "."))
            or any(ord(character) < 32 for character in part)
            or part.split(".", 1)[0].casefold() in WINDOWS_RESERVED_NAMES
            for part in raw_parts
        )
    ):
        raise CandidateBuildError(f"Caminho de payload inseguro: {relative!r}")
    if path.suffix.casefold() not in {".wem", ".bnk"}:
        raise CandidateBuildError(f"Extensão de payload inesperada: {relative!r}")
    return path.as_posix()


def _safe_archive_name(name: str) -> str:
    if (
        not name
        or "/" in name
        or "\\" in name
        or ":" in name
        or "\x00" in name
        or name in {".", ".."}
        or name.endswith((" ", "."))
        or any(ord(character) < 32 for character in name)
        or name.split(".", 1)[0].casefold() in WINDOWS_RESERVED_NAMES
        or not name.casefold().endswith(".zip")
    ):
        raise CandidateBuildError(
            "--archive-name precisa ser um nome .zip simples e seguro."
        )
    return name


def _canonical_relative(relative: str) -> str:
    return unicodedata.normalize("NFC", relative).casefold()


def _safe_bundle_relative(relative: str) -> str:
    """Validate a non-empty generic path inside a candidate bundle."""

    if not relative or "\\" in relative or ":" in relative or "\x00" in relative:
        raise CandidateBuildError(f"Caminho de bundle inseguro: {relative!r}")
    raw_parts = relative.split("/")
    path = PurePosixPath(*raw_parts)
    if (
        path.is_absolute()
        or any(part in {"", ".", ".."} for part in raw_parts)
        or path.as_posix() != relative
        or any(
            part.endswith((" ", "."))
            or any(ord(character) < 32 for character in part)
            or part.split(".", 1)[0].casefold() in WINDOWS_RESERVED_NAMES
            for part in raw_parts
        )
    ):
        raise CandidateBuildError(f"Caminho de bundle inseguro: {relative!r}")
    return path.as_posix()


def _bundle_inventory(
    root: Path, *, label: str
) -> tuple[tuple[BundleDirectorySnapshot, ...], tuple[tuple[str, Path, FileSnapshot], ...]]:
    """Return an exact, identity-pinned inventory without following links."""

    root = _absolute_path(root)
    _snapshot_directory(root, label=label)
    directories: list[BundleDirectorySnapshot] = []
    files: list[tuple[str, Path, FileSnapshot]] = []
    seen_entries: set[str] = set()

    def walk_error(error: OSError) -> None:
        raise CandidateBuildError(f"Falha ao percorrer {label}: {root}: {error}")

    try:
        for current_root, directory_names, file_names in os.walk(
            root, topdown=True, onerror=walk_error, followlinks=False
        ):
            current = Path(current_root)
            try:
                current_relative_path = current.relative_to(root)
            except ValueError as exc:
                raise CandidateBuildError(
                    f"Diretório fora de {label}: {current}"
                ) from exc
            current_relative = (
                ""
                if not current_relative_path.parts
                else _safe_bundle_relative(current_relative_path.as_posix())
            )
            current_snapshot = _snapshot_directory(current, label=label)
            directories.append(
                BundleDirectorySnapshot(
                    relative=current_relative,
                    device=current_snapshot.device,
                    inode=current_snapshot.inode,
                )
            )

            directory_names.sort(key=lambda name: (name.casefold(), name))
            file_names.sort(key=lambda name: (name.casefold(), name))
            for name in directory_names:
                path = current / name
                _snapshot_directory(path, label=label)
                relative = _safe_bundle_relative(path.relative_to(root).as_posix())
                canonical = _canonical_relative(relative)
                if canonical in seen_entries:
                    raise CandidateBuildError(
                        f"Entrada duplicada por caixa em {label}: {relative}"
                    )
                seen_entries.add(canonical)
            for name in file_names:
                path = current / name
                relative = _safe_bundle_relative(path.relative_to(root).as_posix())
                canonical = _canonical_relative(relative)
                if canonical in seen_entries:
                    raise CandidateBuildError(
                        f"Entrada duplicada por caixa em {label}: {relative}"
                    )
                seen_entries.add(canonical)
                files.append(
                    (
                        relative,
                        path,
                        _snapshot_regular(path, label=f"{label} {relative}"),
                    )
                )
    except CandidateBuildError:
        raise
    except OSError as exc:
        raise CandidateBuildError(f"Falha ao percorrer {label}: {root}: {exc}") from exc

    return (
        tuple(
            sorted(
                directories,
                key=lambda item: (_canonical_relative(item.relative), item.relative),
            )
        ),
        tuple(
            sorted(
                files,
                key=lambda item: (_canonical_relative(item[0]), item[0]),
            )
        ),
    )


def _regular_tree_files(root: Path, *, label: str) -> tuple[Path, ...]:
    root = _absolute_path(root)
    root_chain = _safe_directory_chain(root, label=label)
    files: list[Path] = []
    try:
        for current_root, directory_names, file_names in os.walk(
            root, followlinks=False
        ):
            current = Path(current_root)
            for name in directory_names:
                _snapshot_directory(current / name, label=label)
            for name in file_names:
                path = current / name
                _snapshot_regular(path, label=label)
                files.append(path)
    except CandidateBuildError:
        raise
    except OSError as exc:
        raise CandidateBuildError(f"Falha ao percorrer {label}: {root}: {exc}") from exc
    _assert_directory_chain(root_chain, label=label)
    return tuple(
        sorted(
            files,
            key=lambda item: (
                item.relative_to(root).as_posix().casefold(),
                item.relative_to(root).as_posix(),
            ),
        )
    )


def _records_for_paths(
    root: Path,
    paths: Iterable[Path],
    *,
    role: str,
    expected_hashes: Mapping[str, str] | None = None,
) -> tuple[CandidateFile, ...]:
    result: list[CandidateFile] = []
    seen: set[str] = set()
    expected = dict(expected_hashes or {})
    for path in paths:
        try:
            relative = _safe_relative(path.relative_to(root).as_posix())
        except ValueError as exc:
            raise CandidateBuildError(f"Arquivo fora da origem: {path}") from exc
        canonical = _canonical_relative(relative)
        if canonical in seen:
            raise CandidateBuildError(f"Caminho duplicado por caixa: {relative}")
        seen.add(canonical)
        digest, snapshot = _hash_regular(path, label=f"{role} {relative}")
        expected_digest = expected.get(relative)
        if expected_hashes is not None:
            if expected_digest is None:
                raise CandidateBuildError(
                    f"{role} não está coberto pelo manifesto: {relative}"
                )
            if digest != expected_digest:
                raise CandidateBuildError(
                    f"SHA-256 divergente para {role} {relative}: "
                    f"{digest}; esperado {expected_digest}"
                )
        result.append(
            CandidateFile(
                relative=relative,
                source=path,
                role=role,
                size=snapshot.size,
                sha256=digest,
                snapshot=snapshot,
            )
        )
    if expected_hashes is not None and set(expected) != {
        item.relative for item in result
    }:
        missing = sorted(set(expected) - {item.relative for item in result})
        raise CandidateBuildError(
            f"Manifesto de {role} referencia arquivos ausentes: {missing[:5]}"
        )
    return tuple(result)


def _validate_rebuild_manifest(
    rebuild_root: Path,
) -> tuple[dict, str, dict[str, str], dict[str, int]]:
    manifest, manifest_sha256 = _read_json_regular(
        rebuild_root / "manifest.json", label="Manifesto dos BNKs reconstruídos"
    )
    if manifest_sha256 != EXPECTED_REBUILD_MANIFEST_SHA256:
        raise CandidateBuildError(
            "SHA-256 do manifesto de BNK não corresponde ao rebuild canônico fixado."
        )
    if manifest.get("schema") != REBUILD_SCHEMA:
        raise CandidateBuildError("Schema do manifesto de BNK não suportado.")
    if manifest.get("algorithm") != REBUILD_ALGORITHM:
        raise CandidateBuildError("Algoritmo do manifesto de BNK não reconhecido.")
    target = manifest.get("target")
    metrics = manifest.get("metrics")
    output = manifest.get("output")
    if not all(isinstance(item, dict) for item in (target, metrics, output)):
        raise CandidateBuildError("Manifesto de BNK incompleto.")
    if output.get("banks_sha256") != EXPECTED_REBUILT_BANKS_SHA256:
        raise CandidateBuildError(
            "SHA agregado físico não corresponde aos BNKs canônicos fixados."
        )
    if output.get("alias_tree_sha256") != EXPECTED_REBUILT_ALIAS_TREE_SHA256:
        raise CandidateBuildError(
            "SHA da árvore de aliases não corresponde aos BNKs canônicos fixados."
        )
    if target.get("steam_build_id") != EXPECTED_BUILD_ID:
        raise CandidateBuildError("BuildID dos BNKs reconstruídos não é 25080141.")
    if target.get("game_version") != EXPECTED_GAME_VERSION:
        raise CandidateBuildError("Versão de jogo dos BNKs reconstruídos não é 1.17.1.")
    required_metrics = {
        "banks_rebuilt": EXPECTED_PHYSICAL_BANK_COUNT,
        "bank_aliases_verified": EXPECTED_BNK_COUNT,
        "output_alias_files": EXPECTED_BNK_COUNT,
        "identical_alias_pairs": EXPECTED_PHYSICAL_BANK_COUNT,
        "external_wem_ids": EXPECTED_WEM_COUNT,
        "sound_objects_changed": EXPECTED_CHANGED_SOUND_OBJECTS,
        "sound_objects_filtered": EXPECTED_FILTERED_SOUND_OBJECTS,
    }
    for field, expected in required_metrics.items():
        if metrics.get(field) != expected:
            raise CandidateBuildError(
                f"Métrica de reconstrução {field!r} divergente: "
                f"{metrics.get(field)!r}; esperado {expected}."
            )
    banks = output.get("banks")
    if not isinstance(banks, list) or len(banks) != EXPECTED_PHYSICAL_BANK_COUNT:
        raise CandidateBuildError("Lista física de BNKs reconstruídos incompleta.")
    if not all(isinstance(record, dict) for record in banks):
        raise CandidateBuildError("Registro de BNK reconstruído inválido.")

    alias_hashes: dict[str, str] = {}
    alias_sizes: dict[str, int] = {}
    physical_names: set[str] = set()
    physical_digest = hashlib.sha256()
    physical_records: list[tuple[str, str]] = []
    alias_records: list[tuple[str, str]] = []
    changed_id_digest = hashlib.sha256()
    filtered_id_digest = hashlib.sha256()
    changed_id_count = 0
    filtered_id_count = 0
    vcmain_filtered_ids: list[int] | None = None
    for record in sorted(
        banks,
        key=lambda item: (
            str(item.get("output_path", "")).casefold(),
            str(item.get("output_path", "")),
        ),
    ):
        if not isinstance(record, dict):
            raise CandidateBuildError("Registro de BNK reconstruído inválido.")
        output_path = record.get("output_path")
        output_hash = record.get("output_sha256")
        aliases = record.get("output_aliases")
        output_size = record.get("output_size")
        if (
            not isinstance(output_path, str)
            or not isinstance(output_hash, str)
            or len(output_hash) != 64
            or any(char not in "0123456789abcdef" for char in output_hash)
            or isinstance(output_size, bool)
            or not isinstance(output_size, int)
            or output_size <= 0
            or not isinstance(aliases, list)
            or len(aliases) != 2
        ):
            raise CandidateBuildError("Metadados de BNK reconstruído inválidos.")
        safe_output_path = _safe_relative(output_path)
        output_canonical = _canonical_relative(safe_output_path)
        if output_canonical in physical_names:
            raise CandidateBuildError(
                f"Caminho físico de BNK duplicado: {safe_output_path}"
            )
        physical_names.add(output_canonical)
        physical_records.append((output_path, output_hash))
        for field, digest, label in (
            ("sound_object_ids_changed", changed_id_digest, "alterado"),
            ("sound_object_ids_filtered", filtered_id_digest, "filtrado"),
        ):
            object_ids = record.get(field)
            if (
                not isinstance(object_ids, list)
                or any(
                    isinstance(item, bool)
                    or not isinstance(item, int)
                    or not 0 <= item <= 0xFFFFFFFF
                    for item in object_ids
                )
                or object_ids != sorted(set(object_ids))
            ):
                raise CandidateBuildError(
                    f"IDs de Sound {label} inválidos em {output_path}."
                )
            for object_id in object_ids:
                digest.update(output_path.encode("utf-8"))
                digest.update(b"\0")
                digest.update(struct.pack("<I", object_id))
            if field == "sound_object_ids_changed":
                changed_id_count += len(object_ids)
            else:
                filtered_id_count += len(object_ids)
                if Path(output_path).stem.casefold() == "vcmain":
                    if vcmain_filtered_ids is not None:
                        raise CandidateBuildError("vcmain aparece mais de uma vez no manifesto.")
                    vcmain_filtered_ids = object_ids
        for alias in aliases:
            if not isinstance(alias, str):
                raise CandidateBuildError("Alias BNK inválido no manifesto.")
            relative = _safe_relative(alias)
            if not relative.casefold().endswith(".bnk"):
                raise CandidateBuildError(f"Alias não é BNK: {relative}")
            canonical = _canonical_relative(relative)
            if any(
                _canonical_relative(existing) == canonical for existing in alias_hashes
            ):
                raise CandidateBuildError(f"Alias BNK duplicado: {relative}")
            alias_hashes[relative] = output_hash
            alias_sizes[relative] = output_size
            alias_records.append((relative, output_hash))
        if safe_output_path not in aliases:
            raise CandidateBuildError(
                f"Caminho físico não aparece entre os aliases: {safe_output_path}"
            )
    for output_path, output_hash in sorted(
        physical_records, key=lambda item: (item[0].casefold(), item[0])
    ):
        physical_digest.update(output_path.encode("utf-8"))
        physical_digest.update(b"\0")
        physical_digest.update(bytes.fromhex(output_hash))
    if physical_digest.hexdigest() != output.get("banks_sha256"):
        raise CandidateBuildError("SHA agregado físico dos BNKs não confere.")
    alias_digest = hashlib.sha256()
    for relative, output_hash in sorted(
        alias_records, key=lambda item: (item[0].casefold(), item[0])
    ):
        alias_digest.update(relative.encode("utf-8"))
        alias_digest.update(b"\0")
        alias_digest.update(bytes.fromhex(output_hash))
    if alias_digest.hexdigest() != output.get("alias_tree_sha256"):
        raise CandidateBuildError("SHA da árvore de aliases BNK não confere.")
    if (
        changed_id_count != EXPECTED_CHANGED_SOUND_OBJECTS
        or changed_id_digest.hexdigest() != EXPECTED_CHANGED_SOUND_IDS_SHA256
    ):
        raise CandidateBuildError(
            f"Identidade dos {EXPECTED_CHANGED_SOUND_OBJECTS} objetos Sound "
            "alterados não confere."
        )
    if (
        filtered_id_count != EXPECTED_FILTERED_SOUND_OBJECTS
        or filtered_id_digest.hexdigest() != EXPECTED_FILTERED_SOUND_IDS_SHA256
    ):
        raise CandidateBuildError(
            f"Identidade dos {EXPECTED_FILTERED_SOUND_OBJECTS} objetos Sound "
            "filtrados não confere."
        )
    if vcmain_filtered_ids is None:
        raise CandidateBuildError("Lista de objetos filtrados de vcmain ausente.")
    vcmain_digest = hashlib.sha256()
    for object_id in vcmain_filtered_ids:
        vcmain_digest.update(struct.pack("<I", object_id))
    if vcmain_digest.hexdigest() != EXPECTED_VCMAIN_FILTERED_IDS_SHA256:
        raise CandidateBuildError("Identidade dos 52 objetos filtrados de vcmain diverge.")
    if len(alias_hashes) != EXPECTED_BNK_COUNT:
        raise CandidateBuildError(
            f"Manifesto cobre {len(alias_hashes)} aliases BNK; "
            f"esperado {EXPECTED_BNK_COUNT}."
        )
    return manifest, manifest_sha256, alias_hashes, alias_sizes


def collect_candidate_files(
    historical_payload: Path,
    rebuild_root: Path,
) -> tuple[tuple[CandidateFile, ...], dict, str, str]:
    """Authenticate both inputs and return the exact candidate file plan."""

    historical_payload = _absolute_path(historical_payload)
    rebuild_root = _absolute_path(rebuild_root)
    historical_files = _regular_tree_files(
        historical_payload, label="Árvore do payload histórico"
    )
    historical_payload_paths = tuple(
        path
        for path in historical_files
        if path.suffix.casefold() in {".wem", ".bnk"}
    )
    historical_records = _records_for_paths(
        historical_payload,
        historical_payload_paths,
        role="Payload histórico autenticado",
    )
    historical_hashes = {
        record.relative: record.sha256 for record in historical_records
    }
    try:
        old_stats = patch_data.validate_patch_directory(
            historical_payload,
            spec=patch_data.PRODUCTION_PAYLOAD,
            expected_file_sha256=historical_hashes,
        )
    except patch_data.PayloadValidationError as exc:
        raise CandidateBuildError(
            f"O patch_data histórico não corresponde ao payload fixado: {exc}"
        ) from exc
    if (
        old_stats.wem_count != EXPECTED_WEM_COUNT
        or old_stats.bnk_count != EXPECTED_BNK_COUNT
    ):
        raise CandidateBuildError("Contagens do payload histórico são inesperadas.")
    historical_marker_sha256 = _validate_historical_marker(historical_payload)

    (
        rebuild_manifest,
        rebuild_manifest_sha256,
        alias_hashes,
        alias_sizes,
    ) = _validate_rebuild_manifest(rebuild_root)
    rebuild_files = _regular_tree_files(
        rebuild_root, label="Árvore dos BNKs reconstruídos"
    )
    rebuild_names = {path.relative_to(rebuild_root).as_posix() for path in rebuild_files}
    expected_rebuild_names = {*alias_hashes, "manifest.json", "REPORT.md"}
    if rebuild_names != expected_rebuild_names:
        raise CandidateBuildError(
            "A árvore de reconstrução contém arquivos ausentes ou inesperados: "
            f"ausentes={sorted(expected_rebuild_names - rebuild_names)[:5]}, "
            f"extras={sorted(rebuild_names - expected_rebuild_names)[:5]}"
        )
    bnk_records = _records_for_paths(
        rebuild_root,
        tuple(path for path in rebuild_files if path.suffix.casefold() == ".bnk"),
        role="BNK reconstruído",
        expected_hashes=alias_hashes,
    )
    for record in bnk_records:
        if record.size != alias_sizes[record.relative]:
            raise CandidateBuildError(
                f"Tamanho divergente para BNK reconstruído {record.relative}: "
                f"{record.size}; esperado {alias_sizes[record.relative]}"
            )
    wem_records = tuple(
        CandidateFile(
            relative=record.relative,
            source=record.source,
            role="WEM histórico autenticado",
            size=record.size,
            sha256=record.sha256,
            snapshot=record.snapshot,
        )
        for record in historical_records
        if record.relative.casefold().endswith(".wem")
    )
    if len(wem_records) != EXPECTED_WEM_COUNT:
        raise CandidateBuildError(
            f"Foram encontrados {len(wem_records)} WEMs; esperado {EXPECTED_WEM_COUNT}."
        )
    if len(bnk_records) != EXPECTED_BNK_COUNT:
        raise CandidateBuildError(
            f"Foram encontrados {len(bnk_records)} BNKs; esperado {EXPECTED_BNK_COUNT}."
        )

    historical_bnk_names = {
        record.relative
        for record in historical_records
        if record.relative.casefold().endswith(".bnk")
    }
    rebuilt_bnk_names = {item.relative for item in bnk_records}
    if historical_bnk_names != rebuilt_bnk_names:
        raise CandidateBuildError(
            "Os BNKs reconstruídos não substituem exatamente a árvore antiga: "
            f"ausentes={sorted(historical_bnk_names - rebuilt_bnk_names)[:5]}, "
            f"extras={sorted(rebuilt_bnk_names - historical_bnk_names)[:5]}"
        )

    combined = tuple(
        sorted(
            (*wem_records, *bnk_records),
            key=lambda item: (item.relative.casefold(), item.relative),
        )
    )
    canonical_names = [_canonical_relative(item.relative) for item in combined]
    if len(canonical_names) != len(set(canonical_names)):
        raise CandidateBuildError("O plano candidato contém caminhos duplicados.")
    return (
        combined,
        rebuild_manifest,
        rebuild_manifest_sha256,
        historical_marker_sha256,
    )


def _validate_record_plan(
    records: Sequence[CandidateFile],
) -> tuple[CandidateFile, ...]:
    validated = tuple(records)
    expected_order = tuple(
        sorted(
            validated,
            key=lambda item: (
                _canonical_relative(item.relative),
                item.relative,
            ),
        )
    )
    if validated != expected_order:
        raise CandidateBuildError("O plano de arquivos não está em ordem canônica.")
    seen: set[str] = set()
    for record in validated:
        if _safe_relative(record.relative) != record.relative:
            raise CandidateBuildError(
                f"Caminho não canônico no plano: {record.relative!r}"
            )
        canonical = _canonical_relative(record.relative)
        if canonical in seen:
            raise CandidateBuildError(
                f"Caminho duplicado no plano: {record.relative!r}"
            )
        seen.add(canonical)
        if (
            record.size != record.snapshot.size
            or len(record.sha256) != 64
            or any(character not in "0123456789abcdef" for character in record.sha256)
        ):
            raise CandidateBuildError(
                f"Metadados inválidos no plano: {record.relative!r}"
            )
    return validated


def _copy_record(record: CandidateFile, destination: Path) -> None:
    destination = _absolute_path(destination)
    destination_chain = _safe_directory_chain(
        destination.parent,
        label=f"Ancestral da saída {record.relative}",
        create=True,
    )
    if os.path.lexists(destination):
        raise CandidateBuildError(f"Destino de cópia já existe: {destination}")
    digest = hashlib.sha256()
    copied = 0
    try:
        with record.source.open("rb") as source, destination.open("xb") as target:
            opened = os.fstat(source.fileno())
            _assert_open_snapshot(
                opened,
                record.snapshot,
                label=f"Origem {record.relative} antes da cópia",
            )
            target_opened = os.fstat(target.fileno())
            if (
                not stat.S_ISREG(target_opened.st_mode)
                or _is_reparse(target_opened)
                or target_opened.st_nlink != 1
            ):
                raise CandidateBuildError(
                    f"Destino inseguro durante a cópia: {record.relative}"
                )
            while chunk := source.read(COPY_BUFFER_SIZE):
                target.write(chunk)
                digest.update(chunk)
                copied += len(chunk)
            source_after = os.fstat(source.fileno())
            target.flush()
            os.fsync(target.fileno())
    except OSError as exc:
        raise CandidateBuildError(
            f"Falha ao copiar {record.relative}: {exc}"
        ) from exc
    if (
        copied != record.size
        or digest.hexdigest() != record.sha256
    ):
        raise CandidateBuildError(f"Origem mudou durante a cópia: {record.relative}")
    _assert_open_snapshot(
        source_after,
        record.snapshot,
        label=f"Origem {record.relative} durante a cópia",
    )
    _assert_snapshot(
        record.source, record.snapshot, label=f"Origem {record.relative}"
    )
    _assert_directory_chain(
        destination_chain, label=f"Ancestral da saída {record.relative}"
    )
    output_digest, output_snapshot = _hash_regular(
        destination, label=f"Saída {record.relative}"
    )
    if output_snapshot.size != record.size or output_digest != record.sha256:
        raise CandidateBuildError(f"Cópia final divergente: {record.relative}")


def _tree_identity(
    root: Path,
    records: Sequence[CandidateFile],
) -> tuple[str, int, int, dict[str, str]]:
    records = _validate_record_plan(records)
    root = _absolute_path(root)
    root_chain = _safe_directory_chain(root, label="Raiz da árvore candidata")
    digest = hashlib.sha256()
    total_size = 0
    max_file_size = 0
    hashes: dict[str, str] = {}
    for record in records:
        path = root / Path(*PurePosixPath(record.relative).parts)
        parent_chain = _safe_directory_chain(
            path.parent, label=f"Ancestral candidato {record.relative}"
        )
        snapshot = _snapshot_regular(path, label=f"Arquivo candidato {record.relative}")
        encoded = record.relative.encode("utf-8")
        digest.update(struct.pack("<I", len(encoded)))
        digest.update(encoded)
        digest.update(struct.pack("<Q", snapshot.size))
        file_digest = hashlib.sha256()
        try:
            with path.open("rb") as stream:
                opened = os.fstat(stream.fileno())
                _assert_open_snapshot(
                    opened,
                    snapshot,
                    label=f"Arquivo candidato {record.relative} ao abrir",
                )
                while chunk := stream.read(COPY_BUFFER_SIZE):
                    digest.update(chunk)
                    file_digest.update(chunk)
                after = os.fstat(stream.fileno())
        except OSError as exc:
            raise CandidateBuildError(
                f"Falha ao autenticar árvore candidata: {record.relative}: {exc}"
            ) from exc
        _assert_snapshot(path, snapshot, label=f"Arquivo candidato {record.relative}")
        _assert_directory_chain(
            parent_chain, label=f"Ancestral candidato {record.relative}"
        )
        current_hash = file_digest.hexdigest()
        if (
            current_hash != record.sha256
        ):
            raise CandidateBuildError(
                f"Árvore candidata diverge do plano: {record.relative}"
            )
        hashes[record.relative] = current_hash
        total_size += snapshot.size
        max_file_size = max(max_file_size, snapshot.size)
        _assert_open_snapshot(
            after,
            snapshot,
            label=f"Arquivo candidato {record.relative} durante a leitura",
        )
    allowed_names = {record.relative for record in records}
    all_files = _regular_tree_files(root, label="Árvore candidata")
    actual_names = {path.relative_to(root).as_posix() for path in all_files}
    marker_name = patch_data.MARKER_FILENAME
    if marker_name in actual_names:
        actual_names.remove(marker_name)
    if actual_names != allowed_names:
        raise CandidateBuildError(
            "A árvore candidata não corresponde exatamente ao plano: "
            f"ausentes={sorted(allowed_names - actual_names)[:5]}, "
            f"extras={sorted(actual_names - allowed_names)[:5]}"
        )
    _assert_directory_chain(root_chain, label="Raiz da árvore candidata")
    return digest.hexdigest(), total_size, max_file_size, hashes


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=FIXED_ZIP_TIME)
    info.create_system = 3
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    info.flag_bits = 0
    return info


def write_deterministic_archive(
    archive_path: Path,
    tree_root: Path,
    records: Sequence[CandidateFile],
) -> tuple[int, str]:
    """Write the exact deterministic ZIP without marker or directory entries."""

    records = _validate_record_plan(records)
    archive_path = _absolute_path(archive_path)
    tree_root = _absolute_path(tree_root)
    archive_parent_chain = _safe_directory_chain(
        archive_path.parent, label="Ancestral do ZIP candidato"
    )
    tree_chain = _safe_directory_chain(
        tree_root, label="Raiz da árvore a compactar"
    )
    if os.path.lexists(archive_path):
        raise CandidateBuildError(f"ZIP de saída já existe: {archive_path}")
    try:
        with zipfile.ZipFile(
            archive_path,
            "x",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=ZIP_COMPRESSION_LEVEL,
            allowZip64=True,
        ) as archive:
            for index, record in enumerate(records, start=1):
                source_path = tree_root / Path(*PurePosixPath(record.relative).parts)
                snapshot = _snapshot_regular(
                    source_path, label=f"Arquivo candidato {record.relative}"
                )
                source_parent_chain = _safe_directory_chain(
                    source_path.parent,
                    label=f"Ancestral candidato {record.relative}",
                )
                archive_name = f"patch_data/{record.relative}"
                file_digest = hashlib.sha256()
                written = 0
                with source_path.open("rb") as source, archive.open(
                    _zip_info(archive_name), "w", force_zip64=True
                ) as destination:
                    opened = os.fstat(source.fileno())
                    _assert_open_snapshot(
                        opened,
                        snapshot,
                        label=f"Arquivo candidato {record.relative} ao compactar",
                    )
                    while chunk := source.read(COPY_BUFFER_SIZE):
                        destination.write(chunk)
                        file_digest.update(chunk)
                        written += len(chunk)
                    after = os.fstat(source.fileno())
                _assert_open_snapshot(
                    after,
                    snapshot,
                    label=f"Arquivo candidato {record.relative} ao compactar",
                )
                _assert_snapshot(
                    source_path,
                    snapshot,
                    label=f"Arquivo candidato {record.relative}",
                )
                _assert_directory_chain(
                    source_parent_chain,
                    label=f"Ancestral candidato {record.relative}",
                )
                if written != record.size or file_digest.hexdigest() != record.sha256:
                    raise CandidateBuildError(
                        f"Conteúdo candidato divergiu ao compactar: {record.relative}"
                    )
                if index % 500 == 0 or index == len(records):
                    print(f"Compactando: {index}/{len(records)}")
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise CandidateBuildError(f"Falha ao criar ZIP determinístico: {exc}") from exc
    _assert_directory_chain(archive_parent_chain, label="Ancestral do ZIP candidato")
    _assert_directory_chain(tree_chain, label="Raiz da árvore a compactar")
    digest, snapshot = _hash_regular(archive_path, label="ZIP candidato")
    return snapshot.size, digest


def _make_spec(
    *,
    version: str,
    archive_name: str,
    url: str,
    archive_size: int,
    archive_sha256: str,
    tree_sha256: str,
    total_size: int,
    max_file_size: int,
) -> patch_data.PayloadSpec:
    return patch_data.PayloadSpec(
        version=version,
        archive_name=archive_name,
        url=url,
        archive_size=archive_size,
        sha256=archive_sha256,
        wem_count=EXPECTED_WEM_COUNT,
        bnk_count=EXPECTED_BNK_COUNT,
        uncompressed_size=total_size,
        max_file_size=max_file_size,
        tree_sha256=tree_sha256,
    )


def _marker_data(spec: patch_data.PayloadSpec) -> dict[str, int | str]:
    return {
        "schema": patch_data.MARKER_SCHEMA,
        "payload_version": spec.version,
        "archive_name": spec.archive_name,
        "archive_sha256": spec.sha256,
        "tree_sha256": spec.tree_sha256,
        "archive_size": spec.archive_size,
        "file_count": spec.file_count,
        "wem_count": spec.wem_count,
        "bnk_count": spec.bnk_count,
        "uncompressed_size": spec.uncompressed_size,
        "max_file_size": spec.max_file_size,
    }


def _json_bytes(document: object) -> bytes:
    return (
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _write_json_exclusive(path: Path, document: object) -> None:
    _write_bytes_exclusive(path, _json_bytes(document))


def _write_bytes_exclusive(path: Path, data: bytes) -> None:
    path = _absolute_path(path)
    parent_chain = _safe_directory_chain(
        path.parent, label=f"Ancestral do arquivo {path.name}"
    )
    if os.path.lexists(path):
        raise CandidateBuildError(f"Arquivo de saída já existe: {path}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise CandidateBuildError(f"Falha ao gravar {path}: {exc}") from exc
    digest = hashlib.sha256()
    written = 0
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_reparse(opened)
            or opened.st_nlink != 1
        ):
            raise CandidateBuildError(f"Arquivo de saída inseguro: {path}")
        view = memoryview(data)
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise CandidateBuildError(f"Gravação incompleta de {path}")
            digest.update(view[written : written + count])
            written += count
        os.fsync(descriptor)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise CandidateBuildError(f"Falha ao gravar {path}: {exc}") from exc
    finally:
        os.close(descriptor)
    if written != len(data) or digest.hexdigest() != hashlib.sha256(data).hexdigest():
        raise CandidateBuildError(f"Gravação incompleta de {path}")
    _assert_directory_chain(parent_chain, label=f"Ancestral do arquivo {path.name}")
    snapshot = _snapshot_regular(path, label=f"Arquivo de saída {path.name}")
    if (snapshot.device, snapshot.inode) != (after.st_dev, after.st_ino):
        raise CandidateBuildError(f"Arquivo de saída foi trocado: {path}")
    _assert_snapshot(path, snapshot, label=f"Arquivo de saída {path.name}")
    actual_digest, actual_snapshot = _hash_regular(
        path, label=f"Arquivo de saída {path.name}", expected=snapshot
    )
    if actual_snapshot.size != len(data) or actual_digest != hashlib.sha256(data).hexdigest():
        raise CandidateBuildError(f"Arquivo de saída divergente: {path}")


def _write_text_exclusive(path: Path, text: str) -> None:
    _write_bytes_exclusive(path, text.encode("utf-8"))


def validate_archive_contents(
    archive_path: Path,
    *,
    spec: patch_data.PayloadSpec,
    expected_hashes: Mapping[str, str],
) -> str:
    """Inflate and authenticate every ZIP member and its canonical tree."""

    archive_path = _absolute_path(archive_path)
    archive_parent_chain = _safe_directory_chain(
        archive_path.parent, label="Ancestral do ZIP a validar"
    )
    actual_archive_sha256, archive_snapshot = _hash_regular(
        archive_path, label="ZIP candidato"
    )
    if (
        archive_snapshot.size != spec.archive_size
        or actual_archive_sha256 != spec.sha256
    ):
        raise CandidateBuildError("ZIP candidato falhou no PayloadSpec de tamanho/SHA-256.")
    normalized_hashes: dict[str, str] = {}
    canonical_expected: set[str] = set()
    for raw_name, expected_hash in expected_hashes.items():
        if _safe_relative(raw_name) != raw_name:
            raise CandidateBuildError(f"Caminho esperado inseguro: {raw_name!r}")
        canonical = _canonical_relative(raw_name)
        if canonical in canonical_expected:
            raise CandidateBuildError(f"Caminho esperado duplicado: {raw_name!r}")
        if (
            not isinstance(expected_hash, str)
            or len(expected_hash) != 64
            or any(character not in "0123456789abcdef" for character in expected_hash)
        ):
            raise CandidateBuildError(f"SHA-256 esperado inválido: {raw_name!r}")
        canonical_expected.add(canonical)
        normalized_hashes[raw_name] = expected_hash
    expected_names = set(normalized_hashes)
    seen: set[str] = set()
    tree_digest = hashlib.sha256()
    total_size = 0
    max_file_size = 0
    wem_count = 0
    bnk_count = 0
    try:
        with archive_path.open("rb") as raw_archive:
            opened = os.fstat(raw_archive.fileno())
            _assert_open_snapshot(
                opened, archive_snapshot, label="ZIP candidato ao abrir"
            )
            with zipfile.ZipFile(raw_archive, "r") as archive:
                if archive.comment:
                    raise CandidateBuildError("ZIP candidato contém comentário inesperado.")
                infos = archive.infolist()
                if len(infos) != len(expected_names):
                    raise CandidateBuildError(
                        f"ZIP possui {len(infos)} entradas; esperado {len(expected_names)}."
                    )
                normalized: list[tuple[str, zipfile.ZipInfo]] = []
                canonical_seen: set[str] = set()
                for info in infos:
                    prefix = "patch_data/"
                    if info.is_dir() or not info.filename.startswith(prefix):
                        raise CandidateBuildError(
                            f"Layout inesperado no ZIP: {info.filename!r}"
                        )
                    relative = _safe_relative(info.filename[len(prefix) :])
                    if info.filename != f"{prefix}{relative}":
                        raise CandidateBuildError(
                            f"Nome não canônico no ZIP: {info.filename!r}"
                        )
                    canonical = _canonical_relative(relative)
                    if canonical in canonical_seen:
                        raise CandidateBuildError(f"Entrada duplicada no ZIP: {relative}")
                    if (
                        info.date_time != FIXED_ZIP_TIME
                        or info.compress_type != zipfile.ZIP_DEFLATED
                        or info.create_system != 3
                        or info.external_attr != ((stat.S_IFREG | 0o644) << 16)
                        or info.extra
                        or info.comment
                        or info.flag_bits & ~0x800
                    ):
                        raise CandidateBuildError(
                            f"Metadados não determinísticos no ZIP: {info.filename!r}"
                        )
                    canonical_seen.add(canonical)
                    seen.add(relative)
                    normalized.append((relative, info))
                if seen != expected_names:
                    raise CandidateBuildError(
                        "Árvore do ZIP difere do plano: "
                        f"ausentes={sorted(expected_names - seen)[:5]}, "
                        f"extras={sorted(seen - expected_names)[:5]}"
                    )
                expected_order = sorted(
                    normalized,
                    key=lambda item: (_canonical_relative(item[0]), item[0]),
                )
                if normalized != expected_order:
                    raise CandidateBuildError("Entradas do ZIP fora da ordem canônica.")
                for index, (relative, info) in enumerate(normalized, start=1):
                    encoded = relative.encode("utf-8")
                    tree_digest.update(struct.pack("<I", len(encoded)))
                    tree_digest.update(encoded)
                    tree_digest.update(struct.pack("<Q", info.file_size))
                    file_digest = hashlib.sha256()
                    inflated_size = 0
                    with archive.open(info, "r") as stream:
                        while chunk := stream.read(COPY_BUFFER_SIZE):
                            tree_digest.update(chunk)
                            file_digest.update(chunk)
                            inflated_size += len(chunk)
                    if (
                        inflated_size != info.file_size
                        or file_digest.hexdigest() != normalized_hashes[relative]
                    ):
                        raise CandidateBuildError(
                            f"Conteúdo compactado divergente: {relative}"
                        )
                    total_size += inflated_size
                    max_file_size = max(max_file_size, inflated_size)
                    if relative.casefold().endswith(".wem"):
                        wem_count += 1
                    else:
                        bnk_count += 1
                    if index % 1000 == 0 or index == len(normalized):
                        print(f"Validando ZIP: {index}/{len(normalized)}")
            after = os.fstat(raw_archive.fileno())
            _assert_open_snapshot(
                after, archive_snapshot, label="ZIP candidato durante a validação"
            )
    except CandidateBuildError:
        raise
    except (OSError, zipfile.BadZipFile, NotImplementedError, RuntimeError) as exc:
        raise CandidateBuildError(f"Falha na validação integral do ZIP: {exc}") from exc
    _assert_snapshot(archive_path, archive_snapshot, label="ZIP candidato")
    _assert_directory_chain(archive_parent_chain, label="Ancestral do ZIP a validar")
    if (
        wem_count != spec.wem_count
        or bnk_count != spec.bnk_count
        or total_size != spec.uncompressed_size
        or max_file_size != spec.max_file_size
    ):
        raise CandidateBuildError("Estatísticas infladas do ZIP divergem do PayloadSpec.")
    actual_tree = tree_digest.hexdigest()
    if actual_tree != spec.tree_sha256:
        raise CandidateBuildError(
            f"SHA da árvore inflada é {actual_tree}; esperado {spec.tree_sha256}."
        )
    return actual_tree


def _same_regular_bytes(first: Path, second: Path) -> bool:
    first_parent_chain = _safe_directory_chain(
        first.parent, label="Ancestral do primeiro ZIP"
    )
    second_parent_chain = _safe_directory_chain(
        second.parent, label="Ancestral do segundo ZIP"
    )
    first_snapshot = _snapshot_regular(first, label="Primeiro ZIP")
    second_snapshot = _snapshot_regular(second, label="Segundo ZIP")
    if first_snapshot.size != second_snapshot.size:
        return False
    try:
        with first.open("rb") as left, second.open("rb") as right:
            left_opened = os.fstat(left.fileno())
            right_opened = os.fstat(right.fileno())
            _assert_open_snapshot(
                left_opened, first_snapshot, label="Primeiro ZIP ao abrir"
            )
            _assert_open_snapshot(
                right_opened, second_snapshot, label="Segundo ZIP ao abrir"
            )
            while True:
                left_chunk = left.read(COPY_BUFFER_SIZE)
                right_chunk = right.read(COPY_BUFFER_SIZE)
                if left_chunk != right_chunk:
                    return False
                if not left_chunk:
                    break
            left_after = os.fstat(left.fileno())
            right_after = os.fstat(right.fileno())
    except OSError as exc:
        raise CandidateBuildError(f"Falha ao comparar ZIPs determinísticos: {exc}") from exc
    _assert_open_snapshot(
        left_after, first_snapshot, label="Primeiro ZIP durante a comparação"
    )
    _assert_open_snapshot(
        right_after, second_snapshot, label="Segundo ZIP durante a comparação"
    )
    _assert_snapshot(first, first_snapshot, label="Primeiro ZIP")
    _assert_snapshot(second, second_snapshot, label="Segundo ZIP")
    _assert_directory_chain(first_parent_chain, label="Ancestral do primeiro ZIP")
    _assert_directory_chain(second_parent_chain, label="Ancestral do segundo ZIP")
    return True


def _unlink_owned_regular(path: Path) -> None:
    snapshot = _snapshot_regular(path, label="ZIP temporário de determinismo")
    _assert_snapshot(path, snapshot, label="ZIP temporário de determinismo")
    try:
        path.unlink()
    except OSError as exc:
        raise CandidateBuildError(
            f"ZIP temporário validado não pôde ser removido: {path}: {exc}"
        ) from exc


def _report(document: dict) -> str:
    spec = document["payload_spec"]
    stats = document["statistics"]
    validation = document["validation"]
    return "\n".join(
        (
            "# Payload completo candidato do ERPT-BR",
            "",
            "**Estado: CANDIDATO OFFLINE — NÃO APLICADO AO JOGO E NÃO PUBLICADO.**",
            "",
            f"- Versão candidata: `{spec['version']}`",
            f"- Elden Ring: `{EXPECTED_GAME_VERSION}` / Steam BuildID `{EXPECTED_BUILD_ID}`",
            f"- Reconstrução BNK: `{REBUILD_ALGORITHM}`",
            (
                f"- Arquivos: {stats['file_count']} "
                f"({stats['wem_count']} WEM + {stats['bnk_count']} BNK)"
            ),
            f"- Tamanho descompactado: {stats['uncompressed_size']} bytes",
            f"- Tamanho do ZIP: {spec['archive_size']} bytes",
            f"- SHA-256 do ZIP: `{spec['sha256']}`",
            f"- SHA-256 da árvore: `{spec['tree_sha256']}`",
            (
                f"- BNKs reconstruídos: {stats['physical_banks_rebuilt']} físicos / "
                f"{stats['bnk_count']} aliases"
            ),
            f"- Arquivo máximo: {stats['max_file_size']} bytes",
            f"- PayloadSpec: {'OK' if validation['payload_spec'] else 'FALHOU'}",
            (
                "- Árvore extraída + marker: "
                f"{'OK' if validation['directory_and_marker'] else 'FALHOU'}"
            ),
            f"- Conteúdo integral do ZIP: {'OK' if validation['archive_contents'] else 'FALHOU'}",
            (
                "- Segunda compactação byte a byte idêntica: "
                f"{'SIM' if validation['deterministic_archive'] else 'NÃO'}"
            ),
            "",
            "O ZIP contém apenas dados `.wem`/`.bnk` sob `patch_data/`. O marker fica ",
            "na árvore extraída, no formato esperado pelo cache do patcher. Nenhuma ",
            "constante de produção foi alterada.",
            "",
        )
    )


def _revalidate_sources(
    *,
    historical_payload: Path,
    rebuild_root: Path,
    records: Sequence[CandidateFile],
    rebuild_manifest: dict,
    rebuild_manifest_sha256: str,
    historical_marker_sha256: str,
) -> None:
    (
        fresh_records,
        fresh_manifest,
        fresh_manifest_sha256,
        fresh_marker_sha256,
    ) = collect_candidate_files(historical_payload, rebuild_root)
    if (
        fresh_records != tuple(records)
        or fresh_manifest != rebuild_manifest
        or fresh_manifest_sha256 != rebuild_manifest_sha256
        or fresh_marker_sha256 != historical_marker_sha256
    ):
        raise CandidateBuildError(
            "Uma origem autenticada mudou durante a geração do candidato."
        )


def _expected_bundle_layout(
    *,
    archive_name: str,
    records: Sequence[CandidateFile],
    spec: patch_data.PayloadSpec,
    document: dict,
) -> tuple[dict[str, str], set[str]]:
    expected_files = {
        f"patch_data/{record.relative}": record.sha256 for record in records
    }
    expected_files[f"patch_data/{patch_data.MARKER_FILENAME}"] = hashlib.sha256(
        _json_bytes(_marker_data(spec))
    ).hexdigest()
    expected_files[archive_name] = spec.sha256
    expected_files["candidate-manifest.json"] = hashlib.sha256(
        _json_bytes(document)
    ).hexdigest()
    expected_files["REPORT.md"] = hashlib.sha256(
        _report(document).encode("utf-8")
    ).hexdigest()

    canonical_names: set[str] = set()
    expected_directories = {""}
    for relative in expected_files:
        safe_relative = _safe_bundle_relative(relative)
        if safe_relative != relative:
            raise CandidateBuildError(
                f"Caminho não canônico no layout final: {relative!r}"
            )
        canonical = _canonical_relative(relative)
        if canonical in canonical_names:
            raise CandidateBuildError(
                f"Caminho duplicado no layout final: {relative!r}"
            )
        canonical_names.add(canonical)
        parent = PurePosixPath(relative).parent
        while parent != PurePosixPath("."):
            expected_directories.add(parent.as_posix())
            parent = parent.parent
    return expected_files, expected_directories


def _assert_bundle_snapshot(
    bundle_root: Path,
    expected: BundleSnapshot,
    *,
    label: str,
    verify_contents: bool,
) -> None:
    """Recheck exact inventory, identity and optionally every file's bytes."""

    bundle_root = _absolute_path(bundle_root)
    current_directories, current_files = _bundle_inventory(bundle_root, label=label)
    if current_directories != expected.directories:
        raise CandidateBuildError(f"Inventário/identidade de diretórios mudou em {label}.")

    expected_by_name = {item.relative: item for item in expected.files}
    current_by_name = {
        relative: (path, snapshot)
        for relative, path, snapshot in current_files
    }
    if set(current_by_name) != set(expected_by_name):
        raise CandidateBuildError(
            f"Inventário de arquivos mudou em {label}: "
            f"ausentes={sorted(set(expected_by_name) - set(current_by_name))[:5]}, "
            f"extras={sorted(set(current_by_name) - set(expected_by_name))[:5]}"
        )
    for relative in sorted(
        expected_by_name,
        key=lambda item: (_canonical_relative(item), item),
    ):
        expected_file = expected_by_name[relative]
        path, current_snapshot = current_by_name[relative]
        if current_snapshot != expected_file.snapshot:
            raise CandidateBuildError(
                f"Identidade do arquivo mudou em {label}: {relative}"
            )
        if verify_contents:
            digest, hashed_snapshot = _hash_regular(
                path,
                label=f"{label} {relative}",
                expected=current_snapshot,
            )
            if hashed_snapshot != expected_file.snapshot or digest != expected_file.sha256:
                raise CandidateBuildError(
                    f"Conteúdo do arquivo mudou em {label}: {relative}"
                )

    # Pin the whole namespace again after the last content read.  This catches
    # swaps, additions and deletions that happened while the full hash pass ran.
    final_directories, final_files = _bundle_inventory(bundle_root, label=label)
    final_file_snapshots = tuple(
        (relative, snapshot) for relative, _path, snapshot in final_files
    )
    expected_file_snapshots = tuple(
        (item.relative, item.snapshot) for item in expected.files
    )
    if (
        final_directories != expected.directories
        or final_file_snapshots != expected_file_snapshots
    ):
        raise CandidateBuildError(
            f"O bundle mudou durante a revalidação integral em {label}."
        )


def _pin_exact_bundle(
    bundle_root: Path,
    *,
    expected_files: Mapping[str, str],
    expected_directories: set[str],
    label: str,
) -> BundleSnapshot:
    """Hash and pin every expected file plus the complete directory namespace."""

    bundle_root = _absolute_path(bundle_root)
    directories, files = _bundle_inventory(bundle_root, label=label)
    actual_directories = {item.relative for item in directories}
    actual_files = {relative for relative, _path, _snapshot in files}
    if actual_directories != expected_directories or actual_files != set(expected_files):
        raise CandidateBuildError(
            f"Inventário integral divergente em {label}: "
            f"diretórios ausentes={sorted(expected_directories - actual_directories)[:5]}, "
            f"diretórios extras={sorted(actual_directories - expected_directories)[:5]}, "
            f"arquivos ausentes={sorted(set(expected_files) - actual_files)[:5]}, "
            f"arquivos extras={sorted(actual_files - set(expected_files))[:5]}"
        )

    pinned_files: list[BundleFileSnapshot] = []
    for relative, path, snapshot in files:
        digest, hashed_snapshot = _hash_regular(
            path,
            label=f"{label} {relative}",
            expected=snapshot,
        )
        if digest != expected_files[relative]:
            raise CandidateBuildError(
                f"SHA-256 integral divergente em {label}: {relative}"
            )
        pinned_files.append(
            BundleFileSnapshot(
                relative=relative,
                sha256=digest,
                snapshot=hashed_snapshot,
            )
        )
    pinned = BundleSnapshot(directories=directories, files=tuple(pinned_files))
    _assert_bundle_snapshot(
        bundle_root,
        pinned,
        label=label,
        verify_contents=True,
    )
    return pinned


def _validate_final_bundle(
    *,
    bundle_root: Path,
    archive_name: str,
    records: Sequence[CandidateFile],
    spec: patch_data.PayloadSpec,
    expected_hashes: Mapping[str, str],
    document: dict,
) -> BundleSnapshot:
    bundle_root = _absolute_path(bundle_root)
    bundle_chain = _safe_directory_chain(
        bundle_root, label="Bundle candidato em staging"
    )
    expected_top = {
        "patch_data",
        archive_name,
        "candidate-manifest.json",
        "REPORT.md",
    }
    try:
        top_entries = tuple(bundle_root.iterdir())
    except OSError as exc:
        raise CandidateBuildError(f"Falha ao enumerar bundle candidato: {exc}") from exc
    actual_top = {entry.name for entry in top_entries}
    if actual_top != expected_top or len(top_entries) != len(expected_top):
        raise CandidateBuildError(
            "Layout final do bundle divergente: "
            f"ausentes={sorted(expected_top - actual_top)}, "
            f"extras={sorted(actual_top - expected_top)}"
        )
    tree_root = bundle_root / "patch_data"
    _snapshot_directory(tree_root, label="Árvore final patch_data")
    for name in expected_top - {"patch_data"}:
        _snapshot_regular(bundle_root / name, label=f"Arquivo final {name}")

    try:
        stats = patch_data.validate_patch_directory(
            tree_root,
            spec=spec,
            expected_file_sha256=expected_hashes,
        )
    except patch_data.PayloadValidationError as exc:
        raise CandidateBuildError(f"Árvore final do candidato divergiu: {exc}") from exc
    marker, _marker_sha256 = _read_json_regular(
        tree_root / patch_data.MARKER_FILENAME,
        label="Marker final do candidato",
    )
    if marker != _marker_data(spec):
        raise CandidateBuildError("Marker final do candidato não é exato.")
    tree_sha256, total_size, max_file_size, final_hashes = _tree_identity(
        tree_root, records
    )
    if (
        tree_sha256 != spec.tree_sha256
        or total_size != spec.uncompressed_size
        or max_file_size != spec.max_file_size
        or final_hashes != dict(expected_hashes)
        or stats.total_size != spec.uncompressed_size
    ):
        raise CandidateBuildError("Identidade final da árvore candidata divergiu.")
    if (
        validate_archive_contents(
            bundle_root / archive_name,
            spec=spec,
            expected_hashes=expected_hashes,
        )
        != spec.tree_sha256
    ):
        raise CandidateBuildError("Identidade final do ZIP candidato divergiu.")
    final_manifest, _manifest_sha256 = _read_json_regular(
        bundle_root / "candidate-manifest.json",
        label="Manifesto final do candidato",
    )
    if final_manifest != document:
        raise CandidateBuildError("Manifesto final do candidato divergiu.")
    expected_report = _report(document).encode("utf-8")
    report_digest, report_snapshot = _hash_regular(
        bundle_root / "REPORT.md", label="Relatório final do candidato"
    )
    if (
        report_snapshot.size != len(expected_report)
        or report_digest != hashlib.sha256(expected_report).hexdigest()
    ):
        raise CandidateBuildError("Relatório final do candidato divergiu.")
    _assert_directory_chain(bundle_chain, label="Bundle candidato em staging")
    expected_files, expected_directories = _expected_bundle_layout(
        archive_name=archive_name,
        records=records,
        spec=spec,
        document=document,
    )
    return _pin_exact_bundle(
        bundle_root,
        expected_files=expected_files,
        expected_directories=expected_directories,
        label="Bundle candidato integral",
    )


def _publish_directory_exclusive(
    staging: Path,
    output: Path,
    *,
    output_parent_chain: Sequence[DirectorySnapshot],
    validated_bundle: BundleSnapshot,
) -> None:
    """Publish a completed directory without replacing a pre-existing target."""

    staging = _absolute_path(staging)
    output = _absolute_path(output)
    staging_snapshot = _snapshot_directory(staging, label="Staging a publicar")
    _assert_directory_chain(output_parent_chain, label="Ancestral da saída final")
    if os.path.lexists(output):
        raise CandidateBuildError(f"O bundle de saída apareceu: {output}")
    _assert_bundle_snapshot(
        staging,
        validated_bundle,
        label="Staging imediatamente antes da publicação",
        verify_contents=True,
    )
    _assert_directory_chain(output_parent_chain, label="Ancestral da saída final")
    if os.path.lexists(output):
        raise CandidateBuildError(f"O bundle de saída apareceu: {output}")

    try:
        if os.name == "nt":
            # Windows MoveFile semantics used by os.rename fail if dst exists.
            os.rename(staging, output)
        elif sys.platform.startswith("linux"):
            libc = ctypes.CDLL(None, use_errno=True)
            renameat2 = getattr(libc, "renameat2", None)
            if renameat2 is None:
                raise CandidateBuildError(
                    "O sistema não oferece publicação atômica RENAME_NOREPLACE."
                )
            renameat2.argtypes = (
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            )
            renameat2.restype = ctypes.c_int
            at_fdcwd = -100
            rename_noreplace = 1
            result = renameat2(
                at_fdcwd,
                os.fsencode(staging),
                at_fdcwd,
                os.fsencode(output),
                rename_noreplace,
            )
            if result != 0:
                error_number = ctypes.get_errno()
                raise OSError(error_number, os.strerror(error_number), output)
        else:
            raise CandidateBuildError(
                "Publicação exclusiva não suportada com segurança neste sistema."
            )
    except CandidateBuildError:
        raise
    except OSError as exc:
        raise CandidateBuildError(
            f"Falha ao publicar bundle sem sobrescrever {output}: {exc}"
        ) from exc
    published = _snapshot_directory(output, label="Bundle candidato publicado")
    if (published.device, published.inode) != (
        staging_snapshot.device,
        staging_snapshot.inode,
    ):
        raise CandidateBuildError("O diretório publicado não é o staging validado.")
    _assert_directory_chain(output_parent_chain, label="Ancestral da saída final")
    _assert_bundle_snapshot(
        output,
        validated_bundle,
        label="Bundle publicado sob o nome final",
        verify_contents=True,
    )


def build_candidate(
    *,
    historical_payload: Path,
    rebuild_root: Path,
    output: Path,
    version: str = DEFAULT_VERSION,
    archive_name: str = DEFAULT_ARCHIVE_NAME,
    url: str = DEFAULT_URL,
    verify_determinism: bool = True,
) -> dict:
    historical_payload = _absolute_path(historical_payload)
    rebuild_root = _absolute_path(rebuild_root)
    output = _absolute_path(output)
    historical_chain = _safe_directory_chain(
        historical_payload, label="Origem histórica"
    )
    rebuild_chain = _safe_directory_chain(
        rebuild_root, label="Origem dos BNKs reconstruídos"
    )
    output_parent_chain = _safe_directory_chain(
        output.parent, label="Ancestral da saída final", create=True
    )
    if output.exists() or os.path.lexists(output):
        raise CandidateBuildError(f"O bundle de saída já existe: {output}")
    archive_name = _safe_archive_name(archive_name)
    for source in (historical_payload, rebuild_root):
        if output == source or output in source.parents or source in output.parents:
            raise CandidateBuildError(
                f"O bundle de saída não pode se sobrepor à origem: {source}"
            )
    _assert_directory_chain(historical_chain, label="Origem histórica")
    _assert_directory_chain(rebuild_chain, label="Origem dos BNKs reconstruídos")
    _assert_directory_chain(output_parent_chain, label="Ancestral da saída final")

    print("Validando payload histórico e manifesto dos BNKs reconstruídos...")
    (
        records,
        rebuild_manifest,
        rebuild_manifest_sha256,
        historical_marker_sha256,
    ) = collect_candidate_files(historical_payload, rebuild_root)
    staging = output.parent / f".{output.name}.{uuid.uuid4().hex}.staging"
    if os.path.lexists(staging):
        raise CandidateBuildError(f"Staging aleatório já existe: {staging}")
    staging.mkdir()
    staging_snapshot = _snapshot_directory(staging, label="Staging candidato")
    tree_root = staging / "patch_data"
    tree_root.mkdir()
    tree_snapshot = _snapshot_directory(tree_root, label="Árvore candidata")
    archive_path = staging / archive_name
    try:
        for index, record in enumerate(records, start=1):
            _copy_record(
                record,
                tree_root / Path(*PurePosixPath(record.relative).parts),
            )
            if index % 1000 == 0 or index == len(records):
                print(f"Copiando árvore: {index}/{len(records)}")

        tree_sha256, total_size, max_file_size, candidate_hashes = _tree_identity(
            tree_root, records
        )
        archive_size, archive_sha256 = write_deterministic_archive(
            archive_path, tree_root, records
        )
        spec = _make_spec(
            version=version,
            archive_name=archive_name,
            url=url,
            archive_size=archive_size,
            archive_sha256=archive_sha256,
            tree_sha256=tree_sha256,
            total_size=total_size,
            max_file_size=max_file_size,
        )

        marker_path = tree_root / patch_data.MARKER_FILENAME
        _write_json_exclusive(marker_path, _marker_data(spec))
        try:
            directory_stats = patch_data.validate_patch_directory(
                tree_root,
                spec=spec,
                expected_file_sha256=candidate_hashes,
            )
        except patch_data.PayloadValidationError as exc:
            raise CandidateBuildError(
                f"Árvore candidata/marker falhou no PayloadSpec: {exc}"
            ) from exc
        inflated_tree_sha256 = validate_archive_contents(
            archive_path,
            spec=spec,
            expected_hashes=candidate_hashes,
        )

        deterministic = False
        if verify_determinism:
            second_path = staging / f".{archive_name}.determinism-{uuid.uuid4().hex}.zip"
            second_size, second_sha256 = write_deterministic_archive(
                second_path, tree_root, records
            )
            deterministic = (
                second_size == archive_size
                and second_sha256 == archive_sha256
                and _same_regular_bytes(archive_path, second_path)
            )
            if not deterministic:
                raise CandidateBuildError(
                    "A segunda compactação não é byte a byte determinística."
                )
            _unlink_owned_regular(second_path)

        file_manifest = [
            {
                "path": record.relative,
                "role": "historical-wem" if record.role.startswith("WEM") else "rebuilt-bnk",
                "size": record.size,
                "sha256": record.sha256,
            }
            for record in records
        ]
        document = {
            "schema": BUNDLE_SCHEMA,
            "status": "offline-candidate-not-applied-not-published",
            "payload_spec": asdict(spec),
            "target": {
                "game": "ELDEN RING",
                "game_version": EXPECTED_GAME_VERSION,
                "steam_build_id": EXPECTED_BUILD_ID,
                "build_fingerprint": rebuild_manifest["target"]["build_fingerprint"],
            },
            "provenance": {
                "historical_payload_version": patch_data.PRODUCTION_PAYLOAD.version,
                "historical_archive_sha256": patch_data.PRODUCTION_PAYLOAD.sha256,
                "historical_tree_sha256": patch_data.PRODUCTION_PAYLOAD.tree_sha256,
                "historical_marker_sha256": historical_marker_sha256,
                "rebuild_algorithm": rebuild_manifest["algorithm"],
                "rebuild_manifest_sha256": rebuild_manifest_sha256,
                "rebuilt_banks_sha256": rebuild_manifest["output"]["banks_sha256"],
                "rebuilt_alias_tree_sha256": rebuild_manifest["output"]["alias_tree_sha256"],
                "changed_sound_ids_sha256": EXPECTED_CHANGED_SOUND_IDS_SHA256,
                "filtered_sound_ids_sha256": EXPECTED_FILTERED_SOUND_IDS_SHA256,
                "vcmain_filtered_ids_sha256": EXPECTED_VCMAIN_FILTERED_IDS_SHA256,
            },
            "statistics": {
                "file_count": len(records),
                "wem_count": sum(
                    1 for item in records if item.relative.casefold().endswith(".wem")
                ),
                "bnk_count": sum(
                    1 for item in records if item.relative.casefold().endswith(".bnk")
                ),
                "physical_banks_rebuilt": EXPECTED_PHYSICAL_BANK_COUNT,
                "uncompressed_size": directory_stats.total_size,
                "max_file_size": directory_stats.max_file_size,
            },
            "validation": {
                "payload_spec": True,
                "directory_and_marker": True,
                "archive_contents": inflated_tree_sha256 == spec.tree_sha256,
                "deterministic_archive": deterministic,
                "determinism_runs": 2 if verify_determinism else 1,
                "final_source_revalidation": True,
                "final_bundle_revalidation": True,
                "zip_wrapper": "patch_data/",
                "fixed_zip_timestamp": "1980-01-01T00:00:00",
                "zip_compression": f"deflate-{ZIP_COMPRESSION_LEVEL}",
                "zlib_version": zlib.ZLIB_VERSION,
                "python_version": sys.version.split()[0],
            },
            "files": file_manifest,
        }
        _write_json_exclusive(staging / "candidate-manifest.json", document)
        _write_text_exclusive(staging / "REPORT.md", _report(document))
        _assert_directory_snapshot(staging_snapshot, label="Staging candidato")
        _assert_directory_snapshot(tree_snapshot, label="Árvore candidata")
        print("Revalidando integralmente as origens e o bundle final...")
        _revalidate_sources(
            historical_payload=historical_payload,
            rebuild_root=rebuild_root,
            records=records,
            rebuild_manifest=rebuild_manifest,
            rebuild_manifest_sha256=rebuild_manifest_sha256,
            historical_marker_sha256=historical_marker_sha256,
        )
        validated_staging = _validate_final_bundle(
            bundle_root=staging,
            archive_name=archive_name,
            records=records,
            spec=spec,
            expected_hashes=candidate_hashes,
            document=document,
        )
        _assert_directory_chain(historical_chain, label="Origem histórica")
        _assert_directory_chain(rebuild_chain, label="Origem dos BNKs reconstruídos")
        _assert_directory_chain(output_parent_chain, label="Ancestral da saída final")
        if output.exists() or os.path.lexists(output):
            raise CandidateBuildError(f"O bundle de saída apareceu durante a geração: {output}")
        _publish_directory_exclusive(
            staging,
            output,
            output_parent_chain=output_parent_chain,
            validated_bundle=validated_staging,
        )
        validated_output = _validate_final_bundle(
            bundle_root=output,
            archive_name=archive_name,
            records=records,
            spec=spec,
            expected_hashes=candidate_hashes,
            document=document,
        )
        _assert_bundle_snapshot(
            output,
            validated_output,
            label="Bundle final antes da conclusão",
            verify_contents=True,
        )
        return document
    except Exception as exc:
        preserved = tuple(
            path for path in (output, staging) if os.path.lexists(path)
        )
        if preserved:
            artifact_detail = ", ".join(str(path) for path in preserved)
        else:
            artifact_detail = "nenhum caminho de artefato permaneceu acessível"
        raise CandidateBuildError(
            f"{exc} Artefato(s) preservado(s) para diagnóstico: {artifact_detail}"
        ) from exc


def _default_historical_payload() -> Path:
    local_data = os.environ.get("LOCALAPPDATA")
    if not local_data:
        raise CandidateBuildError("LOCALAPPDATA ausente; informe --historical-payload.")
    return Path(local_data) / "ERPT-BR" / "payload" / "patch_data"


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Monta e valida um ZIP candidato com WEMs históricos e BNKs reconstruídos."
        )
    )
    parser.add_argument("--historical-payload", type=Path)
    parser.add_argument("--rebuilt-bnks", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", default=DEFAULT_VERSION)
    parser.add_argument("--archive-name", default=DEFAULT_ARCHIVE_NAME)
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument(
        "--skip-determinism-check",
        action="store_true",
        help="gera uma vez (não use para um candidato de release)",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        document = build_candidate(
            historical_payload=args.historical_payload or _default_historical_payload(),
            rebuild_root=args.rebuilt_bnks,
            output=args.output,
            version=args.version,
            archive_name=args.archive_name,
            url=args.url,
            verify_determinism=not args.skip_determinism_check,
        )
    except (CandidateBuildError, OSError, ValueError) as exc:
        print(f"ERRO SEGURO: {exc}", file=sys.stderr)
        return 2
    spec = document["payload_spec"]
    print(
        "Candidato concluído sem tocar no jogo: "
        f"{document['statistics']['file_count']} arquivos, "
        f"ZIP {spec['archive_size']} bytes, SHA-256 {spec['sha256']}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
