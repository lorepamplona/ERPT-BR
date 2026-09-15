#!/usr/bin/env python3
"""Reconstrói BNKs traduzidos sobre um backup vanilla autenticado.

Esta ferramenta é deliberadamente *offline*: lê o BHD ativo somente como
índice autenticado, lê os bytes vanilla exclusivamente de ``*.bdt.backup`` e
publica BNKs soltos em um diretório novo. Ela nunca abre um BDT do jogo para
escrita e nunca produz um BDT pronto para substituir o original.
"""

from __future__ import annotations

import argparse
from collections import Counter
from contextlib import ExitStack
import ctypes
import hashlib
import json
import os
import re
import stat
import struct
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from patcher import bnk, engine, patch_data  # noqa: E402


TOOL_SCHEMA = 1
ALGORITHM = "vanilla-authoritative-wwise135-v2"
DEFAULT_EXPECTED_BANKS = 136
DEFAULT_EXPECTED_BUILD_ID = "25080141"
DEFAULT_GAME_VERSION = "1.17.1"
ARCHIVE_RECORD_RE = re.compile(r"^sd(?:_dlc\d+)?$", re.IGNORECASE)
HEX_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COPY_BUFFER_SIZE = 8 * 1024 * 1024
PINNED_BHD_SHA256_BY_BUILD = {
    DEFAULT_EXPECTED_BUILD_ID: {
        "sd": "c62ef231ebdcd91b09349496c6f1ff6f5bc32959cc59bbd0474f90d36b3eb5ec",
        "sd_dlc02": "f8e4be20c1fd1c04b7d287de95d455fe9dceb73d13aaab44450fc03a225dde7e",
    }
}
PINNED_BDT_BACKUPS_BY_BUILD = {
    DEFAULT_EXPECTED_BUILD_ID: {
        "sd": (
            2_308_921_312,
            "2cfc747f4bafef625210a9f0abbdd47f2e076f2576757f31c3b4aeb2e063742d",
        ),
        "sd_dlc02": (
            371_868_704,
            "b7f590ea9c8dd9c4fedfb76204516e0c037321170c5c83302b777e58d96cb97c",
        ),
    }
}
EXPECTED_CHANGED_SOUND_OBJECTS = 1_010
EXPECTED_FILTERED_SOUND_OBJECTS = 216
EXPECTED_CHANGED_SOUND_IDS_SHA256 = (
    "0d0472d678ebbc7db72baa27f850678af077746f22361bd0c9101cc9d7647f3c"
)
EXPECTED_FILTERED_SOUND_IDS_SHA256 = (
    "f0cb9b857ccef7749f0a2b8bcf768399ceafcd7261ccd1e048b8df546497e292"
)
EXPECTED_VCMAIN_FILTERED_IDS = (
    6_933_300,
    50_540_840,
    85_522_856,
    121_741_034,
    151_057_931,
    183_902_495,
    189_229_904,
    229_928_286,
    255_857_829,
    257_500_591,
    266_323_891,
    269_882_965,
    273_504_111,
    342_459_047,
    343_413_349,
    355_429_712,
    357_928_405,
    377_916_798,
    388_192_396,
    406_157_836,
    419_720_592,
    420_823_461,
    423_145_166,
    466_346_397,
    488_788_193,
    490_435_046,
    491_169_895,
    494_912_009,
    508_400_630,
    558_414_689,
    587_593_013,
    631_592_257,
    631_933_384,
    656_670_235,
    674_473_528,
    699_305_366,
    713_663_617,
    727_688_011,
    731_256_160,
    773_229_985,
    785_602_366,
    794_016_037,
    795_065_857,
    808_681_170,
    814_916_618,
    820_005_175,
    843_549_263,
    867_104_907,
    988_578_645,
    1_042_023_995,
    1_064_739_259,
    1_071_372_075,
)


class RebuildError(RuntimeError):
    """Falha segura que não autoriza publicar um payload."""


@dataclass(frozen=True)
class FileSnapshot:
    device: int
    inode: int
    size: int
    mtime_ns: int


@dataclass(frozen=True)
class DirectorySnapshot:
    device: int
    inode: int


@dataclass(frozen=True)
class AuthenticatedArchive:
    name: str
    bhd_path: Path
    backup_path: Path
    bhd_sha256: str
    backup_sha256: str
    snapshot: FileSnapshot
    entries: tuple[engine.FileEntry, ...]
    salt: bytes


@dataclass(frozen=True)
class PayloadBank:
    path: Path
    relative: str
    data: bytes
    sha256: str
    snapshot: FileSnapshot


@dataclass(frozen=True)
class BankTarget:
    archive: AuthenticatedArchive
    entry: engine.FileEntry


@dataclass(frozen=True)
class BankJob:
    game_path: str
    sources: tuple[PayloadBank, ...]
    target: BankTarget


def _is_reparse(metadata: os.stat_result) -> bool:
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(metadata, "st_file_attributes", 0)
    return bool(flag and attributes & flag)


def _absolute_without_resolving(path: str | os.PathLike[str]) -> Path:
    """Normalize a path lexically while retaining evidence of reparses."""

    return Path(os.path.abspath(os.fspath(path)))


def _snapshot_directory(path: Path, *, label: str) -> DirectorySnapshot:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise RebuildError(f"{label} ausente ou ilegível: {path}: {exc}") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or _is_reparse(metadata)
        or not stat.S_ISDIR(metadata.st_mode)
    ):
        raise RebuildError(
            f"{label} precisa ser um diretório real, sem link/reparse: {path}"
        )
    return DirectorySnapshot(metadata.st_dev, metadata.st_ino)


def _ensure_safe_directory_tree(
    path: str | os.PathLike[str],
    *,
    label: str,
    create: bool,
) -> Path:
    """Validate every lexical ancestor, optionally creating missing directories."""

    target = _absolute_without_resolving(path)
    inspected: list[tuple[Path, DirectorySnapshot]] = []
    for current in (*reversed(target.parents), target):
        if os.path.lexists(current):
            inspected.append(
                (current, _snapshot_directory(current, label=label))
            )
            continue
        if not create:
            return target
        try:
            current.mkdir()
        except FileExistsError:
            pass
        except OSError as exc:
            raise RebuildError(
                f"Não foi possível criar {label} {current}: {exc}"
            ) from exc
        inspected.append((current, _snapshot_directory(current, label=label)))

    # A component can be swapped after its first lstat while a descendant is
    # inspected.  Recheck every identity once the complete chain exists.
    for current, expected in inspected:
        if _snapshot_directory(current, label=label) != expected:
            raise RebuildError(f"{label} mudou durante a validação: {current}")
    return target


def _assert_directory_unchanged(
    path: Path,
    expected: DirectorySnapshot,
    *,
    label: str,
) -> None:
    _ensure_safe_directory_tree(path, label=label, create=False)
    if _snapshot_directory(path, label=label) != expected:
        raise RebuildError(f"{label} mudou durante a reconstrução: {path}")


def _matches_file_snapshot(
    metadata: os.stat_result,
    expected: FileSnapshot,
) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and not _is_reparse(metadata)
        and metadata.st_nlink == 1
        and (metadata.st_dev, metadata.st_ino)
        == (expected.device, expected.inode)
        and metadata.st_size == expected.size
        and metadata.st_mtime_ns == expected.mtime_ns
    )


def _snapshot_regular(path: Path, *, label: str) -> FileSnapshot:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise RebuildError(f"{label} ausente ou ilegível: {path}: {exc}") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or _is_reparse(metadata)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        raise RebuildError(
            f"{label} precisa ser um arquivo regular exclusivo, sem link/reparse: {path}"
        )
    return FileSnapshot(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        size=metadata.st_size,
        mtime_ns=metadata.st_mtime_ns,
    )


def _assert_unchanged(path: Path, expected: FileSnapshot, *, label: str) -> None:
    if _snapshot_regular(path, label=label) != expected:
        raise RebuildError(f"{label} mudou durante a reconstrução: {path}")


def _sha256_regular(
    path: Path,
    *,
    label: str,
    expected: FileSnapshot | None = None,
) -> tuple[str, FileSnapshot]:
    before = expected or _snapshot_regular(path, label=label)
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if not _matches_file_snapshot(opened, before):
                raise RebuildError(f"{label} foi trocado durante a abertura: {path}")
            while chunk := stream.read(COPY_BUFFER_SIZE):
                digest.update(chunk)
            opened_after = os.fstat(stream.fileno())
    except OSError as exc:
        raise RebuildError(f"Falha ao ler {label}: {path}: {exc}") from exc
    if not _matches_file_snapshot(opened_after, before):
        raise RebuildError(f"{label} mudou durante o hash: {path}")
    _assert_unchanged(path, before, label=label)
    return digest.hexdigest(), before


def _read_regular_bytes(path: Path, *, label: str) -> tuple[bytes, str]:
    snapshot = _snapshot_regular(path, label=label)
    data = bytearray()
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if not _matches_file_snapshot(opened, snapshot):
                raise RebuildError(f"{label} foi trocado durante a abertura: {path}")
            while chunk := stream.read(COPY_BUFFER_SIZE):
                data.extend(chunk)
                digest.update(chunk)
            after = os.fstat(stream.fileno())
    except OSError as exc:
        raise RebuildError(f"Falha ao ler {label}: {path}: {exc}") from exc
    if not _matches_file_snapshot(after, snapshot):
        raise RebuildError(f"{label} mudou durante a leitura: {path}")
    _assert_unchanged(path, snapshot, label=label)
    return bytes(data), digest.hexdigest()


def _default_backup_root() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        raise RebuildError("LOCALAPPDATA ausente; informe --backup-root.")
    return Path(local_app_data) / "ERPT-BR" / "backups"


def _default_payload_root() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        raise RebuildError("LOCALAPPDATA ausente; informe --payload.")
    return Path(local_app_data) / "ERPT-BR" / "payload" / "patch_data"


def _expected_payload_marker() -> dict[str, int | str]:
    spec = patch_data.PRODUCTION_PAYLOAD
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


def validate_historical_payload(payload_root: Path) -> str:
    """Require the entire pinned v0.8.1 tree and its exact cache marker."""

    try:
        stats = patch_data.validate_patch_directory(
            payload_root,
            spec=patch_data.PRODUCTION_PAYLOAD,
        )
    except patch_data.PayloadValidationError as exc:
        raise RebuildError(
            f"Payload histórico não corresponde integralmente ao v0.8.1 fixado: {exc}"
        ) from exc
    marker, marker_sha256 = _load_json_regular(
        payload_root / patch_data.MARKER_FILENAME,
        label="Marker do payload histórico",
    )
    if marker != _expected_payload_marker():
        raise RebuildError(
            "Marker do payload histórico não corresponde exatamente ao "
            "PayloadSpec v0.8.1 fixado."
        )
    if (
        stats.wem_count != patch_data.PRODUCTION_PAYLOAD.wem_count
        or stats.bnk_count != patch_data.PRODUCTION_PAYLOAD.bnk_count
        or stats.total_size != patch_data.PRODUCTION_PAYLOAD.uncompressed_size
        or stats.max_file_size != patch_data.PRODUCTION_PAYLOAD.max_file_size
    ):
        raise RebuildError("Estatísticas do payload histórico divergem do v0.8.1.")
    return marker_sha256


def discover_manifest(backup_root: Path) -> Path:
    if not backup_root.is_dir():
        raise RebuildError(f"Raiz de backup inexistente: {backup_root}")
    candidates = sorted(backup_root.glob("*/*/manifest.json"), key=str)
    usable: list[Path] = []
    for candidate in candidates:
        try:
            document, _digest = _load_json_regular(
                candidate, label="Candidato a manifesto de backup"
            )
        except RebuildError:
            continue
        if (
            document.get("schema") == engine.BACKUP_SCHEMA
            and document.get("state") == "applied"
            and isinstance(document.get("archives"), list)
        ):
            usable.append(candidate)
    if len(usable) != 1:
        raise RebuildError(
            "Era esperado exatamente um backup aplicado utilizável; "
            f"foram encontrados {len(usable)}. Informe --manifest explicitamente."
        )
    return usable[0]


def _load_json_regular(path: Path, *, label: str) -> tuple[dict, str]:
    data, digest = _read_regular_bytes(path, label=label)
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RebuildError(f"{label} não é JSON UTF-8 válido: {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise RebuildError(f"{label} precisa conter um objeto JSON: {path}")
    return document, digest


def _steam_build_id(game_dir: Path) -> str:
    try:
        steamapps = game_dir.parents[2]
    except IndexError as exc:
        raise RebuildError(f"Pasta do jogo inesperada: {game_dir}") from exc
    app_manifest = steamapps / "appmanifest_1245620.acf"
    data, _digest = _read_regular_bytes(
        app_manifest, label="Manifesto Steam do Elden Ring"
    )
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise RebuildError(f"Manifesto Steam não é texto UTF-8: {app_manifest}") from exc
    match = re.search(r'^\s*"buildid"\s+"([0-9]+)"\s*$', text, re.MULTILINE)
    if not match:
        raise RebuildError(f"BuildID ausente no manifesto Steam: {app_manifest}")
    return match.group(1)


def _decrypt_authenticated_bhd(bhd_data: bytes, *, name: str) -> bytes:
    """Accept only the RSA-wrapped index distributed by the game."""

    if bhd_data.startswith(b"BHD5"):
        raise RebuildError(
            f"Índice {name} está em texto puro; a autoridade RSA do jogo é obrigatória."
        )
    if not bhd_data or len(bhd_data) % 256:
        raise RebuildError(f"Formato RSA do índice {name} não suportado.")
    try:
        decrypted = engine.rsa_decrypt_bhd(bhd_data)
    except engine.PatcherError as exc:
        raise RebuildError(f"Falha ao autenticar o índice RSA {name}: {exc}") from exc
    if not decrypted.startswith(b"BHD5"):
        raise RebuildError(f"Índice RSA {name} não decifrou para BHD5.")
    return decrypted


def _validate_pinned_bhd_digests(
    build_id: str,
    observed: dict[str, str],
) -> None:
    expected = PINNED_BHD_SHA256_BY_BUILD.get(build_id)
    if expected is None:
        return
    normalized = {name.casefold(): digest for name, digest in observed.items()}
    if normalized != expected:
        raise RebuildError(
            f"Conjunto/hash de BHDs não corresponde ao BuildID fixado {build_id}."
        )


def _validate_pinned_bdt_backups(
    build_id: str,
    observed: dict[str, tuple[int, str]],
) -> None:
    expected = PINNED_BDT_BACKUPS_BY_BUILD.get(build_id)
    if expected is None:
        return
    normalized = {name.casefold(): value for name, value in observed.items()}
    if normalized != expected:
        raise RebuildError(
            f"Conjunto/tamanho/hash dos backups BDT não corresponde ao BuildID "
            f"fixado {build_id}."
        )


def load_authenticated_archives(
    manifest_path: Path,
    *,
    expected_build_id: str,
) -> tuple[dict, str, Path, tuple[AuthenticatedArchive, ...]]:
    manifest_path = manifest_path.resolve(strict=True)
    manifest, manifest_digest = _load_json_regular(
        manifest_path, label="Manifesto de backup"
    )
    if manifest.get("schema") != engine.BACKUP_SCHEMA:
        raise RebuildError("Schema do manifesto de backup não suportado.")
    if manifest.get("state") != "applied":
        raise RebuildError(
            "O backup precisa estar no estado 'applied' para representar o vanilla "
            "anterior ao patch."
        )
    fingerprint = manifest.get("build_fingerprint")
    if not isinstance(fingerprint, str) or not HEX_SHA256_RE.fullmatch(fingerprint):
        raise RebuildError("Fingerprint de build inválido no manifesto.")
    if manifest_path.parent.name != fingerprint:
        raise RebuildError("Diretório e fingerprint do manifesto não correspondem.")

    game_dir_value = manifest.get("game_dir")
    if not isinstance(game_dir_value, str) or not game_dir_value:
        raise RebuildError("Pasta do jogo ausente no manifesto de backup.")
    game_dir = Path(game_dir_value).resolve(strict=True)
    sd_dir = game_dir / "sd"
    if not sd_dir.is_dir():
        raise RebuildError(f"Pasta sd do jogo ausente: {sd_dir}")
    build_id = _steam_build_id(game_dir)
    if build_id != expected_build_id:
        raise RebuildError(
            f"Build Steam incompatível: {build_id}; esperado {expected_build_id}."
        )

    raw_records = manifest.get("archives")
    if not isinstance(raw_records, list) or not raw_records:
        raise RebuildError("Manifesto sem arquivos de backup.")
    archives: list[AuthenticatedArchive] = []
    observed_bhd_digests: dict[str, str] = {}
    observed_bdt_backups: dict[str, tuple[int, str]] = {}
    seen_names: set[str] = set()
    for raw in raw_records:
        if not isinstance(raw, dict):
            raise RebuildError("Registro de arquivo inválido no manifesto.")
        bdt_name = raw.get("bdt")
        bhd_name = raw.get("bhd")
        backup_name = raw.get("backup")
        if not all(isinstance(value, str) for value in (bdt_name, bhd_name, backup_name)):
            raise RebuildError("Nomes de arquivo inválidos no manifesto.")
        stem = Path(bdt_name).stem
        if (
            not ARCHIVE_RECORD_RE.fullmatch(stem)
            or bhd_name != f"{stem}.bhd"
            or backup_name != f"{stem}.bdt.backup"
            or Path(bdt_name).name != bdt_name
        ):
            raise RebuildError(f"Par BHD/BDT inseguro no manifesto: {raw!r}")
        key = stem.casefold()
        if key in seen_names:
            raise RebuildError(f"Arquivo duplicado no manifesto: {stem}")
        seen_names.add(key)

        expected_bhd = raw.get("bhd_sha256")
        expected_backup = raw.get("sha256")
        expected_size = raw.get("bdt_size")
        if (
            not isinstance(expected_bhd, str)
            or not HEX_SHA256_RE.fullmatch(expected_bhd)
            or not isinstance(expected_backup, str)
            or not HEX_SHA256_RE.fullmatch(expected_backup)
            or not isinstance(expected_size, int)
            or expected_size <= 0
        ):
            raise RebuildError(f"Metadados criptográficos inválidos para {stem}.")
        pinned_backups = PINNED_BDT_BACKUPS_BY_BUILD.get(expected_build_id)
        if pinned_backups is not None and pinned_backups.get(key) != (
            expected_size,
            expected_backup,
        ):
            raise RebuildError(
                f"Tamanho/SHA-256 declarado de {backup_name} não corresponde ao "
                f"BuildID fixado {expected_build_id}."
            )

        bhd_path = sd_dir / bhd_name
        backup_path = manifest_path.parent / backup_name
        bhd_data, actual_bhd = _read_regular_bytes(
            bhd_path, label=f"Índice ativo {bhd_name}"
        )
        if actual_bhd != expected_bhd:
            raise RebuildError(
                f"SHA-256 do {bhd_name} não corresponde ao manifesto de backup."
            )
        observed_bhd_digests[key] = actual_bhd
        pinned_bhds = PINNED_BHD_SHA256_BY_BUILD.get(expected_build_id)
        if pinned_bhds is not None and pinned_bhds.get(key) != actual_bhd:
            raise RebuildError(
                f"SHA-256 do {bhd_name} não corresponde ao BuildID fixado "
                f"{expected_build_id}."
            )
        backup_snapshot = _snapshot_regular(
            backup_path, label=f"Backup vanilla {backup_name}"
        )
        if backup_snapshot.size != expected_size:
            raise RebuildError(
                f"Tamanho do {backup_name} é {backup_snapshot.size}; esperado {expected_size}."
            )
        actual_backup, _ = _sha256_regular(
            backup_path,
            label=f"Backup vanilla {backup_name}",
            expected=backup_snapshot,
        )
        if actual_backup != expected_backup:
            raise RebuildError(
                f"SHA-256 do backup vanilla {backup_name} não corresponde ao manifesto."
            )
        observed_bdt_backups[key] = (backup_snapshot.size, actual_backup)

        decrypted_bhd = _decrypt_authenticated_bhd(bhd_data, name=bhd_name)
        try:
            entries = engine.parse_bhd5(decrypted_bhd, bdt_size=expected_size)
            salt = engine.parse_bhd5_salt(decrypted_bhd)
        except engine.PatcherError as exc:
            raise RebuildError(f"Índice {bhd_name} inválido: {exc}") from exc
        archives.append(
            AuthenticatedArchive(
                name=stem,
                bhd_path=bhd_path,
                backup_path=backup_path,
                bhd_sha256=actual_bhd,
                backup_sha256=actual_backup,
                snapshot=backup_snapshot,
                entries=entries,
                salt=salt,
            )
        )
    _validate_pinned_bhd_digests(expected_build_id, observed_bhd_digests)
    _validate_pinned_bdt_backups(expected_build_id, observed_bdt_backups)
    return manifest, manifest_digest, game_dir, tuple(archives)


def _payload_files(payload_root: Path, suffix: str) -> tuple[Path, ...]:
    return tuple(
        sorted(
            (
                path
                for path in payload_root.rglob("*")
                if path.is_file() and path.suffix.casefold() == suffix
            ),
            key=lambda item: item.relative_to(payload_root).as_posix().casefold(),
        )
    )


def collect_external_wem_ids(payload_root: Path) -> tuple[frozenset[int], str]:
    files = _payload_files(payload_root, ".wem")
    if not files:
        raise RebuildError("Payload não contém WEMs externos.")
    ids: set[int] = set()
    relative_names: list[str] = []
    for path in files:
        relative = path.relative_to(payload_root).as_posix()
        if not path.stem.isdecimal():
            raise RebuildError(f"Nome de WEM não numérico: {relative}")
        media_id = int(path.stem, 10)
        if not 0 <= media_id <= 0xFFFFFFFF:
            raise RebuildError(f"ID WEM fora de 32 bits: {relative}")
        ids.add(media_id)
        relative_names.append(relative)
    if len(ids) != len(files):
        raise RebuildError(
            "Payload possui IDs WEM duplicados em caminhos diferentes: "
            f"{len(files)} arquivos, {len(ids)} IDs únicos."
        )
    digest = hashlib.sha256()
    for relative in relative_names:
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
    return frozenset(ids), digest.hexdigest()


def _revalidate_historical_payload(
    payload_root: Path,
    *,
    expected_marker_sha256: str,
    expected_wem_ids: frozenset[int],
    expected_wem_name_digest: str,
) -> None:
    marker_sha256 = validate_historical_payload(payload_root)
    if marker_sha256 != expected_marker_sha256:
        raise RebuildError("O marker do payload histórico mudou durante a reconstrução.")
    current_wem_ids, current_wem_name_digest = collect_external_wem_ids(payload_root)
    if (
        current_wem_ids != expected_wem_ids
        or current_wem_name_digest != expected_wem_name_digest
    ):
        raise RebuildError("O conjunto de WEMs externos mudou durante a reconstrução.")


def collect_bank_jobs(
    payload_root: Path,
    archives: Sequence[AuthenticatedArchive],
    *,
    expected_banks: int,
) -> tuple[tuple[BankJob, ...], int, str]:
    paths = _payload_files(payload_root, ".bnk")
    if not paths:
        raise RebuildError("Payload não contém BNKs.")
    entry_map: dict[int, list[BankTarget]] = {}
    for archive in archives:
        for entry in archive.entries:
            entry_map.setdefault(entry.file_name_hash, []).append(
                BankTarget(archive, entry)
            )

    grouped: dict[tuple[str, int], list[tuple[str, PayloadBank]]] = {}
    input_tree = hashlib.sha256()
    for path in paths:
        relative = path.relative_to(payload_root).as_posix()
        snapshot = _snapshot_regular(path, label=f"BNK do payload {relative}")
        data, digest = _read_regular_bytes(path, label=f"BNK do payload {relative}")
        _assert_unchanged(path, snapshot, label=f"BNK do payload {relative}")
        payload_bank = PayloadBank(path, relative, data, digest, snapshot)
        input_tree.update(relative.encode("utf-8"))
        input_tree.update(b"\0")
        input_tree.update(bytes.fromhex(digest))

        selected: tuple[str, list[BankTarget]] | None = None
        for candidate in engine.PatchEngine._candidate_game_paths(
            relative, ".bnk", path.stem
        ):
            targets = entry_map.get(engine.hash_path(candidate))
            if targets:
                selected = (candidate, targets)
                break
        if selected is None:
            raise RebuildError(f"BNK sem alvo no BHD 1.17.1: {relative}")
        game_path, targets = selected
        for target in targets:
            key = (target.archive.name.casefold(), target.entry.file_offset)
            grouped.setdefault(key, []).append((game_path, payload_bank))

    jobs: list[BankJob] = []
    output_paths: dict[str, tuple[str, int]] = {}
    for key, items in grouped.items():
        game_paths = {item[0].casefold() for item in items}
        digests = {item[1].sha256 for item in items}
        if len(game_paths) != 1:
            raise RebuildError(f"Um slot recebeu caminhos divergentes: {sorted(game_paths)}")
        if len(digests) != 1:
            raise RebuildError(
                "Aliases do payload possuem BNKs diferentes para o mesmo slot: "
                + ", ".join(sorted(item[1].relative for item in items))
            )
        target_archive_name, target_offset = key
        target = next(
            candidate
            for candidate in (
                BankTarget(archive, entry)
                for archive in archives
                for entry in archive.entries
            )
            if candidate.archive.name.casefold() == target_archive_name
            and candidate.entry.file_offset == target_offset
        )
        canonical_game_path = items[0][0].replace("\\", "/").strip("/")
        aliases = {item[1].relative for item in items}
        basename = Path(canonical_game_path).name
        expected_aliases = {basename, f"enus/{basename}"}
        if aliases != expected_aliases:
            raise RebuildError(
                f"Aliases root/enus incompletos para {canonical_game_path}: "
                f"{sorted(aliases)}; esperado {sorted(expected_aliases)}."
            )
        output_key = canonical_game_path.casefold()
        previous_target = output_paths.get(output_key)
        if previous_target is not None and previous_target != key:
            raise RebuildError(
                f"O caminho {canonical_game_path} corresponde a mais de um slot físico."
            )
        output_paths[output_key] = key
        jobs.append(
            BankJob(
                game_path=canonical_game_path,
                sources=tuple(sorted((item[1] for item in items), key=lambda x: x.relative)),
                target=target,
            )
        )

    jobs.sort(key=lambda item: item.game_path.casefold())
    if len(jobs) != expected_banks:
        raise RebuildError(
            f"Quantidade de bancos físicos inesperada: {len(jobs)}; "
            f"esperado {expected_banks}."
        )
    return tuple(jobs), len(paths), input_tree.hexdigest()


def _section_map(data: bytes) -> tuple[tuple[bnk.BnkSection, ...], dict[bytes, bnk.BnkSection]]:
    sections = bnk.parse_bnk(data)
    return sections, {item.chunk_id: item for item in sections}


def _bank_identity(sections: dict[bytes, bnk.BnkSection]) -> tuple[int, int]:
    header = sections[b"BKHD"].data
    if len(header) < 8:
        raise RebuildError("BKHD truncado durante a validação final.")
    return struct.unpack_from("<II", header)


def _media_map(sections: dict[bytes, bnk.BnkSection]) -> dict[int, bytes]:
    if b"DIDX" not in sections:
        return {}
    didx = sections[b"DIDX"].data
    data = sections[b"DATA"].data
    if len(didx) % 12:
        raise RebuildError("DIDX inválido durante a validação final.")
    result: dict[int, bytes] = {}
    for offset in range(0, len(didx), 12):
        media_id, data_offset, size = struct.unpack_from("<III", didx, offset)
        end = data_offset + size
        if media_id in result or end > len(data):
            raise RebuildError("DIDX duplicado ou fora de DATA na validação final.")
        result[media_id] = data[data_offset:end]
    return result


def validate_merged_bank(
    vanilla: bytes,
    payload: bytes,
    merged: bytes,
    *,
    external_wem_ids: frozenset[int],
) -> dict[str, int | list[int]]:
    try:
        vanilla_order, vanilla_sections = _section_map(vanilla)
        _payload_order, payload_sections = _section_map(payload)
        merged_order, merged_sections = _section_map(merged)
        vanilla_objects = bnk.parse_hirc(vanilla_sections[b"HIRC"].data)
        payload_objects = bnk.parse_hirc(payload_sections[b"HIRC"].data)
        merged_objects = bnk.parse_hirc(merged_sections[b"HIRC"].data)
    except bnk.BnkMergeError as exc:
        raise RebuildError(f"BNK inválido na validação final: {exc}") from exc

    identity = _bank_identity(vanilla_sections)
    if _bank_identity(payload_sections) != identity or _bank_identity(merged_sections) != identity:
        raise RebuildError("Versão/BankID mudou durante a reconstrução.")
    if [item.chunk_id for item in merged_order] != [
        item.chunk_id for item in vanilla_order
    ]:
        raise RebuildError("Ordem/conjunto de chunks do vanilla não foi preservado.")
    for section in vanilla_order:
        if section.chunk_id not in {b"DIDX", b"DATA", b"HIRC"}:
            if merged_sections[section.chunk_id].data != section.data:
                raise RebuildError(
                    f"Chunk estrutural {section.chunk_id!r} do vanilla foi alterado."
                )

    vanilla_signature = [(item.type_id, item.object_id) for item in vanilla_objects]
    merged_signature = [(item.type_id, item.object_id) for item in merged_objects]
    if merged_signature != vanilla_signature:
        raise RebuildError("Lista/ordem de objetos HIRC do vanilla não foi preservada.")
    changed_type_two: list[int] = []
    filtered_type_two: list[int] = []
    payload_sounds = {
        item.object_id: item for item in payload_objects if item.type_id == 2
    }
    for old, new in zip(vanilla_objects, merged_objects, strict=True):
        if old.raw != new.raw:
            if old.type_id != 2:
                raise RebuildError(
                    f"Objeto HIRC não-Sound {old.object_id} foi alterado."
                )
            if len(old.raw) < 23 or len(new.raw) != len(old.raw):
                raise RebuildError(
                    f"Objeto Sound {old.object_id} mudou com layout inesperado."
                )
            expected_sound = bytearray(old.raw)
            expected_sound[13] = 2
            wem_id = struct.unpack_from("<I", old.raw, 14)[0]
            if (
                old.raw[13] != 1
                or new.raw[13] != 2
                or new.raw != bytes(expected_sound)
                or wem_id not in external_wem_ids
            ):
                raise RebuildError(
                    f"Objeto Sound {old.object_id} não é uma transição 1->2 "
                    "autorizada por WEM externo."
                )
            changed_type_two.append(old.object_id)
        payload_sound = payload_sounds.get(old.object_id)
        if (
            old.type_id == 2
            and payload_sound is not None
            and old.raw != payload_sound.raw
            and new.raw == old.raw
        ):
            filtered_type_two.append(old.object_id)

    vanilla_media = _media_map(vanilla_sections)
    payload_media = _media_map(payload_sections)
    merged_media = _media_map(merged_sections)
    if set(merged_media) != set(vanilla_media):
        raise RebuildError("Conjunto de mídias DIDX do vanilla não foi preservado.")
    for media_id, media_data in vanilla_media.items():
        expected = payload_media.get(media_id, media_data)
        if merged_media[media_id] != expected:
            raise RebuildError(f"Mídia DIDX {media_id} não corresponde ao merge seguro.")

    # Uma segunda execução com os mesmos insumos precisa produzir os mesmos bytes.
    try:
        repeated = bnk.merge_bnk_with_vanilla(
            vanilla,
            payload,
            external_wem_ids=external_wem_ids,
        )
    except bnk.BnkMergeError as exc:
        raise RebuildError(f"Merge não repetível: {exc}") from exc
    if repeated != merged:
        raise RebuildError("Merge BNK não é determinístico.")

    return {
        "bank_version": identity[0],
        "bank_id": identity[1],
        "hirc_vanilla": len(vanilla_objects),
        "hirc_payload": len(payload_objects),
        "hirc_output": len(merged_objects),
        "sound_objects_changed": len(changed_type_two),
        "sound_object_ids_changed": sorted(changed_type_two),
        "sound_objects_filtered": len(filtered_type_two),
        "sound_object_ids_filtered": sorted(filtered_type_two),
        "hirc_preserved_missing_from_payload": sum(
            (
                Counter(vanilla_signature) - Counter(
                    (item.type_id, item.object_id) for item in payload_objects
                )
            ).values()
        ),
        "media_vanilla": len(vanilla_media),
        "media_payload": len(payload_media),
        "media_output": len(merged_media),
        "media_replaced": sum(
            1
            for media_id, old in vanilla_media.items()
            if media_id in payload_media and payload_media[media_id] != old
        ),
        "media_preserved_missing_from_payload": len(
            set(vanilla_media) - set(payload_media)
        ),
    }


def _safe_output_relative(relative_path: str) -> Path:
    normalized = relative_path.replace("\\", "/").strip("/")
    relative = Path(*normalized.split("/"))
    is_root_bank = len(relative.parts) == 1
    is_enus_bank = len(relative.parts) == 2 and relative.parts[0].casefold() == "enus"
    if (
        not (is_root_bank or is_enus_bank)
        or relative.suffix.casefold() != ".bnk"
        or relative.is_absolute()
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise RebuildError(f"Caminho de saída BNK inseguro: {relative_path!r}")
    return relative


def _assert_protected_directories(
    protected: Sequence[tuple[Path, DirectorySnapshot]],
) -> None:
    seen: set[Path] = set()
    for path, snapshot in protected:
        absolute = _absolute_without_resolving(path)
        if absolute in seen:
            continue
        seen.add(absolute)
        _assert_directory_unchanged(
            absolute,
            snapshot,
            label=f"Diretório protegido {absolute}",
        )


def _write_exclusive_regular(
    path: Path,
    data: bytes,
    *,
    label: str,
    protected_directories: Sequence[tuple[Path, DirectorySnapshot]],
) -> FileSnapshot:
    """Create a file exclusively and bind its descriptor to its lexical path."""

    path = _absolute_without_resolving(path)
    _assert_protected_directories(protected_directories)
    if os.path.lexists(path):
        raise RebuildError(f"{label} já existe e não será sobrescrito: {path}")
    try:
        stream = path.open("xb")
    except FileExistsError as exc:
        raise RebuildError(f"{label} apareceu durante a criação: {path}") from exc
    except OSError as exc:
        raise RebuildError(f"Não foi possível criar {label} {path}: {exc}") from exc

    try:
        opened = os.fstat(stream.fileno())
        current = path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or _is_reparse(current)
            or opened.st_nlink != 1
            or current.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise RebuildError(f"{label} mudou ou possui link/reparse: {path}")
        _assert_protected_directories(protected_directories)
        written = stream.write(data)
        if written != len(data):
            raise RebuildError(
                f"Escrita incompleta de {label}: {written} de {len(data)} bytes."
            )
        stream.flush()
        os.fsync(stream.fileno())
        opened_after = os.fstat(stream.fileno())
        current_after = path.lstat()
        if (
            not stat.S_ISREG(opened_after.st_mode)
            or not stat.S_ISREG(current_after.st_mode)
            or _is_reparse(current_after)
            or opened_after.st_nlink != 1
            or current_after.st_nlink != 1
            or opened_after.st_size != len(data)
            or current_after.st_size != len(data)
            or (opened_after.st_dev, opened_after.st_ino)
            != (current_after.st_dev, current_after.st_ino)
        ):
            raise RebuildError(f"{label} mudou durante a gravação: {path}")
        final_snapshot = FileSnapshot(
            device=opened_after.st_dev,
            inode=opened_after.st_ino,
            size=opened_after.st_size,
            mtime_ns=opened_after.st_mtime_ns,
        )
    except OSError as exc:
        raise RebuildError(f"Falha ao gravar {label} {path}: {exc}") from exc
    finally:
        stream.close()

    _assert_unchanged(path, final_snapshot, label=label)
    _assert_protected_directories(protected_directories)
    return final_snapshot


def _validate_staging_tree(
    staging: Path,
    *,
    expected_files: Mapping[Path, tuple[FileSnapshot, str]],
    expected_directories: Mapping[Path, DirectorySnapshot],
) -> None:
    """Require the exact directory/file inventory and every recorded digest."""

    files = {
        _absolute_without_resolving(path): value
        for path, value in expected_files.items()
    }
    directories = {
        _absolute_without_resolving(path): snapshot
        for path, snapshot in expected_directories.items()
    }
    staging = _absolute_without_resolving(staging)
    if staging not in directories:
        raise RebuildError("O staging raiz não possui identidade registrada.")

    seen_files: set[Path] = set()
    seen_directories: set[Path] = set()
    pending = [staging]
    while pending:
        current = pending.pop()
        expected_directory = directories.get(current)
        if expected_directory is None:
            raise RebuildError(f"Diretório inesperado no staging: {current}")
        _assert_directory_unchanged(
            current,
            expected_directory,
            label="Diretório do staging",
        )
        seen_directories.add(current)
        try:
            children = tuple(current.iterdir())
        except OSError as exc:
            raise RebuildError(f"Falha ao enumerar o staging {current}: {exc}") from exc
        _assert_directory_unchanged(
            current,
            expected_directory,
            label="Diretório do staging",
        )
        for child in children:
            child = _absolute_without_resolving(child)
            try:
                metadata = child.lstat()
            except OSError as exc:
                raise RebuildError(
                    f"Entrada do staging mudou durante a enumeração: {child}: {exc}"
                ) from exc
            if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
                raise RebuildError(f"Link/reparse inesperado no staging: {child}")
            if stat.S_ISDIR(metadata.st_mode):
                if child not in directories:
                    raise RebuildError(f"Diretório inesperado no staging: {child}")
                pending.append(child)
                continue
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise RebuildError(f"Arquivo inseguro no staging: {child}")
            if child not in files:
                raise RebuildError(f"Arquivo inesperado no staging: {child}")
            seen_files.add(child)

    if seen_directories != set(directories):
        raise RebuildError("O conjunto de diretórios do staging está incompleto.")
    if seen_files != set(files):
        raise RebuildError("O conjunto de arquivos do staging está incompleto.")
    for path, (snapshot, expected_digest) in files.items():
        actual_digest, _snapshot = _sha256_regular(
            path,
            label=f"Arquivo final do staging {path.name}",
            expected=snapshot,
        )
        if actual_digest != expected_digest:
            raise RebuildError(f"SHA-256 final do staging diverge: {path}")
    for path, snapshot in directories.items():
        _assert_directory_unchanged(
            path,
            snapshot,
            label="Diretório final do staging",
        )


def _path_overlaps(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _rename_directory_no_replace(source: Path, destination: Path) -> None:
    """Atomically move a directory without replacing a racing destination."""

    source = _absolute_without_resolving(source)
    destination = _absolute_without_resolving(destination)
    if os.name == "nt":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        move_file_ex = kernel32.MoveFileExW
        move_file_ex.argtypes = (
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
        )
        move_file_ex.restype = ctypes.c_int
        ctypes.set_last_error(0)
        # Zero deliberately omits MOVEFILE_REPLACE_EXISTING and
        # MOVEFILE_COPY_ALLOWED. Staging and destination share one parent.
        if not move_file_ex(str(source), str(destination), 0):
            raise ctypes.WinError(ctypes.get_last_error())
        return

    if sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        try:
            renameat2 = libc.renameat2
        except AttributeError as exc:
            raise RebuildError(
                "Este Linux não expõe renameat2(RENAME_NOREPLACE); publicação "
                "atômica segura indisponível."
            ) from exc
        renameat2.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        renameat2.restype = ctypes.c_int
        ctypes.set_errno(0)
        at_fdcwd = -100
        rename_noreplace = 1
        result = renameat2(
            at_fdcwd,
            os.fsencode(source),
            at_fdcwd,
            os.fsencode(destination),
            rename_noreplace,
        )
        if result != 0:
            error_number = ctypes.get_errno()
            raise OSError(
                error_number,
                os.strerror(error_number),
                str(destination),
            )
        return

    raise RebuildError(
        f"Publicação atômica no-replace não suportada nesta plataforma: {sys.platform}."
    )


def _publish_new_directory(
    staging: Path,
    output: Path,
    *,
    output_parent_snapshot: DirectorySnapshot,
    staging_snapshot: DirectorySnapshot,
    expected_files: Mapping[Path, tuple[FileSnapshot, str]],
    expected_directories: Mapping[Path, DirectorySnapshot],
) -> None:
    _assert_directory_unchanged(
        output.parent,
        output_parent_snapshot,
        label="Diretório pai da saída",
    )
    _assert_directory_unchanged(
        staging,
        staging_snapshot,
        label="Staging da reconstrução",
    )
    _validate_staging_tree(
        staging,
        expected_files=expected_files,
        expected_directories=expected_directories,
    )
    _assert_directory_unchanged(
        output.parent,
        output_parent_snapshot,
        label="Diretório pai da saída",
    )
    _assert_directory_unchanged(
        staging,
        staging_snapshot,
        label="Staging da reconstrução",
    )
    if output.exists() or os.path.lexists(output):
        raise RebuildError(f"O diretório de saída já existe: {output}")
    try:
        _rename_directory_no_replace(staging, output)
    except OSError as exc:
        raise RebuildError(f"Não foi possível publicar {output}: {exc}") from exc

    # The directory move is the publication boundary, not proof that the bytes
    # validated under the staging name are still the bytes now exposed under
    # the final name.  Bind the final path to the exact staging inode and hash
    # the complete inventory again.  A failure deliberately leaves ``output``
    # untouched so it can be inspected; callers must treat the raised error as
    # an explicit indication that the published-looking directory is invalid.
    def published_path(path: Path) -> Path:
        absolute = _absolute_without_resolving(path)
        try:
            relative = absolute.relative_to(staging)
        except ValueError as exc:
            raise RebuildError(
                f"Caminho registrado fora do staging: {absolute}"
            ) from exc
        return _absolute_without_resolving(output / relative)

    published_files = {
        published_path(path): value for path, value in expected_files.items()
    }
    published_directories = {
        published_path(path): snapshot
        for path, snapshot in expected_directories.items()
    }
    try:
        _assert_directory_unchanged(
            output,
            staging_snapshot,
            label="Saída recém-publicada",
        )
        _validate_staging_tree(
            output,
            expected_files=published_files,
            expected_directories=published_directories,
        )
        _assert_directory_unchanged(
            output.parent,
            output_parent_snapshot,
            label="Diretório pai da saída publicada",
        )
        _assert_directory_unchanged(
            output,
            staging_snapshot,
            label="Saída final validada",
        )
    except Exception as exc:
        raise RebuildError(
            "Falha na validação criptográfica pós-publicação; a saída inválida "
            f"foi preservada para diagnóstico e não deve ser usada: {output}: {exc}"
        ) from exc


def _banks_digest(records: Iterable[dict]) -> str:
    digest = hashlib.sha256()
    for record in sorted(records, key=lambda item: str(item["output_path"]).casefold()):
        digest.update(str(record["output_path"]).encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(str(record["output_sha256"])))
    return digest.hexdigest()


def _alias_tree_digest(records: Iterable[dict]) -> str:
    digest = hashlib.sha256()
    aliases: list[tuple[str, str]] = []
    for record in records:
        aliases.extend(
            (str(relative), str(record["output_sha256"]))
            for relative in record["output_aliases"]
        )
    for relative, output_sha256 in sorted(aliases, key=lambda item: item[0].casefold()):
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(output_sha256))
    return digest.hexdigest()


def _sound_object_identity(
    records: Sequence[dict],
    field: str,
) -> tuple[int, str]:
    """Hash bank path + every sorted HIRC object id for a reproducible identity."""

    digest = hashlib.sha256()
    count = 0
    for record in sorted(
        records,
        key=lambda item: (
            str(item["output_path"]).casefold(),
            str(item["output_path"]),
        ),
    ):
        output_path = str(record["output_path"])
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
            raise RebuildError(
                f"Lista {field!r} inválida no banco {output_path}."
            )
        for object_id in object_ids:
            digest.update(output_path.encode("utf-8"))
            digest.update(b"\0")
            digest.update(struct.pack("<I", object_id))
            count += 1
    return count, digest.hexdigest()


def _named_regressions(records: Sequence[dict]) -> dict:
    by_name = {Path(str(item["game_path"])).stem.casefold(): item for item in records}
    missing = [name for name in ("cs_main", "cs_m41", "vcmain") if name not in by_name]
    if missing:
        raise RebuildError(
            "Bancos obrigatórios da regressão não foram reconstruídos: " + ", ".join(missing)
        )
    cs_main = by_name["cs_main"]
    cs_m41 = by_name["cs_m41"]
    vcmain = by_name["vcmain"]
    checks = (
        (
            int(cs_main["media_preserved_missing_from_payload"]),
            3,
            "cs_main DIDX preservados",
        ),
        (
            int(cs_main["hirc_preserved_missing_from_payload"]),
            234,
            "cs_main HIRC preservados",
        ),
        (
            int(cs_m41["media_preserved_missing_from_payload"]),
            5,
            "cs_m41 DIDX preservados",
        ),
        (
            int(vcmain["sound_objects_filtered"]),
            52,
            "vcmain Type2 filtrados",
        ),
    )
    for actual, expected, label in checks:
        if actual != expected:
            raise RebuildError(f"{label}: {actual}; esperado {expected}.")
    vcmain_ids = vcmain["sound_object_ids_filtered"]
    if tuple(vcmain_ids) != EXPECTED_VCMAIN_FILTERED_IDS:
        raise RebuildError(
            "A identidade dos 52 objetos Type2 filtrados de vcmain diverge."
        )
    return {
        "cs_main": {
            "didx_preserved_missing_from_old_payload": 3,
            "hirc_preserved_missing_from_old_payload": 234,
        },
        "cs_m41": {"didx_preserved_missing_from_old_payload": 5},
        "vcmain": {
            "type2_stale_objects_filtered_and_kept_vanilla": 52,
            "type2_object_ids": vcmain_ids,
        },
    }


def _report(document: dict) -> str:
    metrics = document["metrics"]
    return "\n".join(
        (
            "# Reconstrução BNK do ERPT-BR para Elden Ring 1.17.1",
            "",
            "**Estado: ARTEFATO OFFLINE — NÃO APLICADO AO JOGO.**",
            "",
            "Os bancos foram reconstruídos usando o backup vanilla autenticado como "
            "autoridade estrutural. Este diretório contém BNKs soltos e não contém nem "
            "substitui arquivos BDT do jogo.",
            "",
            f"- Steam BuildID: `{document['target']['steam_build_id']}`",
            f"- Fingerprint do backup: `{document['target']['build_fingerprint']}`",
            f"- BNKs físicos reconstruídos: {metrics['banks_rebuilt']}",
            f"- Aliases BNK verificados: {metrics['bank_aliases_verified']}",
            f"- Arquivos BNK de saída (root + enus): {metrics['output_alias_files']}",
            f"- Pares root/enus byte a byte idênticos: {metrics['identical_alias_pairs']}",
            f"- IDs WEM externos conhecidos: {metrics['external_wem_ids']}",
            f"- Objetos HIRC vanilla preservados: {metrics['hirc_objects_preserved']}",
            f"- Objetos Sound ajustados: {metrics['sound_objects_changed']}",
            f"- Mídias DIDX vanilla preservadas: {metrics['media_preserved']}",
            f"- Mídias incorporadas substituídas: {metrics['media_replaced']}",
            "- `cs_main.bnk`: 3 DIDX e 234 HIRC novos preservados do vanilla",
            "- `cs_m41.bnk`: 5 DIDX novos preservados do vanilla",
            "- `vcmain.bnk`: 52 objetos Type2 obsoletos do payload filtrados; "
            "objetos vanilla mantidos",
            f"- SHA-256 agregado dos BNKs: `{document['output']['banks_sha256']}`",
            "",
            "## Limite de segurança",
            "",
            "Os hashes salted armazenados no BHD continuam sendo autoridade do jogo. "
            "Não copie estes bancos para um BDT nem anuncie compatibilidade online sem "
            "uma estratégia autenticada para o arquivo e testes separados com EAC.",
            "",
            "Consulte `manifest.json` para hashes e métricas de cada banco.",
            "",
        )
    )


def rebuild(
    *,
    manifest_path: Path,
    payload_root: Path,
    output: Path,
    expected_banks: int = DEFAULT_EXPECTED_BANKS,
    expected_build_id: str = DEFAULT_EXPECTED_BUILD_ID,
    game_version: str = DEFAULT_GAME_VERSION,
) -> dict:
    payload_root = payload_root.resolve(strict=True)
    output = _absolute_without_resolving(output)
    _ensure_safe_directory_tree(
        output.parent,
        label="Árvore pai da saída",
        create=False,
    )
    manifest_path = manifest_path.resolve(strict=True)
    manifest, manifest_digest, game_dir, archives = load_authenticated_archives(
        manifest_path,
        expected_build_id=expected_build_id,
    )
    try:
        backup_root = manifest_path.parents[2]
    except IndexError as exc:
        raise RebuildError(f"Caminho de manifesto inesperado: {manifest_path}") from exc
    for protected in (game_dir, backup_root, payload_root):
        if _path_overlaps(output, protected.resolve()):
            raise RebuildError(
                f"Saída não pode coincidir nem se sobrepor a uma origem protegida: {protected}"
            )
    if output.exists() or os.path.lexists(output):
        raise RebuildError(f"O diretório de saída já existe: {output}")
    output_parent = _ensure_safe_directory_tree(
        output.parent,
        label="Árvore pai da saída",
        create=True,
    )
    output_parent_snapshot = _snapshot_directory(
        output_parent,
        label="Diretório pai da saída",
    )

    historical_marker_sha256 = validate_historical_payload(payload_root)
    external_wem_ids, wem_name_digest = collect_external_wem_ids(payload_root)
    jobs, bank_alias_count, input_bank_digest = collect_bank_jobs(
        payload_root,
        archives,
        expected_banks=expected_banks,
    )

    _assert_directory_unchanged(
        output_parent,
        output_parent_snapshot,
        label="Diretório pai da saída",
    )
    staging = output_parent / f".{output.name}.{uuid.uuid4().hex}.staging"
    try:
        staging.mkdir()
    except FileExistsError as exc:
        raise RebuildError(f"Staging exclusivo já existe: {staging}") from exc
    except OSError as exc:
        raise RebuildError(f"Não foi possível criar o staging {staging}: {exc}") from exc
    staging_snapshot = _snapshot_directory(
        staging,
        label="Staging da reconstrução",
    )
    _assert_directory_unchanged(
        output_parent,
        output_parent_snapshot,
        label="Diretório pai da saída",
    )
    output_directories: dict[Path, DirectorySnapshot] = {
        staging: staging_snapshot,
    }
    output_files: dict[Path, tuple[FileSnapshot, str]] = {}
    records: list[dict] = []
    try:
        with ExitStack() as stack:
            streams = {
                archive.name: stack.enter_context(archive.backup_path.open("rb"))
                for archive in archives
            }
            for archive in archives:
                opened = os.fstat(streams[archive.name].fileno())
                if not _matches_file_snapshot(opened, archive.snapshot):
                    raise RebuildError(
                        f"Backup {archive.backup_path.name} mudou durante a abertura."
                    )
            for index, job in enumerate(jobs, start=1):
                archive = job.target.archive
                entry = job.target.entry
                stream = streams[archive.name]
                stream.seek(entry.file_offset)
                encrypted = stream.read(entry.padded_file_size)
                if len(encrypted) != entry.padded_file_size:
                    raise RebuildError(
                        f"Leitura incompleta do slot {job.game_path} em {archive.name}."
                    )
                if entry.sha_info is None:
                    raise RebuildError(f"Slot sem SHA salted: {job.game_path}")
                actual = engine.calculate_bhd5_salted_sha256(
                    encrypted, archive.salt, entry.sha_info.ranges
                )
                if actual != entry.sha_info.hash_bytes:
                    raise RebuildError(
                        f"Slot vanilla não autenticado pelo BHD: {job.game_path}"
                    )
                baseline = bytearray(encrypted)
                if entry.aes_info and entry.aes_info.ranges:
                    engine.decrypt_aes_ecb(
                        baseline, entry.aes_info.key, entry.aes_info.ranges
                    )
                vanilla = bytes(baseline[: entry.unpadded_file_size])
                payload = job.sources[0].data
                try:
                    merged = bnk.merge_bnk_with_vanilla(
                        vanilla,
                        payload,
                        external_wem_ids=external_wem_ids,
                    )
                except bnk.BnkMergeError as exc:
                    raise RebuildError(f"Falha no merge de {job.game_path}: {exc}") from exc
                if len(merged) > entry.unpadded_file_size:
                    raise RebuildError(
                        f"BNK reconstruído excede o slot lógico em {job.game_path}: "
                        f"{len(merged)} > {entry.unpadded_file_size}."
                    )
                if len(merged) != len(vanilla):
                    raise RebuildError(
                        f"BNK reconstruído mudou o tamanho lógico em {job.game_path}: "
                        f"{len(merged)} != {len(vanilla)}. Saída não será publicada."
                    )
                try:
                    prepared = engine.prepare_slot(merged, ".bnk", entry)
                except engine.PatcherError as exc:
                    raise RebuildError(
                        f"BNK reconstruído não cabe no slot físico {job.game_path}: {exc}"
                    ) from exc
                if len(prepared) != entry.padded_file_size:
                    raise RebuildError(f"Slot físico incorreto para {job.game_path}.")
                validation = validate_merged_bank(
                    vanilla,
                    payload,
                    merged,
                    external_wem_ids=external_wem_ids,
                )

                output_digest = hashlib.sha256(merged).hexdigest()
                output_aliases = [item.relative for item in job.sources]
                for alias in output_aliases:
                    relative = _safe_output_relative(alias)
                    destination = staging / relative
                    destination_parent = _absolute_without_resolving(
                        destination.parent
                    )
                    if destination_parent not in output_directories:
                        _assert_protected_directories(
                            (
                                (output_parent, output_parent_snapshot),
                                (staging, staging_snapshot),
                            )
                        )
                        _ensure_safe_directory_tree(
                            destination_parent,
                            label="Árvore interna do staging",
                            create=True,
                        )
                        output_directories[destination_parent] = _snapshot_directory(
                            destination_parent,
                            label="Diretório interno do staging",
                        )
                    protected_directories = (
                        (output_parent, output_parent_snapshot),
                        (staging, staging_snapshot),
                        (
                            destination_parent,
                            output_directories[destination_parent],
                        ),
                    )
                    written_snapshot = _write_exclusive_regular(
                        destination,
                        merged,
                        label=f"BNK reconstruído {relative.as_posix()}",
                        protected_directories=protected_directories,
                    )
                    written_digest, _written_snapshot = _sha256_regular(
                        destination,
                        label=f"BNK reconstruído {relative.as_posix()}",
                        expected=written_snapshot,
                    )
                    if written_digest != output_digest:
                        raise RebuildError(
                            f"Falha ao validar saída recém-gravada: {relative}"
                        )
                    output_files[_absolute_without_resolving(destination)] = (
                        written_snapshot,
                        output_digest,
                    )
                record = {
                    "output_path": job.game_path,
                    "output_aliases": output_aliases,
                    "output_aliases_identical": True,
                    "game_path": job.game_path,
                    "archive": f"{archive.name}.bdt",
                    "file_name_hash": f"0x{entry.file_name_hash:016x}",
                    "file_offset": entry.file_offset,
                    "slot_logical_size": entry.unpadded_file_size,
                    "slot_physical_size": entry.padded_file_size,
                    "source_aliases": [item.relative for item in job.sources],
                    "vanilla_size": len(vanilla),
                    "payload_size": len(payload),
                    "output_size": len(merged),
                    "vanilla_sha256": hashlib.sha256(vanilla).hexdigest(),
                    "payload_sha256": job.sources[0].sha256,
                    "output_sha256": output_digest,
                    **validation,
                }
                records.append(record)
                print(f"[{index:03d}/{len(jobs):03d}] {job.game_path}")
        for archive in archives:
            backup_digest, _snapshot = _sha256_regular(
                archive.backup_path,
                label=f"Backup vanilla {archive.backup_path.name}",
                expected=archive.snapshot,
            )
            if backup_digest != archive.backup_sha256:
                raise RebuildError(
                    f"Backup {archive.backup_path.name} mudou durante a reconstrução."
                )
            bhd_digest, _snapshot = _sha256_regular(
                archive.bhd_path, label=f"Índice ativo {archive.bhd_path.name}"
            )
            if bhd_digest != archive.bhd_sha256:
                raise RebuildError(
                    f"Índice {archive.bhd_path.name} mudou durante a reconstrução."
                )
        seen_payload_sources: set[Path] = set()
        for job in jobs:
            for source in job.sources:
                if source.path in seen_payload_sources:
                    continue
                seen_payload_sources.add(source.path)
                _assert_unchanged(
                    source.path,
                    source.snapshot,
                    label=f"BNK do payload {source.relative}",
                )
        _revalidate_historical_payload(
            payload_root,
            expected_marker_sha256=historical_marker_sha256,
            expected_wem_ids=external_wem_ids,
            expected_wem_name_digest=wem_name_digest,
        )

        aggregate_digest = _banks_digest(records)
        alias_tree_digest = _alias_tree_digest(records)
        named_regressions = _named_regressions(records)
        changed_count, changed_ids_digest = _sound_object_identity(
            records, "sound_object_ids_changed"
        )
        filtered_count, filtered_ids_digest = _sound_object_identity(
            records, "sound_object_ids_filtered"
        )
        if (
            changed_count != EXPECTED_CHANGED_SOUND_OBJECTS
            or changed_ids_digest != EXPECTED_CHANGED_SOUND_IDS_SHA256
        ):
            raise RebuildError(
                f"Identidade dos {EXPECTED_CHANGED_SOUND_OBJECTS} objetos Sound "
                "alterados diverge da auditoria."
            )
        if (
            filtered_count != EXPECTED_FILTERED_SOUND_OBJECTS
            or filtered_ids_digest != EXPECTED_FILTERED_SOUND_IDS_SHA256
        ):
            raise RebuildError(
                f"Identidade dos {EXPECTED_FILTERED_SOUND_OBJECTS} objetos Sound "
                "filtrados diverge da auditoria."
            )
        document = {
            "schema": TOOL_SCHEMA,
            "algorithm": ALGORITHM,
            "target": {
                "game": "ELDEN RING",
                "game_version": game_version,
                "steam_build_id": expected_build_id,
                "build_fingerprint": manifest["build_fingerprint"],
            },
            "authority": {
                "backup_manifest_sha256": manifest_digest,
                "archives": [
                    {
                        "bhd": archive.bhd_path.name,
                        "bhd_sha256": archive.bhd_sha256,
                        "backup": archive.backup_path.name,
                        "backup_sha256": archive.backup_sha256,
                        "backup_size": archive.snapshot.size,
                    }
                    for archive in archives
                ],
            },
            "payload_input": {
                "payload_version": patch_data.PRODUCTION_PAYLOAD.version,
                "archive_sha256": patch_data.PRODUCTION_PAYLOAD.sha256,
                "tree_sha256": patch_data.PRODUCTION_PAYLOAD.tree_sha256,
                "marker_sha256": historical_marker_sha256,
                "bank_alias_tree_sha256": input_bank_digest,
                "wem_name_tree_sha256": wem_name_digest,
            },
            "metrics": {
                "banks_rebuilt": len(records),
                "bank_aliases_verified": bank_alias_count,
                "output_alias_files": sum(
                    len(item["output_aliases"]) for item in records
                ),
                "identical_alias_pairs": sum(
                    1 for item in records if item["output_aliases_identical"]
                ),
                "external_wem_ids": len(external_wem_ids),
                "hirc_objects_preserved": sum(
                    int(item["hirc_vanilla"]) for item in records
                ),
                "sound_objects_changed": sum(
                    int(item["sound_objects_changed"]) for item in records
                ),
                "sound_objects_filtered": sum(
                    int(item["sound_objects_filtered"]) for item in records
                ),
                "media_preserved": sum(int(item["media_vanilla"]) for item in records),
                "media_replaced": sum(int(item["media_replaced"]) for item in records),
                "output_bytes": sum(int(item["output_size"]) for item in records),
                "logical_slot_bytes": sum(
                    int(item["slot_logical_size"]) for item in records
                ),
            },
            "output": {
                "banks_sha256": aggregate_digest,
                "alias_tree_sha256": alias_tree_digest,
                "changed_sound_ids_sha256": changed_ids_digest,
                "filtered_sound_ids_sha256": filtered_ids_digest,
                "named_regressions": named_regressions,
                "banks": records,
            },
        }
        manifest_output = staging / "manifest.json"
        protected_staging = (
            (output_parent, output_parent_snapshot),
            (staging, staging_snapshot),
        )
        manifest_bytes = (
            json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        manifest_snapshot = _write_exclusive_regular(
            manifest_output,
            manifest_bytes,
            label="Manifesto da reconstrução",
            protected_directories=protected_staging,
        )
        output_files[_absolute_without_resolving(manifest_output)] = (
            manifest_snapshot,
            hashlib.sha256(manifest_bytes).hexdigest(),
        )
        report_output = staging / "REPORT.md"
        report_bytes = _report(document).encode("utf-8")
        report_snapshot = _write_exclusive_regular(
            report_output,
            report_bytes,
            label="Relatório da reconstrução",
            protected_directories=protected_staging,
        )
        output_files[_absolute_without_resolving(report_output)] = (
            report_snapshot,
            hashlib.sha256(report_bytes).hexdigest(),
        )
        _publish_new_directory(
            staging,
            output,
            output_parent_snapshot=output_parent_snapshot,
            staging_snapshot=staging_snapshot,
            expected_files=output_files,
            expected_directories=output_directories,
        )
        return document
    except Exception as exc:
        # Fail-safe: nunca removemos recursivamente um caminho que poderia ter
        # sido trocado por junction/reparse durante uma execução longa. O
        # staging UUID ou a saída já movida fica preservado para inspeção.
        if os.path.lexists(output) and not os.path.lexists(staging):
            preserved = (
                f"Saída possivelmente inválida preservada para diagnóstico: {output}"
            )
        else:
            preserved = f"Staging incompleto preservado para diagnóstico: {staging}"
        raise RebuildError(
            f"{exc} {preserved}"
        ) from exc


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Reconstrói BNKs sobre backup vanilla autenticado sem modificar o jogo."
        )
    )
    parser.add_argument("--manifest", type=Path, help="manifest.json do backup aplicado")
    parser.add_argument("--backup-root", type=Path, help="raiz para autodetectar o backup")
    parser.add_argument("--payload", type=Path, help="pasta patch_data antiga")
    parser.add_argument("--output", type=Path, required=True, help="diretório novo de saída")
    parser.add_argument(
        "--expected-banks", type=int, default=DEFAULT_EXPECTED_BANKS
    )
    parser.add_argument(
        "--expected-build-id", default=DEFAULT_EXPECTED_BUILD_ID
    )
    parser.add_argument("--game-version", default=DEFAULT_GAME_VERSION)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.expected_banks <= 0:
        raise SystemExit("--expected-banks precisa ser positivo.")
    try:
        manifest_path = args.manifest
        if manifest_path is None:
            manifest_path = discover_manifest(args.backup_root or _default_backup_root())
        payload_root = args.payload or _default_payload_root()
        document = rebuild(
            manifest_path=manifest_path,
            payload_root=payload_root,
            output=args.output,
            expected_banks=args.expected_banks,
            expected_build_id=args.expected_build_id,
            game_version=args.game_version,
        )
    except (RebuildError, engine.PatcherError, bnk.BnkMergeError, OSError) as exc:
        print(f"ERRO SEGURO: {exc}", file=sys.stderr)
        return 2
    metrics = document["metrics"]
    print(
        "Reconstrução concluída sem tocar no jogo: "
        f"{metrics['banks_rebuilt']} BNKs, "
        f"SHA agregado {document['output']['banks_sha256']}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
