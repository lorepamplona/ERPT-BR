from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
import unittest
from unittest import mock
import zipfile


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from patcher import patch_data  # noqa: E402


WEM_BYTES = b"RIFF" + (4).to_bytes(4, "little") + b"WAVE"
BNK_BYTES = b"BKHD"


def canonical_tree_sha256(files: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    for name, data in sorted(files.items(), key=lambda item: item[0].casefold()):
        encoded = name.encode("utf-8")
        digest.update(struct.pack("<I", len(encoded)))
        digest.update(encoded)
        digest.update(struct.pack("<Q", len(data)))
        digest.update(data)
    return digest.hexdigest()


def write_zip(
    path: Path,
    files: dict[str, bytes],
    *,
    infos: list[tuple[zipfile.ZipInfo, bytes]] | None = None,
) -> bytes:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
        for info, data in infos or []:
            archive.writestr(info, data)
    return path.read_bytes()


def make_spec(
    archive_bytes: bytes,
    *,
    wem_count: int = 1,
    bnk_count: int = 1,
    uncompressed_size: int = len(WEM_BYTES) + len(BNK_BYTES),
    max_file_size: int = len(WEM_BYTES),
    url: str | None = "https://example.invalid/patch_data_test.zip",
    tree_files: dict[str, bytes] | None = None,
) -> patch_data.PayloadSpec:
    if tree_files is None:
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
            names = [
                name
                for name in archive.namelist()
                if name.lower().endswith((".wem", ".bnk"))
            ]
            wrapper = bool(names) and all(
                name.startswith("patch_data/") for name in names
            )
            tree_files = {
                (name.removeprefix("patch_data/") if wrapper else name): archive.read(
                    name
                )
                for name in names
            }
    return patch_data.PayloadSpec(
        version="test-v1",
        archive_name="patch_data_test.zip",
        url=url,
        archive_size=len(archive_bytes),
        sha256=hashlib.sha256(archive_bytes).hexdigest(),
        wem_count=wem_count,
        bnk_count=bnk_count,
        uncompressed_size=uncompressed_size,
        max_file_size=max_file_size,
        tree_sha256=canonical_tree_sha256(tree_files),
    )


class FakeResponse(io.BytesIO):
    def __init__(
        self,
        data: bytes,
        *,
        url: str = "https://cdn.example.invalid/payload.zip",
        content_length: str | None = None,
        status: int = 200,
    ) -> None:
        super().__init__(data)
        self._url = url
        self.status = status
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = content_length

    def geturl(self) -> str:
        return self._url

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()


class ProductionManifestTests(unittest.TestCase):
    def test_production_manifest_is_pinned_to_bundled_v094(self) -> None:
        spec = patch_data.PRODUCTION_PAYLOAD
        self.assertEqual(spec.version, "v0.9.4")
        self.assertEqual(spec.archive_name, "patch_data_v094.zip")
        self.assertIsNone(spec.url)
        self.assertEqual(spec.archive_size, 588_468_447)
        self.assertEqual(
            spec.sha256,
            "430e9693a9b3313826e9f7c890cf592eb5b468d145bb405e8a4586002b877680",
        )
        self.assertEqual(spec.wem_count, 8_969)
        self.assertEqual(spec.bnk_count, 272)
        self.assertEqual(spec.file_count, 9_241)
        self.assertEqual(spec.uncompressed_size, 605_706_607)
        self.assertEqual(spec.max_file_size, 74_956_066)
        self.assertEqual(
            spec.tree_sha256,
            "8544e551832c929eecad0cf9898204fd673bd4a37a0a6f37433865afbb3556cb",
        )

    def test_legacy_manifest_remains_explicitly_pinned_to_v081(self) -> None:
        spec = patch_data.LEGACY_PAYLOAD_V081
        self.assertEqual(spec.version, "v0.8.1")
        self.assertEqual(spec.archive_name, "patch_data_v081.zip")
        self.assertEqual(
            spec.url,
            "https://github.com/lorepamplona/ERPT-BR/releases/download/v0.8.1/patch_data_v081.zip",
        )
        self.assertEqual(spec.archive_size, 587_566_572)
        self.assertEqual(
            spec.sha256,
            "d66bb45093e911202f80cebac44650063e27da2cba41a78760b10e4d82d81d0c",
        )
        self.assertEqual(spec.wem_count, 8_969)
        self.assertEqual(spec.bnk_count, 272)
        self.assertEqual(spec.file_count, 9_241)
        self.assertEqual(spec.uncompressed_size, 604_911_847)
        self.assertEqual(spec.max_file_size, 74_897_763)
        self.assertEqual(
            spec.tree_sha256,
            "587533f29239d8dbe2131573e6e86a2452b272e76983f6cfef1a332d7b046417",
        )

    def test_specs_require_https_and_a_valid_digest(self) -> None:
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            patch_data.PayloadSpec(
                "x", "x.zip", "http://example.test/x", 1, "0" * 64, 1, 0, 1, 1, "0" * 64
            )
        with self.assertRaisesRegex(ValueError, "64"):
            patch_data.PayloadSpec(
                "x", "x.zip", "https://example.test/x", 1, "bad", 1, 0, 1, 1, "0" * 64
            )

    def test_specs_allow_an_explicit_bundled_only_payload(self) -> None:
        spec = patch_data.PayloadSpec(
            "x", "x.zip", None, 1, "0" * 64, 1, 0, 1, 1, "0" * 64
        )
        self.assertIsNone(spec.url)


class ArchiveValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def valid_archive(
        self, *, wrapper: bool = False
    ) -> tuple[Path, bytes, patch_data.PayloadSpec]:
        archive_path = self.root / "payload.zip"
        prefix = "patch_data/" if wrapper else ""
        archive_bytes = write_zip(
            archive_path,
            {
                f"{prefix}enus/wem/00/100.wem": WEM_BYTES,
                f"{prefix}enus/voice.bnk": BNK_BYTES,
            },
        )
        return archive_path, archive_bytes, make_spec(archive_bytes)

    def test_validates_archive_and_extracts_wrapper_atomically(self) -> None:
        archive_path, _, spec = self.valid_archive(wrapper=True)
        stats = patch_data.validate_archive(archive_path, spec=spec)
        self.assertEqual((stats.wem_count, stats.bnk_count), (1, 1))

        destination = self.root / "cache" / "patch_data"
        progress: list[tuple[int, int]] = []
        result = patch_data.extract_archive(
            archive_path,
            destination,
            spec=spec,
            progress=lambda current, total: progress.append((current, total)),
        )
        self.assertEqual(result, destination)
        self.assertEqual((destination / "enus/wem/00/100.wem").read_bytes(), WEM_BYTES)
        self.assertEqual((destination / "enus/voice.bnk").read_bytes(), BNK_BYTES)
        self.assertFalse((destination / "patch_data").exists())
        marker = json.loads(
            (destination / patch_data.MARKER_FILENAME).read_text("utf-8")
        )
        self.assertEqual(marker["archive_sha256"], spec.sha256)
        self.assertEqual(marker["file_count"], 2)
        self.assertEqual(progress[-1], (spec.uncompressed_size, spec.uncompressed_size))
        self.assertEqual(
            patch_data.validate_patch_directory(destination, spec=spec),
            stats,
        )

    def test_rejects_wrong_archive_size_and_hash(self) -> None:
        archive_path, archive_bytes, spec = self.valid_archive()
        wrong_size = patch_data.PayloadSpec(
            spec.version,
            spec.archive_name,
            spec.url,
            len(archive_bytes) + 1,
            spec.sha256,
            spec.wem_count,
            spec.bnk_count,
            spec.uncompressed_size,
            spec.max_file_size,
            spec.tree_sha256,
        )
        with self.assertRaisesRegex(
            patch_data.PayloadValidationError, "Tamanho incorreto"
        ):
            patch_data.validate_archive(archive_path, spec=wrong_size)

        wrong_hash = patch_data.PayloadSpec(
            spec.version,
            spec.archive_name,
            spec.url,
            spec.archive_size,
            "0" * 64,
            spec.wem_count,
            spec.bnk_count,
            spec.uncompressed_size,
            spec.max_file_size,
            spec.tree_sha256,
        )
        with self.assertRaisesRegex(
            patch_data.PayloadValidationError, "SHA-256 incorreto"
        ):
            patch_data.validate_archive(archive_path, spec=wrong_hash)

    def test_rejects_manifest_count_total_and_max_mismatches(self) -> None:
        archive_path, archive_bytes, _ = self.valid_archive()
        cases = (
            (make_spec(archive_bytes, wem_count=2, bnk_count=1), "WEM"),
            (make_spec(archive_bytes, uncompressed_size=99), "tamanho descompactado"),
            (make_spec(archive_bytes, max_file_size=99), "maior arquivo"),
        )
        for spec, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(patch_data.PayloadValidationError, message):
                    patch_data.validate_archive(archive_path, spec=spec)

    def test_rejects_unsafe_or_unexpected_zip_entries(self) -> None:
        invalid_names = (
            "../escape.wem",
            "/absolute.wem",
            "C:/drive.wem",
            "enus\\backslash.wem",
            "enus/./dot.wem",
            "enus//empty.wem",
            "enus/readme.txt",
        )
        for index, invalid_name in enumerate(invalid_names):
            with self.subTest(name=invalid_name):
                archive_path = self.root / f"unsafe-{index}.zip"
                archive_bytes = write_zip(
                    archive_path,
                    {
                        "enus/valid.wem": WEM_BYTES,
                        "enus/valid.bnk": BNK_BYTES,
                        invalid_name: b"bad",
                    },
                )
                spec = make_spec(
                    archive_bytes,
                    uncompressed_size=len(WEM_BYTES) + len(BNK_BYTES) + 3,
                    max_file_size=len(WEM_BYTES),
                )
                with self.assertRaises(patch_data.PayloadValidationError):
                    patch_data.validate_archive(archive_path, spec=spec)

    def test_rejects_zip_symlink(self) -> None:
        archive_path = self.root / "symlink.zip"
        link = zipfile.ZipInfo("enus/link.wem")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive_bytes = write_zip(
            archive_path,
            {"enus/valid.wem": WEM_BYTES, "enus/valid.bnk": BNK_BYTES},
            infos=[(link, b"../outside")],
        )
        spec = make_spec(
            archive_bytes,
            uncompressed_size=len(WEM_BYTES) + len(BNK_BYTES) + len(b"../outside"),
            max_file_size=len(WEM_BYTES),
        )
        with self.assertRaisesRegex(patch_data.PayloadValidationError, "simbolico"):
            patch_data.validate_archive(archive_path, spec=spec)

    def test_rejects_duplicate_case_insensitive_destinations(self) -> None:
        archive_path = self.root / "duplicate.zip"
        archive_bytes = write_zip(
            archive_path,
            {
                "enus/SAME.wem": WEM_BYTES,
                "enus/same.WEM": WEM_BYTES,
                "enus/valid.bnk": BNK_BYTES,
            },
        )
        spec = make_spec(
            archive_bytes,
            wem_count=2,
            uncompressed_size=2 * len(WEM_BYTES) + len(BNK_BYTES),
        )
        with self.assertRaisesRegex(
            patch_data.PayloadValidationError, "mesmo destino|duplicado"
        ):
            patch_data.validate_archive(archive_path, spec=spec)


class DirectoryValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.payload = self.root / "patch_data"
        (self.payload / "enus/wem").mkdir(parents=True)
        (self.payload / "enus/wem/one.wem").write_bytes(WEM_BYTES)
        (self.payload / "enus/one.bnk").write_bytes(BNK_BYTES)
        # The archive itself is immaterial for an extracted-directory fixture.
        self.spec = make_spec(
            b"fixture",
            tree_files={"enus/wem/one.wem": WEM_BYTES, "enus/one.bnk": BNK_BYTES},
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_accepts_complete_directory_without_marker(self) -> None:
        stats = patch_data.validate_patch_directory(self.payload, spec=self.spec)
        self.assertEqual(stats.file_count, 2)

    def test_plan_hashes_must_match_the_same_pass_as_the_tree_digest(self) -> None:
        wrong = {
            "enus/wem/one.wem": "0" * 64,
            "enus/one.bnk": hashlib.sha256(BNK_BYTES).hexdigest(),
        }

        with self.assertRaisesRegex(
            patch_data.PayloadValidationError, "bytes nao autenticados"
        ):
            patch_data.validate_patch_directory(
                self.payload,
                spec=self.spec,
                expected_file_sha256=wrong,
            )

    def test_rejects_bad_payload_header(self) -> None:
        (self.payload / "enus/wem/one.wem").write_bytes(b"not-a-wave!")
        with self.assertRaisesRegex(patch_data.PayloadValidationError, "RIFF/WAVE"):
            patch_data.validate_patch_directory(self.payload, spec=self.spec)

    def test_rejects_same_size_same_header_content_tampering(self) -> None:
        changed = bytearray(WEM_BYTES)
        changed[7] ^= 0x01
        (self.payload / "enus/wem/one.wem").write_bytes(changed)
        with self.assertRaisesRegex(
            patch_data.PayloadValidationError, "arvore extraida"
        ):
            patch_data.validate_patch_directory(self.payload, spec=self.spec)

    def test_rejects_unexpected_file_and_bad_marker(self) -> None:
        extra = self.payload / "notes.txt"
        extra.write_text("no", encoding="utf-8")
        with self.assertRaisesRegex(
            patch_data.PayloadValidationError, "Extensao inesperada"
        ):
            patch_data.validate_patch_directory(self.payload, spec=self.spec)
        extra.unlink()

        (self.payload / patch_data.MARKER_FILENAME).write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(patch_data.PayloadValidationError, "divergente"):
            patch_data.validate_patch_directory(self.payload, spec=self.spec)

    def test_rejects_non_object_marker_as_controlled_validation_error(self) -> None:
        (self.payload / patch_data.MARKER_FILENAME).write_text("[]", encoding="utf-8")

        with self.assertRaisesRegex(
            patch_data.PayloadValidationError, "JSON deve ser um objeto"
        ):
            patch_data.validate_patch_directory(self.payload, spec=self.spec)

    @unittest.skipIf(
        os.name == "nt", "Criacao de symlink normalmente exige privilegio no Windows"
    )
    def test_rejects_directory_symlink(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        (self.payload / "linked").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(patch_data.PayloadValidationError, "Link/reparse"):
            patch_data.validate_patch_directory(self.payload, spec=self.spec)


class DownloadAndDiscoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name).resolve()
        source = self.root / "source.zip"
        self.archive_bytes = write_zip(
            source,
            {"enus/wem/one.wem": WEM_BYTES, "enus/one.bnk": BNK_BYTES},
        )
        self.spec = make_spec(self.archive_bytes)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    @staticmethod
    def write_valid_payload(destination: Path) -> None:
        (destination / "enus/wem").mkdir(parents=True)
        (destination / "enus/wem/one.wem").write_bytes(WEM_BYTES)
        (destination / "enus/one.bnk").write_bytes(BNK_BYTES)

    def opener(self, request, timeout):
        self.assertEqual(request.full_url, self.spec.url)
        self.assertEqual(timeout, 60.0)
        return FakeResponse(
            self.archive_bytes,
            content_length=str(len(self.archive_bytes)),
        )

    def test_payload_cache_lock_rejects_a_second_writer(self) -> None:
        lock_path = self.root / "cache" / ".payload.lock"
        with patch_data.PayloadCacheLock(lock_path):
            with self.assertRaisesRegex(patch_data.PatchDataError, "Outra instancia"):
                with patch_data.PayloadCacheLock(lock_path):
                    self.fail("a second payload writer must not acquire the cache lock")

    def test_payload_cache_lock_recovers_zero_byte_creation_residue(self) -> None:
        lock_path = self.root / "cache" / ".payload.lock"
        lock_path.parent.mkdir()
        lock_path.write_bytes(b"")

        with patch_data.PayloadCacheLock(lock_path):
            pass

        self.assertEqual(lock_path.read_bytes(), b"\0")

    def test_payload_lock_rejects_hardlink_without_touching_victim(self) -> None:
        cache = self.root / "cache"
        cache.mkdir()
        victim = self.root / "victim.txt"
        victim.write_bytes(b"")
        lock_path = cache / ".payload.lock"
        os.link(victim, lock_path)

        with self.assertRaisesRegex(
            patch_data.PatchDataError, "arquivo regular exclusivo"
        ):
            with patch_data.PayloadCacheLock(lock_path):
                self.fail("a hardlinked lock must never be opened for writing")

        self.assertEqual(victim.read_bytes(), b"")

    def test_cache_root_file_is_rejected_without_resolving_through_it(self) -> None:
        cache = self.root / "cache"
        cache.write_bytes(b"not-a-directory")

        with self.assertRaisesRegex(patch_data.PatchDataError, "tipo inseguro"):
            patch_data.ensure_patch_data(
                self.root / "release",
                cache_dir=cache,
                spec=self.spec,
                opener=self.opener,
            )

        self.assertEqual(cache.read_bytes(), b"not-a-directory")

    def test_cache_recovery_only_runs_after_acquiring_the_lock(self) -> None:
        cache = self.root / "cache"
        residue = cache / ".patch_data.extract-deadbeef"
        residue.mkdir(parents=True)
        (residue / "partial.wem").write_bytes(b"partial")

        with patch_data.PayloadCacheLock(cache / ".payload.lock"):
            with self.assertRaisesRegex(patch_data.PatchDataError, "Outra instancia"):
                patch_data.ensure_patch_data(
                    self.root / "release",
                    cache_dir=cache,
                    spec=self.spec,
                    opener=self.opener,
                )
        self.assertTrue(residue.is_dir())

    def test_ensure_preserves_and_ignores_abandoned_private_extractions(self) -> None:
        adjacent = self.root / "release"
        self.write_valid_payload(adjacent / "patch_data")
        cache = self.root / "cache"
        residues = [
            cache / ".patch_data.extract-aaaaaaa1",
            cache / ".patch_data.extract-aaaaaaa2",
            cache / ".patch_data.extract-aaaaaaa3",
        ]
        for index, residue in enumerate(residues):
            residue.mkdir(parents=True)
            (residue / f"partial-{index}.bin").write_bytes(b"x" * 1024)
        logs: list[str] = []

        def forbidden_opener(request, timeout):
            self.fail("network must not be used for valid adjacent data")

        result = patch_data.ensure_patch_data(
            adjacent,
            cache_dir=cache,
            spec=self.spec,
            opener=forbidden_opener,
            log=logs.append,
        )

        self.assertEqual(result, adjacent / "patch_data")
        self.assertTrue(all(os.path.lexists(path) for path in residues))
        self.assertEqual(
            sum("Extracao interrompida preservada" in line for line in logs),
            len(residues),
        )

    def test_ensure_removes_abandoned_private_downloads(self) -> None:
        adjacent = self.root / "release"
        self.write_valid_payload(adjacent / "patch_data")
        cache = self.root / "cache"
        residue = cache / (f".{self.spec.archive_name}.download-" + "a" * 32 + ".part")
        residue.parent.mkdir(parents=True)
        residue.write_bytes(b"partial")
        predictable = cache / f"{self.spec.archive_name}.part"
        predictable.write_bytes(b"user-file")
        logs: list[str] = []

        patch_data.ensure_patch_data(
            adjacent,
            cache_dir=cache,
            spec=self.spec,
            opener=self.opener,
            log=logs.append,
        )

        self.assertFalse(os.path.lexists(residue))
        self.assertEqual(predictable.read_bytes(), b"user-file")
        self.assertTrue(any("Download interrompido removido" in line for line in logs))

    def test_abandoned_download_directory_is_preserved(self) -> None:
        adjacent = self.root / "release"
        self.write_valid_payload(adjacent / "patch_data")
        cache = self.root / "cache"
        residue = cache / (f".{self.spec.archive_name}.download-" + "b" * 32 + ".part")
        residue.mkdir(parents=True)
        sentinel = residue / "keep.txt"
        sentinel.write_text("keep", encoding="utf-8")

        with self.assertRaisesRegex(patch_data.PatchDataError, "tipo inesperado"):
            patch_data.ensure_patch_data(
                adjacent,
                cache_dir=cache,
                spec=self.spec,
                opener=self.opener,
            )

        self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")

    @unittest.skipIf(
        os.name == "nt", "Criacao de symlink normalmente exige privilegio no Windows"
    )
    def test_abandoned_extraction_cleanup_never_follows_symlinks(self) -> None:
        adjacent = self.root / "release"
        self.write_valid_payload(adjacent / "patch_data")
        cache = self.root / "cache"
        residue = cache / ".patch_data.extract-link0001"
        residue.mkdir(parents=True)
        outside = self.root / "outside"
        outside.mkdir()
        sentinel = outside / "keep.txt"
        sentinel.write_text("keep", encoding="utf-8")
        (residue / "outside-link").symlink_to(outside, target_is_directory=True)

        patch_data.ensure_patch_data(
            adjacent,
            cache_dir=cache,
            spec=self.spec,
            opener=self.opener,
        )

        self.assertTrue(os.path.lexists(residue))
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")

    def test_extraction_residue_is_never_sent_to_recursive_cleanup(self) -> None:
        adjacent = self.root / "release"
        self.write_valid_payload(adjacent / "patch_data")
        cache = self.root / "cache"
        residue = cache / ".patch_data.extract-busy0000"
        residue.mkdir(parents=True)

        with mock.patch.object(
            patch_data,
            "_remove_path_without_following",
            side_effect=PermissionError("busy"),
        ) as remover:
            result = patch_data.ensure_patch_data(
                adjacent,
                cache_dir=cache,
                spec=self.spec,
                opener=self.opener,
            )
        self.assertEqual(result, adjacent / "patch_data")
        remover.assert_not_called()
        self.assertTrue(residue.is_dir())

    def test_preserves_non_tempfile_extraction_name(self) -> None:
        cache = self.root / "cache"
        unrelated = cache / ".patch_data.extract-meus-dados"
        unrelated.mkdir(parents=True)
        sentinel = unrelated / "preservar.txt"
        sentinel.write_text("usuario", encoding="utf-8")

        with self.assertRaisesRegex(patch_data.PatchDataError, "nomes inesperados"):
            patch_data.ensure_patch_data(
                self.root / "release",
                cache_dir=cache,
                spec=self.spec,
                opener=self.opener,
            )

        self.assertEqual(sentinel.read_text(encoding="utf-8"), "usuario")

    def test_recovers_single_valid_old_tree_when_final_target_is_missing(
        self,
    ) -> None:
        cache = self.root / "cache"
        previous = cache / (".patch_data.old-" + "1" * 32)
        self.write_valid_payload(previous)
        logs: list[str] = []

        def forbidden_opener(request, timeout):
            self.fail("network must not be used while recovering a valid backup")

        result = patch_data.ensure_patch_data(
            self.root / "release",
            cache_dir=cache,
            spec=self.spec,
            opener=forbidden_opener,
            log=logs.append,
        )

        self.assertEqual(result, cache / "patch_data")
        self.assertFalse(os.path.lexists(previous))
        self.assertEqual((result / "enus/one.bnk").read_bytes(), BNK_BYTES)
        self.assertTrue(any("Payload recuperado" in line for line in logs))

    def test_preserves_single_old_tree_after_valid_target_was_published(self) -> None:
        cache = self.root / "cache"
        target = cache / "patch_data"
        self.write_valid_payload(target)
        previous = cache / (".patch_data.old-" + "2" * 32)
        previous.mkdir()
        (previous / "obsolete.bin").write_bytes(b"old")

        def forbidden_opener(request, timeout):
            self.fail("network must not be used for a valid cached payload")

        result = patch_data.ensure_patch_data(
            self.root / "release",
            cache_dir=cache,
            spec=self.spec,
            opener=forbidden_opener,
        )

        self.assertEqual(result, target)
        self.assertTrue(os.path.lexists(previous))

    def test_preserves_multiple_old_trees_instead_of_guessing(self) -> None:
        cache = self.root / "cache"
        previous_paths = [
            cache / (".patch_data.old-" + "3" * 32),
            cache / (".patch_data.old-" + "4" * 32),
        ]
        for previous in previous_paths:
            self.write_valid_payload(previous)

        with self.assertRaisesRegex(patch_data.PatchDataError, "multiplos backups"):
            patch_data.ensure_patch_data(
                self.root / "release",
                cache_dir=cache,
                spec=self.spec,
                opener=self.opener,
            )

        self.assertTrue(all(path.is_dir() for path in previous_paths))
        self.assertFalse(os.path.lexists(cache / "patch_data"))

    def test_preserves_invalid_target_and_valid_old_tree_as_ambiguous(self) -> None:
        cache = self.root / "cache"
        target = cache / "patch_data"
        target.mkdir(parents=True)
        (target / "corrupt.bin").write_bytes(b"corrupt")
        previous = cache / (".patch_data.old-" + "5" * 32)
        self.write_valid_payload(previous)

        with self.assertRaisesRegex(patch_data.PatchDataError, "estado ambiguo"):
            patch_data.ensure_patch_data(
                self.root / "release",
                cache_dir=cache,
                spec=self.spec,
                opener=self.opener,
            )

        self.assertTrue(target.is_dir())
        self.assertTrue(previous.is_dir())

    def test_preserves_malformed_old_residue_and_fails_safely(self) -> None:
        cache = self.root / "cache"
        malformed = cache / ".patch_data.old-not-a-uuid"
        malformed.mkdir(parents=True)

        with self.assertRaisesRegex(patch_data.PatchDataError, "nomes inesperados"):
            patch_data.ensure_patch_data(
                self.root / "release",
                cache_dir=cache,
                spec=self.spec,
                opener=self.opener,
            )

        self.assertTrue(malformed.is_dir())

    def test_failed_atomic_old_recovery_preserves_the_only_backup(self) -> None:
        cache = self.root / "cache"
        target = cache / "patch_data"
        previous = cache / (".patch_data.old-" + "6" * 32)
        self.write_valid_payload(previous)
        real_rename = patch_data.os.rename

        def fail_recovery(source, destination):
            if Path(source) == previous and Path(destination) == target:
                raise PermissionError("locked")
            return real_rename(source, destination)

        with mock.patch.object(patch_data.os, "rename", side_effect=fail_recovery):
            with self.assertRaisesRegex(patch_data.PatchDataError, "atomicamente"):
                patch_data.ensure_patch_data(
                    self.root / "release",
                    cache_dir=cache,
                    spec=self.spec,
                    opener=self.opener,
                )

        self.assertTrue(previous.is_dir())
        self.assertFalse(os.path.lexists(target))

    def test_racing_file_is_not_overwritten_during_old_recovery(self) -> None:
        cache = self.root / "cache"
        target = cache / "patch_data"
        previous = cache / (".patch_data.old-" + "7" * 32)
        self.write_valid_payload(previous)
        external = b"EXTERNAL"
        real_rename = patch_data.os.rename
        injected = False

        def inject_target(source, destination):
            nonlocal injected
            if Path(source) == previous and Path(destination) == target:
                target.write_bytes(external)
                injected = True
            return real_rename(source, destination)

        with mock.patch.object(patch_data.os, "rename", side_effect=inject_target):
            with self.assertRaisesRegex(patch_data.PatchDataError, "preservado"):
                patch_data.ensure_patch_data(
                    self.root / "release",
                    cache_dir=cache,
                    spec=self.spec,
                    opener=self.opener,
                )

        self.assertTrue(injected)
        self.assertTrue(previous.is_dir())
        self.assertEqual(target.read_bytes(), external)

    def test_racing_file_is_not_overwritten_during_directory_publish(self) -> None:
        staged = self.root / "cache" / ".patch_data.extract-12345678"
        destination = self.root / "cache" / "patch_data"
        staged.mkdir(parents=True)
        (staged / "new.bin").write_bytes(b"new")
        destination.mkdir()
        (destination / "old.bin").write_bytes(b"old")
        external = b"EXTERNAL-PUBLISH"
        real_rename = patch_data.os.rename
        injected = False

        def inject_publish(source, target):
            nonlocal injected
            if Path(source) == staged and Path(target) == destination:
                destination.write_bytes(external)
                injected = True
            return real_rename(source, target)

        with mock.patch.object(patch_data.os, "rename", side_effect=inject_publish):
            with self.assertRaises(patch_data.PatchDataError):
                patch_data._replace_directory_atomically(staged, destination)

        self.assertTrue(injected)
        self.assertEqual(destination.read_bytes(), external)
        previous = list((self.root / "cache").glob(".patch_data.old-*"))
        self.assertEqual(len(previous), 1)
        self.assertEqual((previous[0] / "old.bin").read_bytes(), b"old")
        self.assertTrue(staged.is_dir())

    def test_download_uses_private_temp_then_publishes_validated_zip(self) -> None:
        destination = self.root / "cache" / self.spec.archive_name
        progress: list[tuple[int, int]] = []
        logs: list[str] = []
        result = patch_data.download_archive(
            destination,
            spec=self.spec,
            opener=self.opener,
            progress=lambda current, total: progress.append((current, total)),
            log=logs.append,
        )
        self.assertEqual(result, destination)
        self.assertEqual(destination.read_bytes(), self.archive_bytes)
        self.assertEqual(
            list(destination.parent.glob(f".{destination.name}.download-*.part")),
            [],
        )
        self.assertEqual(
            progress[-1], (len(self.archive_bytes), len(self.archive_bytes))
        )
        self.assertTrue(any("SHA-256" in line for line in logs))

    def test_download_refuses_a_bundled_only_spec_without_side_effects(self) -> None:
        destination = self.root / "new-cache" / "payload.zip"
        bundled_spec = make_spec(self.archive_bytes, url=None)

        def forbidden_opener(request, timeout):
            self.fail("a bundled-only payload must never access the network")

        with self.assertRaisesRegex(
            patch_data.PayloadDownloadError, "acompanha o pacote oficial"
        ):
            patch_data.download_archive(
                destination,
                spec=bundled_spec,
                opener=forbidden_opener,
            )

        self.assertFalse(destination.parent.exists())

    def test_download_does_not_touch_preplanted_predictable_part_file(self) -> None:
        destination = self.root / "cache" / self.spec.archive_name
        destination.parent.mkdir(parents=True)
        predictable = destination.with_name(destination.name + ".part")
        sentinel = b"PRESERVE-ME"
        predictable.write_bytes(sentinel)

        patch_data.download_archive(
            destination,
            spec=self.spec,
            opener=self.opener,
        )

        self.assertEqual(predictable.read_bytes(), sentinel)
        self.assertEqual(destination.read_bytes(), self.archive_bytes)

    def test_download_uuid_collision_preserves_preexisting_hardlink(self) -> None:
        destination = self.root / "cache" / self.spec.archive_name
        destination.parent.mkdir(parents=True)
        victim = self.root / "victim.bin"
        victim.write_bytes(b"PRESERVE")
        fixed_hex = "c" * 32
        scratch = destination.with_name(
            f".{destination.name}.download-{fixed_hex}.part"
        )
        os.link(victim, scratch)
        fixed_uuid = mock.Mock(hex=fixed_hex)

        with mock.patch.object(patch_data.uuid, "uuid4", return_value=fixed_uuid):
            with self.assertRaises(patch_data.PayloadDownloadError):
                patch_data.download_archive(
                    destination,
                    spec=self.spec,
                    opener=self.opener,
                )

        self.assertEqual(victim.read_bytes(), b"PRESERVE")
        self.assertTrue(scratch.exists())

    def test_marker_uuid_collision_preserves_preexisting_hardlink(self) -> None:
        directory = self.root / "payload"
        directory.mkdir()
        victim = self.root / "marker-victim.bin"
        victim.write_bytes(b"PRESERVE-MARKER")
        fixed_hex = "d" * 32
        scratch = directory / f".{patch_data.MARKER_FILENAME}.{fixed_hex}.tmp"
        os.link(victim, scratch)
        fixed_uuid = mock.Mock(hex=fixed_hex)

        with mock.patch.object(patch_data.uuid, "uuid4", return_value=fixed_uuid):
            with self.assertRaisesRegex(
                patch_data.PayloadExtractionError, "preservado"
            ):
                patch_data._write_marker(directory, self.spec)

        self.assertEqual(victim.read_bytes(), b"PRESERVE-MARKER")
        self.assertTrue(scratch.exists())

    def test_download_preserves_destination_created_during_publish(self) -> None:
        destination = self.root / "cache" / self.spec.archive_name
        external = b"EXTERNAL-RACE"
        real_rename = patch_data.os.rename
        injected = False

        def inject_destination(source, target):
            nonlocal injected
            if Path(target) == destination:
                destination.write_bytes(external)
                injected = True
            return real_rename(source, target)

        with mock.patch.object(patch_data.os, "rename", side_effect=inject_destination):
            with self.assertRaisesRegex(patch_data.PayloadDownloadError, "preservado"):
                patch_data.download_archive(
                    destination,
                    spec=self.spec,
                    opener=self.opener,
                )

        self.assertTrue(injected)
        self.assertEqual(destination.read_bytes(), external)
        self.assertEqual(
            list(destination.parent.glob(f".{destination.name}.download-*.part")),
            [],
        )

    def test_download_never_publishes_a_swapped_private_file_as_valid(self) -> None:
        destination = self.root / "cache" / self.spec.archive_name
        real_validate = patch_data.validate_archive
        swapped_path: Path | None = None

        def validate_then_swap(path, *, spec, progress=None):
            nonlocal swapped_path
            result = real_validate(path, spec=spec, progress=progress)
            swapped_path = Path(path)
            swapped_path.unlink()
            swapped_path.write_bytes(b"UNAUTHENTICATED")
            return result

        with mock.patch.object(
            patch_data, "validate_archive", side_effect=validate_then_swap
        ):
            with self.assertRaisesRegex(
                patch_data.PayloadDownloadError, "trocado|publicacao"
            ):
                patch_data.download_archive(
                    destination,
                    spec=self.spec,
                    opener=self.opener,
                )

        self.assertFalse(destination.exists())
        self.assertIsNotNone(swapped_path)
        assert swapped_path is not None
        self.assertEqual(swapped_path.read_bytes(), b"UNAUTHENTICATED")

    def test_download_rejects_non_https_redirect_and_removes_part(self) -> None:
        destination = self.root / "payload.zip"

        def insecure_opener(request, timeout):
            return FakeResponse(
                self.archive_bytes, url="http://cdn.example.invalid/payload.zip"
            )

        with self.assertRaisesRegex(patch_data.PayloadDownloadError, "sem HTTPS"):
            patch_data.download_archive(
                destination, spec=self.spec, opener=insecure_opener
            )
        self.assertFalse(destination.exists())
        self.assertFalse(destination.with_name(destination.name + ".part").exists())

    def test_download_rejects_wrong_content_and_preserves_existing_archive(
        self,
    ) -> None:
        destination = self.root / "payload.zip"
        destination.write_bytes(b"old")

        def corrupt_opener(request, timeout):
            corrupt = self.archive_bytes[:-1] + bytes([self.archive_bytes[-1] ^ 0xFF])
            return FakeResponse(corrupt, content_length=str(len(corrupt)))

        with self.assertRaisesRegex(patch_data.PayloadDownloadError, "SHA-256"):
            patch_data.download_archive(
                destination, spec=self.spec, opener=corrupt_opener
            )
        self.assertEqual(destination.read_bytes(), b"old")
        self.assertFalse(destination.with_name(destination.name + ".part").exists())

    def test_ensure_replaces_an_invalid_regular_cached_archive(self) -> None:
        cache = self.root / "cache"
        cache.mkdir()
        cached = cache / self.spec.archive_name
        cached.write_bytes(b"corrupt")
        logs: list[str] = []

        result = patch_data.ensure_patch_data(
            self.root / "release",
            cache_dir=cache,
            spec=self.spec,
            opener=self.opener,
            log=logs.append,
        )

        self.assertEqual(result, cache / "patch_data")
        self.assertEqual(cached.read_bytes(), self.archive_bytes)
        self.assertTrue(any("ZIP invalido removido" in line for line in logs))

    def test_ensure_prefers_valid_extracted_adjacent_data_without_network(self) -> None:
        adjacent = self.root / "release"
        payload = adjacent / "patch_data"
        (payload / "enus/wem").mkdir(parents=True)
        (payload / "enus/wem/one.wem").write_bytes(WEM_BYTES)
        (payload / "enus/one.bnk").write_bytes(BNK_BYTES)
        cache = self.root / "cache"

        def forbidden_opener(request, timeout):
            self.fail("network must not be used for valid adjacent data")

        result = patch_data.ensure_patch_data(
            adjacent,
            cache_dir=cache,
            spec=self.spec,
            opener=forbidden_opener,
        )
        self.assertEqual(result, payload)

    def test_ensure_accepts_adjacent_patch_data_zip_only_after_validation(self) -> None:
        adjacent = self.root / "release"
        adjacent.mkdir()
        (adjacent / "patch_data.zip").write_bytes(self.archive_bytes)
        cache = self.root / "cache"

        def forbidden_opener(request, timeout):
            self.fail("network must not be used for a valid adjacent archive")

        result = patch_data.ensure_patch_data(
            adjacent,
            cache_dir=cache,
            spec=self.spec,
            opener=forbidden_opener,
        )
        self.assertEqual(result, cache / "patch_data")
        self.assertEqual((result / "enus/wem/one.wem").read_bytes(), WEM_BYTES)
        self.assertTrue((result / patch_data.MARKER_FILENAME).is_file())

    def test_ensure_uses_a_valid_bundled_archive_without_network(self) -> None:
        adjacent = self.root / "release"
        adjacent.mkdir()
        bundled_spec = make_spec(self.archive_bytes, url=None)
        (adjacent / bundled_spec.archive_name).write_bytes(self.archive_bytes)

        def forbidden_opener(request, timeout):
            self.fail("a bundled-only payload must never access the network")

        result = patch_data.ensure_patch_data(
            adjacent,
            cache_dir=self.root / "cache",
            spec=bundled_spec,
            opener=forbidden_opener,
        )

        self.assertEqual(result, self.root / "cache" / "patch_data")
        self.assertEqual((result / "enus/one.bnk").read_bytes(), BNK_BYTES)

    def test_ensure_fails_closed_when_bundled_archive_is_invalid(self) -> None:
        adjacent = self.root / "release"
        adjacent.mkdir()
        bundled_spec = make_spec(self.archive_bytes, url=None)
        bundled_archive = adjacent / bundled_spec.archive_name
        bundled_archive.write_bytes(b"corrupt")

        def forbidden_opener(request, timeout):
            self.fail("a bundled-only payload must never access the network")

        with self.assertRaisesRegex(
            patch_data.PayloadValidationError,
            "nenhum download alternativo foi tentado",
        ):
            patch_data.ensure_patch_data(
                adjacent,
                cache_dir=self.root / "cache",
                spec=bundled_spec,
                opener=forbidden_opener,
            )

        self.assertEqual(bundled_archive.read_bytes(), b"corrupt")

    def test_ensure_skips_invalid_adjacent_zip_then_downloads_pinned_data(self) -> None:
        adjacent = self.root / "release"
        adjacent.mkdir()
        (adjacent / "patch_data.zip").write_bytes(b"invalid")
        cache = self.root / "cache"
        logs: list[str] = []

        result = patch_data.ensure_patch_data(
            adjacent,
            cache_dir=cache,
            spec=self.spec,
            opener=self.opener,
            log=logs.append,
        )
        self.assertTrue((result / "enus/one.bnk").is_file())
        self.assertTrue(any("ignorado" in line for line in logs))


if __name__ == "__main__":
    unittest.main()
