from __future__ import annotations

from contextlib import redirect_stderr
import hashlib
import io
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from tools import build_source_release, verify_source_release


def _tree_sha(files: list[tuple[str, bytes]]) -> str:
    digest = hashlib.sha256()
    for relative, data in files:
        encoded = relative.encode("utf-8")
        digest.update(struct.pack("<I", len(encoded)))
        digest.update(encoded)
        digest.update(struct.pack("<Q", len(data)))
        digest.update(data)
    return digest.hexdigest()


def _small_payload() -> tuple[bytes, list[tuple[str, bytes]]]:
    files = [
        ("a.wem", b"RIFF\x08\x00\x00\x00WAVEdata"),
        ("b.bnk", b"BKHDok"),
    ]
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for relative, data in files:
            archive.writestr(f"patch_data/{relative}", data)
    return stream.getvalue(), files


def _payload_overrides(
    payload_bytes: bytes, files: list[tuple[str, bytes]]
) -> dict[str, int | str]:
    return {
        "PAYLOAD_ARCHIVE_SIZE": len(payload_bytes),
        "PAYLOAD_SHA256": hashlib.sha256(payload_bytes).hexdigest(),
        "PAYLOAD_TREE_SHA256": _tree_sha(files),
        "PAYLOAD_FILE_COUNT": len(files),
        "PAYLOAD_WEM_COUNT": sum(name.endswith(".wem") for name, _data in files),
        "PAYLOAD_BNK_COUNT": sum(name.endswith(".bnk") for name, _data in files),
        "PAYLOAD_UNCOMPRESSED_SIZE": sum(len(data) for _name, data in files),
        "PAYLOAD_MAX_FILE_SIZE": max(len(data) for _name, data in files),
    }


class FinalReleasePayloadTests(unittest.TestCase):
    def test_final_constants_pin_the_reviewed_flat_payload(self) -> None:
        self.assertEqual(build_source_release.FINAL_VERSION, "v0.9.5")
        self.assertEqual(
            build_source_release.FINAL_ARCHIVE_NAME,
            "ERPT-BR-v0.9.5-Windows.zip",
        )
        self.assertEqual(build_source_release.PAYLOAD_ARCHIVE_SIZE, 588_468_447)
        self.assertEqual(
            build_source_release.PAYLOAD_SHA256,
            "430e9693a9b3313826e9f7c890cf592eb5b468d145bb405e8a4586002b877680",
        )
        self.assertEqual(
            build_source_release.PAYLOAD_TREE_SHA256,
            verify_source_release.PAYLOAD_TREE_SHA256,
        )
        self.assertEqual(build_source_release.PAYLOAD_FILE_COUNT, 9_241)
        self.assertEqual(verify_source_release.PAYLOAD_FILE_COUNT, 9_241)

    def test_payload_is_required_by_the_final_builder_cli(self) -> None:
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            build_source_release.parse_args(
                [
                    "--wheelhouse",
                    "wheelhouse",
                    "--output",
                    build_source_release.FINAL_ARCHIVE_NAME,
                    "--version",
                    build_source_release.FINAL_VERSION,
                ]
            )

    def test_builder_streams_payload_as_direct_members(self) -> None:
        payload_bytes, files = _small_payload()
        overrides = _payload_overrides(payload_bytes, files)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            payload = root / "input.zip"
            payload.write_bytes(payload_bytes)
            outer_path = root / "outer.zip"
            metadata = payload.stat()
            with mock.patch.multiple(build_source_release, **overrides):
                identity = build_source_release.validate_payload(payload)
                with zipfile.ZipFile(
                    outer_path,
                    "w",
                    compression=zipfile.ZIP_DEFLATED,
                    compresslevel=9,
                ) as outer:
                    build_source_release.write_payload_members(
                        outer,
                        payload=payload,
                        package_root="ERPT-BR-v0.9.5",
                        expected_identity=identity,
                    )

            with zipfile.ZipFile(outer_path, "r") as outer:
                expected_names = [
                    f"ERPT-BR-v0.9.5/patch_data/{relative}"
                    for relative, _data in files
                ]
                self.assertEqual(outer.namelist(), expected_names)
                self.assertFalse(
                    any(name.casefold().endswith(".zip") for name in outer.namelist())
                )
                for (relative, data), name in zip(files, expected_names):
                    info = outer.getinfo(name)
                    self.assertEqual(info.compress_type, zipfile.ZIP_DEFLATED)
                    self.assertEqual(
                        info.date_time, build_source_release.ARCHIVE_TIMESTAMP
                    )
                    self.assertEqual(outer.read(info), data, relative)
            self.assertEqual(identity, (metadata.st_dev, metadata.st_ino))

    def test_builder_output_is_deterministic(self) -> None:
        payload_bytes, files = _small_payload()
        overrides = _payload_overrides(payload_bytes, files)
        source_files = (
            "patcher/__init__.py",
            "patcher/patcher_gui.py",
            "interno/INSTALAR_AMBIENTE.cmd",
            "interno/ABRIR_INTERFACE.cmd",
        )
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "root"
            wheelhouse = Path(temp) / "wheelhouse"
            (root / "patcher").mkdir(parents=True)
            (root / "interno").mkdir()
            wheelhouse.mkdir()
            (root / "patcher/__init__.py").write_text(
                '__version__ = "0.9.5"\n', encoding="utf-8", newline="\n"
            )
            (root / "patcher/patcher_gui.py").write_text(
                'PATCHER_VERSION = "0.9.5"\n', encoding="utf-8", newline="\n"
            )
            for command in source_files[2:]:
                (root / command).write_text(
                    "@echo off\nrem venv-0.9.5\n",
                    encoding="utf-8",
                    newline="\n",
                )
            payload = Path(temp) / "input.zip"
            payload.write_bytes(payload_bytes)
            first = Path(temp) / "one" / build_source_release.FINAL_ARCHIVE_NAME
            second = Path(temp) / "two" / build_source_release.FINAL_ARCHIVE_NAME

            with mock.patch.multiple(
                build_source_release,
                SOURCE_FILES=source_files,
                WHEELS={},
                **overrides,
            ):
                build_source_release.build(
                    root,
                    wheelhouse,
                    payload,
                    first,
                    build_source_release.FINAL_VERSION,
                )
                build_source_release.build(
                    root,
                    wheelhouse,
                    payload,
                    second,
                    build_source_release.FINAL_VERSION,
                )
            self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_verifier_streams_and_checks_flat_payload_tree(self) -> None:
        _payload_bytes, files = _small_payload()
        stream = io.BytesIO()
        with zipfile.ZipFile(
            stream, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        ) as archive:
            for relative, data in files:
                archive.writestr(
                    build_source_release.zip_info(
                        f"ERPT-BR-v0.9.5/patch_data/{relative}"
                    ),
                    data,
                )
        stream.seek(0)
        overrides = _payload_overrides(b"unused", files)
        overrides.pop("PAYLOAD_ARCHIVE_SIZE")
        overrides.pop("PAYLOAD_SHA256")
        with mock.patch.multiple(verify_source_release, **overrides):
            with zipfile.ZipFile(stream, "r") as archive:
                entries = [
                    (
                        relative,
                        archive.getinfo(f"ERPT-BR-v0.9.5/patch_data/{relative}"),
                    )
                    for relative, _data in files
                ]
                verify_source_release._verify_flat_payload(archive, entries)

    def test_verifier_rejects_wrong_flat_tree_identity(self) -> None:
        _payload_bytes, files = _small_payload()
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for relative, data in files:
                archive.writestr(
                    build_source_release.zip_info(
                        f"ERPT-BR-v0.9.5/patch_data/{relative}"
                    ),
                    data,
                )
        stream.seek(0)
        overrides = _payload_overrides(b"unused", files)
        overrides.pop("PAYLOAD_ARCHIVE_SIZE")
        overrides.pop("PAYLOAD_SHA256")
        overrides["PAYLOAD_TREE_SHA256"] = "00" * 32
        with mock.patch.multiple(verify_source_release, **overrides):
            with zipfile.ZipFile(stream, "r") as archive:
                entries = [
                    (
                        relative,
                        archive.getinfo(f"ERPT-BR-v0.9.5/patch_data/{relative}"),
                    )
                    for relative, _data in files
                ]
                with self.assertRaisesRegex(SystemExit, "arvore"):
                    verify_source_release._verify_flat_payload(archive, entries)

    def test_builder_rejects_archive_member_inside_payload(self) -> None:
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("patch_data/nested.zip", b"PK\x03\x04")
        payload_bytes = stream.getvalue()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            payload = root / "input.zip"
            payload.write_bytes(payload_bytes)
            output = root / "outer.zip"
            with mock.patch.multiple(
                build_source_release,
                PAYLOAD_ARCHIVE_SIZE=len(payload_bytes),
                PAYLOAD_SHA256=hashlib.sha256(payload_bytes).hexdigest(),
                PAYLOAD_FILE_COUNT=1,
            ):
                identity = build_source_release.validate_payload(payload)
                with zipfile.ZipFile(output, "w") as outer:
                    with self.assertRaisesRegex(SystemExit, "Caminho inseguro"):
                        build_source_release.write_payload_members(
                            outer,
                            payload=payload,
                            package_root="ERPT-BR-v0.9.5",
                            expected_identity=identity,
                        )

    def test_verifier_explicitly_rejects_nested_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            archive_path = Path(temp) / verify_source_release.FINAL_ARCHIVE_NAME
            with zipfile.ZipFile(
                archive_path, "w", compression=zipfile.ZIP_DEFLATED
            ) as archive:
                archive.writestr(
                    build_source_release.zip_info(
                        "ERPT-BR-v0.9.5/patch_data/nested.zip"
                    ),
                    b"PK\x03\x04",
                )
            with mock.patch.multiple(
                verify_source_release,
                EXPECTED_FILES=frozenset(),
                PAYLOAD_FILE_COUNT=1,
            ):
                with self.assertRaisesRegex(SystemExit, "compactado aninhado"):
                    verify_source_release.verify(str(archive_path))


if __name__ == "__main__":
    unittest.main()
