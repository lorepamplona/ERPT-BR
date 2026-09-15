from __future__ import annotations

from contextlib import redirect_stderr
import hashlib
import io
import stat
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


class FinalReleasePayloadTests(unittest.TestCase):
    def test_final_constants_pin_the_reviewed_payload(self) -> None:
        self.assertEqual(build_source_release.FINAL_VERSION, "v0.9.4")
        self.assertEqual(
            build_source_release.FINAL_ARCHIVE_NAME,
            "ERPT-BR-v0.9.4-Windows.zip",
        )
        self.assertEqual(build_source_release.PAYLOAD_ARCHIVE_SIZE, 588_468_447)
        self.assertEqual(
            build_source_release.PAYLOAD_SHA256,
            "430e9693a9b3313826e9f7c890cf592eb5b468d145bb405e8a4586002b877680",
        )
        self.assertEqual(
            verify_source_release.PAYLOAD_TREE_SHA256,
            "8544e551832c929eecad0cf9898204fd673bd4a37a0a6f37433865afbb3556cb",
        )

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

    def test_builder_streams_payload_as_stored_nested_zip(self) -> None:
        payload_bytes, _files = _small_payload()
        digest = hashlib.sha256(payload_bytes).hexdigest()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            payload = root / "input.zip"
            payload.write_bytes(payload_bytes)
            outer_path = root / "outer.zip"
            metadata = payload.stat()
            with mock.patch.multiple(
                build_source_release,
                PAYLOAD_ARCHIVE_SIZE=len(payload_bytes),
                PAYLOAD_SHA256=digest,
            ):
                identity = build_source_release.validate_payload(payload)
                with zipfile.ZipFile(outer_path, "w") as outer:
                    build_source_release.write_payload_member(
                        outer,
                        payload=payload,
                        member_name="ERPT-BR-v0.9.4/patch_data_v094.zip",
                        expected_identity=identity,
                    )
            with zipfile.ZipFile(outer_path, "r") as outer:
                info = outer.getinfo("ERPT-BR-v0.9.4/patch_data_v094.zip")
                self.assertEqual(info.compress_type, zipfile.ZIP_STORED)
                self.assertEqual(info.file_size, len(payload_bytes))
                self.assertEqual(info.compress_size, len(payload_bytes))
                self.assertEqual(outer.read(info), payload_bytes)
            self.assertEqual(identity, (metadata.st_dev, metadata.st_ino))

    def test_verifier_streams_and_checks_nested_payload_tree(self) -> None:
        payload_bytes, files = _small_payload()
        outer_stream = io.BytesIO()
        with zipfile.ZipFile(outer_stream, "w") as outer:
            info = zipfile.ZipInfo(
                "ERPT-BR-v0.9.4/patch_data_v094.zip",
                date_time=(2020, 1, 1, 0, 0, 0),
            )
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            outer.writestr(info, payload_bytes)
        outer_stream.seek(0)
        with mock.patch.multiple(
            verify_source_release,
            PAYLOAD_ARCHIVE_SIZE=len(payload_bytes),
            PAYLOAD_SHA256=hashlib.sha256(payload_bytes).hexdigest(),
            PAYLOAD_TREE_SHA256=_tree_sha(files),
            PAYLOAD_FILE_COUNT=2,
            PAYLOAD_WEM_COUNT=1,
            PAYLOAD_BNK_COUNT=1,
            PAYLOAD_UNCOMPRESSED_SIZE=sum(len(data) for _, data in files),
            PAYLOAD_MAX_FILE_SIZE=max(len(data) for _, data in files),
        ):
            with zipfile.ZipFile(outer_stream, "r") as outer:
                verify_source_release._verify_nested_payload(
                    outer,
                    outer.getinfo("ERPT-BR-v0.9.4/patch_data_v094.zip"),
                )

    def test_verifier_rejects_wrong_nested_tree_identity(self) -> None:
        payload_bytes, files = _small_payload()
        outer_stream = io.BytesIO()
        with zipfile.ZipFile(outer_stream, "w") as outer:
            outer.writestr(
                "ERPT-BR-v0.9.4/patch_data_v094.zip",
                payload_bytes,
                compress_type=zipfile.ZIP_STORED,
            )
        outer_stream.seek(0)
        with mock.patch.multiple(
            verify_source_release,
            PAYLOAD_ARCHIVE_SIZE=len(payload_bytes),
            PAYLOAD_SHA256=hashlib.sha256(payload_bytes).hexdigest(),
            PAYLOAD_TREE_SHA256="00" * 32,
            PAYLOAD_FILE_COUNT=2,
            PAYLOAD_WEM_COUNT=1,
            PAYLOAD_BNK_COUNT=1,
            PAYLOAD_UNCOMPRESSED_SIZE=sum(len(data) for _, data in files),
            PAYLOAD_MAX_FILE_SIZE=max(len(data) for _, data in files),
        ):
            with zipfile.ZipFile(outer_stream, "r") as outer:
                with self.assertRaisesRegex(SystemExit, "arvore"):
                    verify_source_release._verify_nested_payload(
                        outer,
                        outer.getinfo("ERPT-BR-v0.9.4/patch_data_v094.zip"),
                    )


if __name__ == "__main__":
    unittest.main()
