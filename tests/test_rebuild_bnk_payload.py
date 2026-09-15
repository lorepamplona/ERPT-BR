from __future__ import annotations

import hashlib
import os
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from patcher import bnk, engine, patch_data
from tools import rebuild_bnk_payload


def _section(chunk_id: bytes, data: bytes) -> bytes:
    return chunk_id + struct.pack("<I", len(data)) + data


def _sound(object_id: int, wem_id: int, stream_type: int) -> bytes:
    # CAkSound prefix for Wwise 135: object id, plugin id, StreamType, WemId,
    # in-memory media size and source bits.
    body = (
        struct.pack("<II", object_id, 0x00040001)
        + bytes((stream_type,))
        + struct.pack("<II", wem_id, 0)
        + b"\0"
    )
    return b"\x02" + struct.pack("<I", len(body)) + body


def _bank(sound: bytes, *, bank_id: int = 7) -> bytes:
    return (
        _section(b"BKHD", struct.pack("<II", 135, bank_id))
        + _section(b"HIRC", struct.pack("<I", 1) + sound)
    )


class RebuildBnkPayloadTests(unittest.TestCase):
    def test_read_regular_bytes_binds_handle_and_rechecks_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "input.bin"
            data = b"authenticated input"
            path.write_bytes(data)

            with mock.patch.object(
                rebuild_bnk_payload,
                "_assert_unchanged",
                wraps=rebuild_bnk_payload._assert_unchanged,
            ) as unchanged:
                actual, digest = rebuild_bnk_payload._read_regular_bytes(
                    path,
                    label="Entrada de teste",
                )

            self.assertEqual(actual, data)
            self.assertEqual(digest, hashlib.sha256(data).hexdigest())
            unchanged.assert_called_once()

            with path.open("rb") as stream:
                opened = os.fstat(stream.fileno())
            linked_after = SimpleNamespace(
                st_mode=opened.st_mode,
                st_dev=opened.st_dev,
                st_ino=opened.st_ino,
                st_size=opened.st_size,
                st_mtime_ns=opened.st_mtime_ns,
                st_nlink=2,
                st_file_attributes=getattr(opened, "st_file_attributes", 0),
            )
            with mock.patch.object(
                rebuild_bnk_payload.os,
                "fstat",
                side_effect=(opened, linked_after),
            ):
                with self.assertRaisesRegex(
                    rebuild_bnk_payload.RebuildError,
                    "mudou durante a leitura",
                ):
                    rebuild_bnk_payload._read_regular_bytes(
                        path,
                        label="Entrada de teste",
                    )

    def test_bhd_requires_rsa_and_rejects_plaintext(self) -> None:
        with self.assertRaisesRegex(
            rebuild_bnk_payload.RebuildError,
            "texto puro.*RSA",
        ):
            rebuild_bnk_payload._decrypt_authenticated_bhd(
                b"BHD5" + b"\0" * 252,
                name="sd.bhd",
            )

        encrypted = b"X" * 256
        decrypted = b"BHD5" + b"\0" * 251
        with mock.patch.object(
            engine,
            "rsa_decrypt_bhd",
            return_value=decrypted,
        ) as rsa_decrypt:
            self.assertEqual(
                rebuild_bnk_payload._decrypt_authenticated_bhd(
                    encrypted,
                    name="sd.bhd",
                ),
                decrypted,
            )
        rsa_decrypt.assert_called_once_with(encrypted)

    def test_pinned_build_requires_exact_bhd_hash_set(self) -> None:
        expected = dict(
            rebuild_bnk_payload.PINNED_BHD_SHA256_BY_BUILD["25080141"]
        )
        rebuild_bnk_payload._validate_pinned_bhd_digests("25080141", expected)

        for invalid in (
            {"sd": expected["sd"]},
            {**expected, "sd": "0" * 64},
            {**expected, "unexpected": "0" * 64},
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(
                    rebuild_bnk_payload.RebuildError,
                    "BuildID fixado",
                ):
                    rebuild_bnk_payload._validate_pinned_bhd_digests(
                        "25080141",
                        invalid,
                    )

    def test_pinned_build_requires_exact_bdt_backup_size_and_hash(self) -> None:
        expected = dict(
            rebuild_bnk_payload.PINNED_BDT_BACKUPS_BY_BUILD["25080141"]
        )
        rebuild_bnk_payload._validate_pinned_bdt_backups("25080141", expected)

        sd_size, sd_digest = expected["sd"]
        for invalid in (
            {"sd": expected["sd"]},
            {**expected, "sd": (sd_size - 1, sd_digest)},
            {**expected, "sd": (sd_size, "0" * 64)},
            {**expected, "unexpected": (1, "0" * 64)},
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(
                    rebuild_bnk_payload.RebuildError,
                    "backups BDT.*BuildID fixado",
                ):
                    rebuild_bnk_payload._validate_pinned_bdt_backups(
                        "25080141",
                        invalid,
                    )

    def test_final_payload_revalidation_checks_full_tree_marker_and_wems(
        self,
    ) -> None:
        payload = Path("payload")
        wem_ids = frozenset({10, 20})
        with (
            mock.patch.object(
                rebuild_bnk_payload,
                "validate_historical_payload",
                return_value="a" * 64,
            ) as validate_tree,
            mock.patch.object(
                rebuild_bnk_payload,
                "collect_external_wem_ids",
                return_value=(wem_ids, "b" * 64),
            ) as collect_wems,
        ):
            rebuild_bnk_payload._revalidate_historical_payload(
                payload,
                expected_marker_sha256="a" * 64,
                expected_wem_ids=wem_ids,
                expected_wem_name_digest="b" * 64,
            )
        validate_tree.assert_called_once_with(payload)
        collect_wems.assert_called_once_with(payload)

        with mock.patch.object(
            rebuild_bnk_payload,
            "validate_historical_payload",
            return_value="c" * 64,
        ):
            with self.assertRaisesRegex(
                rebuild_bnk_payload.RebuildError,
                "marker.*mudou",
            ):
                rebuild_bnk_payload._revalidate_historical_payload(
                    payload,
                    expected_marker_sha256="a" * 64,
                    expected_wem_ids=wem_ids,
                    expected_wem_name_digest="b" * 64,
                )

        with (
            mock.patch.object(
                rebuild_bnk_payload,
                "validate_historical_payload",
                return_value="a" * 64,
            ),
            mock.patch.object(
                rebuild_bnk_payload,
                "collect_external_wem_ids",
                return_value=(frozenset({10}), "b" * 64),
            ),
        ):
            with self.assertRaisesRegex(
                rebuild_bnk_payload.RebuildError,
                "conjunto de WEMs.*mudou",
            ):
                rebuild_bnk_payload._revalidate_historical_payload(
                    payload,
                    expected_marker_sha256="a" * 64,
                    expected_wem_ids=wem_ids,
                    expected_wem_name_digest="b" * 64,
                )

    def test_safe_output_tree_detects_replaced_directory_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output_parent = rebuild_bnk_payload._ensure_safe_directory_tree(
                root / "new" / "output",
                label="Árvore de teste",
                create=True,
            )
            snapshot = rebuild_bnk_payload._snapshot_directory(
                output_parent,
                label="Diretório de teste",
            )
            moved = root / "moved-output"
            output_parent.rename(moved)
            output_parent.mkdir()

            with self.assertRaisesRegex(
                rebuild_bnk_payload.RebuildError,
                "mudou durante a reconstrução",
            ):
                rebuild_bnk_payload._assert_directory_unchanged(
                    output_parent,
                    snapshot,
                    label="Diretório de teste",
                )

            blocker = root / "regular-file"
            blocker.write_bytes(b"not a directory")
            with self.assertRaisesRegex(
                rebuild_bnk_payload.RebuildError,
                "diretório real",
            ):
                rebuild_bnk_payload._ensure_safe_directory_tree(
                    blocker / "child",
                    label="Árvore bloqueada",
                    create=True,
                )

    def test_safe_output_tree_rejects_symlink_or_reparse(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target"
            target.mkdir()
            link = root / "linked-output"
            try:
                link.symlink_to(target, target_is_directory=True)
            except OSError as exc:  # pragma: no cover - política local do Windows
                self.skipTest(f"Links simbólicos indisponíveis: {exc}")

            with self.assertRaisesRegex(
                rebuild_bnk_payload.RebuildError,
                "sem link/reparse",
            ):
                rebuild_bnk_payload._ensure_safe_directory_tree(
                    link / "child",
                    label="Árvore com reparse",
                    create=True,
                )

    def test_exclusive_output_never_overwrites_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            parent_snapshot = rebuild_bnk_payload._snapshot_directory(
                parent,
                label="Diretório de teste",
            )
            protected = ((parent, parent_snapshot),)
            destination = parent / "manifest.json"
            snapshot = rebuild_bnk_payload._write_exclusive_regular(
                destination,
                b"first",
                label="Manifesto de teste",
                protected_directories=protected,
            )
            self.assertEqual(destination.read_bytes(), b"first")
            self.assertEqual(snapshot.size, 5)

            with self.assertRaisesRegex(
                rebuild_bnk_payload.RebuildError,
                "não será sobrescrito",
            ):
                rebuild_bnk_payload._write_exclusive_regular(
                    destination,
                    b"second",
                    label="Manifesto de teste",
                    protected_directories=protected,
                )
            self.assertEqual(destination.read_bytes(), b"first")

    def test_publish_rejects_replaced_staging_and_preserves_it(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            output = parent / "published"
            staging = parent / ".published.staging"
            staging.mkdir()
            parent_snapshot = rebuild_bnk_payload._snapshot_directory(
                parent,
                label="Diretório pai",
            )
            staging_snapshot = rebuild_bnk_payload._snapshot_directory(
                staging,
                label="Staging",
            )
            preserved = parent / "preserved-staging"
            staging.rename(preserved)
            staging.mkdir()

            with self.assertRaisesRegex(
                rebuild_bnk_payload.RebuildError,
                "mudou durante a reconstrução",
            ):
                rebuild_bnk_payload._publish_new_directory(
                    staging,
                    output,
                    output_parent_snapshot=parent_snapshot,
                    staging_snapshot=staging_snapshot,
                    expected_files={},
                    expected_directories={staging: staging_snapshot},
                )
            self.assertTrue(staging.is_dir())
            self.assertTrue(preserved.is_dir())
            self.assertFalse(output.exists())

    def test_atomic_directory_publish_never_replaces_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            staging = parent / ".published.staging"
            output = parent / "published"
            staging.mkdir()
            output.mkdir()
            (staging / "owned.txt").write_bytes(b"staging")
            (output / "foreign.txt").write_bytes(b"foreign")

            with self.assertRaises(OSError):
                rebuild_bnk_payload._rename_directory_no_replace(staging, output)

            self.assertEqual((staging / "owned.txt").read_bytes(), b"staging")
            self.assertEqual((output / "foreign.txt").read_bytes(), b"foreign")

    def test_publish_preserves_destination_created_after_collision_check(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            output = parent / "published"
            staging = parent / ".published.staging"
            staging.mkdir()
            proof = staging / "proof.txt"
            proof.write_bytes(b"complete")
            parent_snapshot = rebuild_bnk_payload._snapshot_directory(
                parent,
                label="Diretório pai",
            )
            staging_snapshot = rebuild_bnk_payload._snapshot_directory(
                staging,
                label="Staging",
            )
            proof_snapshot = rebuild_bnk_payload._snapshot_regular(
                proof,
                label="Prova",
            )
            real_publish = rebuild_bnk_payload._rename_directory_no_replace

            def race_destination(source: Path, destination: Path) -> None:
                destination.mkdir()
                (destination / "foreign.txt").write_bytes(b"foreign")
                real_publish(source, destination)

            with mock.patch.object(
                rebuild_bnk_payload,
                "_rename_directory_no_replace",
                side_effect=race_destination,
            ):
                with self.assertRaisesRegex(
                    rebuild_bnk_payload.RebuildError,
                    "Não foi possível publicar",
                ):
                    rebuild_bnk_payload._publish_new_directory(
                        staging,
                        output,
                        output_parent_snapshot=parent_snapshot,
                        staging_snapshot=staging_snapshot,
                        expected_files={
                            proof: (
                                proof_snapshot,
                                hashlib.sha256(b"complete").hexdigest(),
                            )
                        },
                        expected_directories={staging: staging_snapshot},
                    )

            self.assertEqual((staging / "proof.txt").read_bytes(), b"complete")
            self.assertEqual((output / "foreign.txt").read_bytes(), b"foreign")

    def test_publish_moves_unchanged_staging(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            output = parent / "published"
            staging = parent / ".published.staging"
            staging.mkdir()
            proof = staging / "proof.txt"
            proof.write_bytes(b"complete")
            parent_snapshot = rebuild_bnk_payload._snapshot_directory(
                parent,
                label="Diretório pai",
            )
            staging_snapshot = rebuild_bnk_payload._snapshot_directory(
                staging,
                label="Staging",
            )
            proof_snapshot = rebuild_bnk_payload._snapshot_regular(
                proof,
                label="Prova",
            )

            rebuild_bnk_payload._publish_new_directory(
                staging,
                output,
                output_parent_snapshot=parent_snapshot,
                staging_snapshot=staging_snapshot,
                expected_files={
                    proof: (
                        proof_snapshot,
                        hashlib.sha256(b"complete").hexdigest(),
                    )
                },
                expected_directories={staging: staging_snapshot},
            )

            self.assertFalse(staging.exists())
            self.assertEqual((output / "proof.txt").read_bytes(), b"complete")

    def test_publish_rehashes_final_name_and_preserves_invalid_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            output = parent / "published"
            staging = parent / ".published.staging"
            staging.mkdir()
            proof = staging / "proof.txt"
            proof.write_bytes(b"complete")
            parent_snapshot = rebuild_bnk_payload._snapshot_directory(
                parent,
                label="Diretório pai",
            )
            staging_snapshot = rebuild_bnk_payload._snapshot_directory(
                staging,
                label="Staging",
            )
            proof_snapshot = rebuild_bnk_payload._snapshot_regular(
                proof,
                label="Prova",
            )
            expected_files = {
                proof: (
                    proof_snapshot,
                    hashlib.sha256(b"complete").hexdigest(),
                )
            }
            expected_directories = {staging: staging_snapshot}
            real_validator = rebuild_bnk_payload._validate_staging_tree
            validations = 0

            def validate_then_tamper(*args, **kwargs) -> None:
                nonlocal validations
                validations += 1
                real_validator(*args, **kwargs)
                if validations == 1:
                    proof.write_bytes(b"TAMPER!!")
                    current = proof.stat()
                    os.utime(
                        proof,
                        ns=(current.st_atime_ns, proof_snapshot.mtime_ns),
                    )

            with mock.patch.object(
                rebuild_bnk_payload,
                "_validate_staging_tree",
                side_effect=validate_then_tamper,
            ):
                with self.assertRaisesRegex(
                    rebuild_bnk_payload.RebuildError,
                    "validação criptográfica pós-publicação",
                ):
                    rebuild_bnk_payload._publish_new_directory(
                        staging,
                        output,
                        output_parent_snapshot=parent_snapshot,
                        staging_snapshot=staging_snapshot,
                        expected_files=expected_files,
                        expected_directories=expected_directories,
                    )

            self.assertEqual(validations, 2)
            self.assertFalse(staging.exists())
            self.assertTrue(output.is_dir())
            self.assertEqual((output / "proof.txt").read_bytes(), b"TAMPER!!")

    def test_staging_inventory_rejects_extra_and_same_metadata_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            staging = Path(temp) / "staging"
            staging.mkdir()
            proof = staging / "proof.txt"
            proof.write_bytes(b"complete")
            staging_snapshot = rebuild_bnk_payload._snapshot_directory(
                staging,
                label="Staging",
            )
            proof_snapshot = rebuild_bnk_payload._snapshot_regular(
                proof,
                label="Prova",
            )
            expected_files = {
                proof: (
                    proof_snapshot,
                    hashlib.sha256(b"complete").hexdigest(),
                )
            }
            expected_directories = {staging: staging_snapshot}

            extra = staging / "extra.txt"
            extra.write_bytes(b"unexpected")
            with self.assertRaisesRegex(
                rebuild_bnk_payload.RebuildError,
                "Arquivo inesperado",
            ):
                rebuild_bnk_payload._validate_staging_tree(
                    staging,
                    expected_files=expected_files,
                    expected_directories=expected_directories,
                )
            extra.unlink()

            proof.write_bytes(b"tamper!!")
            current = proof.stat()
            os.utime(
                proof,
                ns=(current.st_atime_ns, proof_snapshot.mtime_ns),
            )
            with self.assertRaisesRegex(
                rebuild_bnk_payload.RebuildError,
                "SHA-256 final",
            ):
                rebuild_bnk_payload._validate_staging_tree(
                    staging,
                    expected_files=expected_files,
                    expected_directories=expected_directories,
                )

    def test_historical_payload_requires_pinned_tree_and_exact_marker(self) -> None:
        spec = patch_data.LEGACY_PAYLOAD_V081
        stats = patch_data.PayloadStats(
            wem_count=spec.wem_count,
            bnk_count=spec.bnk_count,
            total_size=spec.uncompressed_size,
            max_file_size=spec.max_file_size,
        )
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            marker = rebuild_bnk_payload._expected_payload_marker()
            (root / patch_data.MARKER_FILENAME).write_text(
                __import__("json").dumps(marker), encoding="utf-8"
            )
            with mock.patch.object(
                patch_data, "validate_patch_directory", return_value=stats
            ) as validator:
                digest = rebuild_bnk_payload.validate_historical_payload(root)
            self.assertEqual(len(digest), 64)
            validator.assert_called_once_with(root, spec=spec)

            marker["unexpected"] = True
            (root / patch_data.MARKER_FILENAME).write_text(
                __import__("json").dumps(marker), encoding="utf-8"
            )
            with mock.patch.object(
                patch_data, "validate_patch_directory", return_value=stats
            ):
                with self.assertRaisesRegex(
                    rebuild_bnk_payload.RebuildError,
                    "não corresponde exatamente",
                ):
                    rebuild_bnk_payload.validate_historical_payload(root)

    def test_final_validation_counts_changed_and_filtered_sounds(self) -> None:
        vanilla = _bank(_sound(10, 100, 1))
        translated = _bank(_sound(10, 100, 2))

        merged = bnk.merge_bnk_with_vanilla(
            vanilla, translated, external_wem_ids={100}
        )
        changed = rebuild_bnk_payload.validate_merged_bank(
            vanilla,
            translated,
            merged,
            external_wem_ids=frozenset({100}),
        )
        self.assertEqual(len(merged), len(vanilla))
        self.assertEqual(changed["sound_objects_changed"], 1)
        self.assertEqual(changed["sound_objects_filtered"], 0)

        preserved = bnk.merge_bnk_with_vanilla(
            vanilla, translated, external_wem_ids=set()
        )
        filtered = rebuild_bnk_payload.validate_merged_bank(
            vanilla,
            translated,
            preserved,
            external_wem_ids=frozenset(),
        )
        self.assertEqual(preserved, vanilla)
        self.assertEqual(filtered["sound_objects_changed"], 0)
        self.assertEqual(filtered["sound_objects_filtered"], 1)

    def test_final_validation_independently_rejects_unauthorized_sound_change(
        self,
    ) -> None:
        vanilla = _bank(_sound(10, 100, 1))
        translated = _bank(_sound(10, 100, 2))

        with self.assertRaisesRegex(
            rebuild_bnk_payload.RebuildError,
            "autorizada por WEM externo",
        ):
            rebuild_bnk_payload.validate_merged_bank(
                vanilla,
                translated,
                translated,
                external_wem_ids=frozenset(),
            )

        legitimate = bytearray(
            bnk.merge_bnk_with_vanilla(
                vanilla,
                translated,
                external_wem_ids={100},
            )
        )
        legitimate[-1] ^= 0x01
        with self.assertRaisesRegex(
            rebuild_bnk_payload.RebuildError,
            "autorizada por WEM externo",
        ):
            rebuild_bnk_payload.validate_merged_bank(
                vanilla,
                translated,
                bytes(legitimate),
                external_wem_ids=frozenset({100}),
            )

    def test_output_paths_allow_only_expected_root_and_enus_aliases(self) -> None:
        self.assertEqual(
            rebuild_bnk_payload._safe_output_relative("cs_main.bnk"),
            Path("cs_main.bnk"),
        )
        self.assertEqual(
            rebuild_bnk_payload._safe_output_relative("enus/cs_main.bnk"),
            Path("enus/cs_main.bnk"),
        )
        for unsafe in (
            "../cs_main.bnk",
            "enus/../cs_main.bnk",
            "other/cs_main.bnk",
            "enus/deep/cs_main.bnk",
            "enus/cs_main.txt",
        ):
            with self.subTest(unsafe=unsafe):
                with self.assertRaises(rebuild_bnk_payload.RebuildError):
                    rebuild_bnk_payload._safe_output_relative(unsafe)

    def test_duplicate_external_wem_ids_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "a").mkdir()
            (root / "b").mkdir()
            (root / "a" / "100.wem").write_bytes(b"a")
            (root / "b" / "100.wem").write_bytes(b"b")

            with self.assertRaisesRegex(
                rebuild_bnk_payload.RebuildError, "IDs WEM duplicados"
            ):
                rebuild_bnk_payload.collect_external_wem_ids(root)

    def test_named_regressions_are_fail_closed(self) -> None:
        records = [
            {
                "game_path": "enus/cs_main.bnk",
                "media_preserved_missing_from_payload": 3,
                "hirc_preserved_missing_from_payload": 234,
            },
            {
                "game_path": "enus/cs_m41.bnk",
                "media_preserved_missing_from_payload": 5,
            },
            {
                "game_path": "enus/vcmain.bnk",
                "sound_objects_filtered": 52,
                "sound_object_ids_filtered": list(
                    rebuild_bnk_payload.EXPECTED_VCMAIN_FILTERED_IDS
                ),
            },
        ]
        result = rebuild_bnk_payload._named_regressions(records)
        self.assertEqual(
            result["vcmain"]["type2_stale_objects_filtered_and_kept_vanilla"],
            52,
        )

        records[0]["hirc_preserved_missing_from_payload"] = 233
        with self.assertRaisesRegex(
            rebuild_bnk_payload.RebuildError, "esperado 234"
        ):
            rebuild_bnk_payload._named_regressions(records)

    def test_alias_tree_digest_is_order_independent(self) -> None:
        first = {
            "output_aliases": ["a.bnk", "enus/a.bnk"],
            "output_sha256": "01" * 32,
        }
        second = {
            "output_aliases": ["b.bnk", "enus/b.bnk"],
            "output_sha256": "02" * 32,
        }
        self.assertEqual(
            rebuild_bnk_payload._alias_tree_digest([first, second]),
            rebuild_bnk_payload._alias_tree_digest([second, first]),
        )

    def test_sound_object_identity_is_order_independent_and_fail_closed(self) -> None:
        first = {
            "output_path": "enus/a.bnk",
            "sound_object_ids_changed": [10, 20],
        }
        second = {
            "output_path": "enus/b.bnk",
            "sound_object_ids_changed": [30],
        }
        self.assertEqual(
            rebuild_bnk_payload._sound_object_identity(
                [first, second], "sound_object_ids_changed"
            ),
            rebuild_bnk_payload._sound_object_identity(
                [second, first], "sound_object_ids_changed"
            ),
        )
        first["sound_object_ids_changed"] = [20, 10]
        with self.assertRaisesRegex(
            rebuild_bnk_payload.RebuildError, "Lista"
        ):
            rebuild_bnk_payload._sound_object_identity(
                [first, second], "sound_object_ids_changed"
            )


if __name__ == "__main__":
    unittest.main()
