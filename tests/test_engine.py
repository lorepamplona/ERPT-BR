from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from patcher import engine


def make_bhd(entries: list[tuple[int, int, int, int]]) -> bytes:
    """Build the smallest plain BHD5 accepted by ``parse_bhd5``.

    Entries are ``(path_hash, padded_size, unpadded_size, bdt_offset)``.
    The synthetic fixtures intentionally omit SHA and AES metadata so the
    tests remain stdlib-only.
    """

    buckets_offset = 32
    entries_offset = buckets_offset + 8
    data = bytearray(entries_offset + 40 * len(entries))
    data[:4] = b"BHD5"
    data[4] = 0xFF
    struct.pack_into("<i", data, 8, 1)
    struct.pack_into("<i", data, 12, len(data))
    struct.pack_into("<i", data, 16, 1)
    struct.pack_into("<i", data, 20, buckets_offset)
    struct.pack_into("<i", data, 24, 0)
    struct.pack_into("<ii", data, buckets_offset, len(entries), entries_offset)
    for index, (path_hash, padded, unpadded, offset) in enumerate(entries):
        struct.pack_into(
            "<Qiiqqq",
            data,
            entries_offset + index * 40,
            path_hash,
            padded,
            unpadded,
            offset,
            0,
            0,
        )
    return bytes(data)


def make_bhd_with_sha(
    entries: list[
        tuple[int, int, int, int, bytes, tuple[tuple[int, int], ...]]
    ],
    salt: bytes,
) -> bytes:
    """Build a plain BHD5 whose entries contain salted SHA metadata."""

    buckets_offset = 28 + len(salt)
    entries_offset = buckets_offset + 8
    data = bytearray(entries_offset + 40 * len(entries))
    data[:4] = b"BHD5"
    data[4] = 0xFF
    struct.pack_into("<i", data, 8, 1)
    struct.pack_into("<i", data, 16, 1)
    struct.pack_into("<i", data, 20, buckets_offset)
    struct.pack_into("<i", data, 24, len(salt))
    data[28 : 28 + len(salt)] = salt
    struct.pack_into("<ii", data, buckets_offset, len(entries), entries_offset)

    for index, (path_hash, padded, unpadded, offset, digest, ranges) in enumerate(
        entries
    ):
        sha_offset = len(data)
        data.extend(digest)
        data.extend(struct.pack("<i", len(ranges)))
        for start, end in ranges:
            data.extend(struct.pack("<qq", start, end))
        struct.pack_into(
            "<Qiiqqq",
            data,
            entries_offset + index * 40,
            path_hash,
            padded,
            unpadded,
            offset,
            sha_offset,
            0,
        )
    struct.pack_into("<i", data, 12, len(data))
    return bytes(data)


def make_wem(fmt_data: bytes, audio_data: bytes, extra_hash: bytes = b"") -> bytes:
    chunks = bytearray()

    def add_chunk(chunk_id: bytes, value: bytes) -> None:
        chunks.extend(chunk_id)
        chunks.extend(struct.pack("<I", len(value)))
        chunks.extend(value)
        if len(value) & 1:
            chunks.append(0)

    add_chunk(b"fmt ", fmt_data)
    if extra_hash:
        add_chunk(b"hash", extra_hash)
    add_chunk(b"data", audio_data)
    return b"RIFF" + struct.pack("<I", len(chunks) + 4) + b"WAVE" + bytes(chunks)


def write_archive(
    sd_dir: Path,
    stem: str,
    entries: list[tuple[int, int, int, int]],
    bdt_data: bytes,
) -> tuple[Path, Path]:
    bhd_path = sd_dir / f"{stem}.bhd"
    bdt_path = sd_dir / f"{stem}.bdt"
    bhd_path.write_bytes(make_bhd(entries))
    bdt_path.write_bytes(bdt_data)
    return bhd_path, bdt_path


class BhdParsingTests(unittest.TestCase):
    def test_parse_valid_plain_bhd5(self) -> None:
        path_hash = 0x0123456789ABCDEF
        data = make_bhd([(path_hash, 8, 6, 4)])

        parsed = engine.parse_bhd5(data, bdt_size=12)

        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0].file_name_hash, path_hash)
        self.assertEqual(parsed[0].padded_file_size, 8)
        self.assertEqual(parsed[0].unpadded_file_size, 6)
        self.assertEqual(parsed[0].file_offset, 4)
        self.assertIsNone(parsed[0].sha_info)
        self.assertIsNone(parsed[0].aes_info)

    def test_parse_uses_declared_size_and_allows_rsa_padding_tail(self) -> None:
        data = make_bhd([(1, 8, 6, 4)])

        parsed = engine.parse_bhd5(data + b"\0" * 175, bdt_size=12)

        self.assertEqual(len(parsed), 1)

    def test_parse_rejects_non_little_endian_pc_header(self) -> None:
        data = bytearray(make_bhd([(1, 8, 6, 4)]))
        data[4] = 0

        with self.assertRaisesRegex(engine.CompatibilityError, "endian"):
            engine.parse_bhd5(bytes(data), bdt_size=12)

    def test_parse_rejects_truncated_entry_table(self) -> None:
        truncated = make_bhd([(1, 8, 6, 4)])[:-1]

        with self.assertRaises(engine.CompatibilityError):
            engine.parse_bhd5(truncated, bdt_size=12)

    def test_parse_rejects_slot_past_end_of_bdt(self) -> None:
        data = make_bhd([(1, 8, 6, 4)])

        with self.assertRaisesRegex(engine.CompatibilityError, "alem do BDT"):
            engine.parse_bhd5(data, bdt_size=11)

    def test_parse_rejects_negative_sha_or_aes_metadata_offsets(self) -> None:
        for field_offset in (24, 32):
            with self.subTest(field_offset=field_offset):
                data = bytearray(make_bhd([(1, 8, 6, 4)]))
                entry_offset = 32 + 8
                struct.pack_into("<q", data, entry_offset + field_offset, -1)
                with self.assertRaisesRegex(engine.CompatibilityError, "offset"):
                    engine.parse_bhd5(bytes(data), bdt_size=12)

    def test_parse_accepts_zero_sized_placeholder(self) -> None:
        data = make_bhd([(1, 0, 0, 12)])

        parsed = engine.parse_bhd5(data, bdt_size=12)

        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0].padded_file_size, 0)
        self.assertEqual(parsed[0].unpadded_file_size, 0)

    def test_parse_rejects_inconsistent_zero_sizes(self) -> None:
        for padded, unpadded in ((0, 1), (8, 0)):
            with self.subTest(padded=padded, unpadded=unpadded):
                data = make_bhd([(1, padded, unpadded, 0)])

                with self.assertRaisesRegex(
                    engine.CompatibilityError, "tamanhos/offset"
                ):
                    engine.parse_bhd5(data, bdt_size=8)

    def test_parse_rejects_non_block_aligned_aes_range(self) -> None:
        data = bytearray(make_bhd([(1, 32, 32, 0)]))
        aes_offset = len(data)
        struct.pack_into("<q", data, 40 + 32, aes_offset)
        data.extend(b"K" * 16)
        data.extend(struct.pack("<iqq", 1, 0, 17))
        struct.pack_into("<i", data, 12, len(data))

        with self.assertRaisesRegex(engine.CompatibilityError, "multiplo de 16"):
            engine.parse_bhd5(bytes(data), bdt_size=32)

    def test_parse_accepts_unilateral_unused_range_sentinels(self) -> None:
        for start, end in ((-1, 16), (0, -1)):
            with self.subTest(start=start, end=end):
                data = bytearray(make_bhd([(1, 32, 32, 0)]))
                aes_offset = len(data)
                struct.pack_into("<q", data, 40 + 32, aes_offset)
                data.extend(b"K" * 16)
                data.extend(struct.pack("<iqq", 1, start, end))
                struct.pack_into("<i", data, 12, len(data))

                parsed = engine.parse_bhd5(bytes(data), bdt_size=32)

                self.assertEqual(
                    parsed[0].aes_info.ranges,
                    (engine.AESRange(start, end),),
                )


class PayloadPreparationTests(unittest.TestCase):
    def test_hash_path_has_stable_known_vector_and_normalization(self) -> None:
        expected = 0xD86461F5BD5581EC

        self.assertEqual(engine.hash_path("enus/wem/12/123.wem"), expected)
        self.assertEqual(engine.hash_path("/ENUS\\WEM\\12\\123.WEM/"), expected)

    def test_normalize_wem_removes_hash_chunk_without_truncating_audio(self) -> None:
        fmt_data = b"\x01\x00\x02\x00"
        audio_data = b"dubbed-audio"
        source = make_wem(fmt_data, audio_data, extra_hash=b"auxiliary-hash")

        normalized = engine.normalize_wem(source, target_size=64)

        self.assertEqual(len(normalized), 64)
        self.assertEqual(normalized[:4], b"RIFF")
        self.assertEqual(struct.unpack_from("<I", normalized, 4)[0], 56)
        self.assertNotIn(b"hash", normalized)
        normalized_fmt, normalized_audio = engine._riff_chunks(normalized)
        self.assertEqual(normalized_fmt, fmt_data)
        self.assertTrue(normalized_audio.startswith(audio_data))
        self.assertEqual(
            normalized_audio[len(audio_data) :],
            b"\0" * (len(normalized_audio) - len(audio_data)),
        )

    def test_normalize_wem_rejects_logical_slot_overflow(self) -> None:
        source = make_wem(b"fmt!", b"audio")

        with self.assertRaisesRegex(
            engine.CompatibilityError, "maior que o slot logico"
        ):
            engine.normalize_wem(source, target_size=36)

    def test_prepare_slot_rejects_bnk_larger_than_unpadded_size(self) -> None:
        entry = engine.FileEntry(
            file_name_hash=1,
            padded_file_size=8,
            unpadded_file_size=4,
            file_offset=0,
            sha_hash_offset=0,
            aes_key_offset=0,
        )

        with self.assertRaisesRegex(engine.CompatibilityError, "BNK maior"):
            engine.prepare_slot(b"12345", ".bnk", entry)

    def test_encrypt_rejects_non_block_aligned_aes_range_before_crypto(self) -> None:
        with self.assertRaisesRegex(engine.CompatibilityError, "multiplo de 16"):
            engine.encrypt_aes_ecb(
                bytearray(32),
                b"K" * 16,
                (engine.AESRange(0, 17),),
            )

    def test_encrypt_skips_range_when_either_endpoint_is_unused(self) -> None:
        original = bytearray(b"A" * 32)

        result = engine.encrypt_aes_ecb(
            bytearray(original),
            b"K" * 16,
            (engine.AESRange(-1, 16), engine.AESRange(0, -1)),
        )

        self.assertEqual(result, original)

    def test_encrypt_aes_ecb_matches_nist_known_answer(self) -> None:
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plaintext = bytearray.fromhex("00112233445566778899aabbccddeeff")
        expected = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

        result = engine.encrypt_aes_ecb(
            plaintext,
            key,
            (engine.AESRange(0, 16),),
        )

        self.assertEqual(bytes(result), expected)


class PatchEngineTests(unittest.TestCase):
    def _make_engine_with_two_archives(
        self,
        root: Path,
        payload_name: str = "voice.bnk",
    ) -> tuple[engine.PatchEngine, Path, dict[str, bytes], int, int]:
        game_dir = root / "Game"
        sd_dir = game_dir / "sd"
        sd_dir.mkdir(parents=True)
        file_hash = engine.hash_path(payload_name)
        slot_offset = 4
        slot_padded = 8
        slot_unpadded = 6
        originals = {
            "sd.bdt": b"A" * 16,
            "sd_dlc02.bdt": b"B" * 16,
        }
        for stem, bdt_data in (
            ("sd", originals["sd.bdt"]),
            ("sd_dlc02", originals["sd_dlc02.bdt"]),
        ):
            write_archive(
                sd_dir,
                stem,
                [(file_hash, slot_padded, slot_unpadded, slot_offset)],
                bdt_data,
            )
        patcher = engine.PatchEngine(game_dir, backup_root=root / "backups")
        return patcher, game_dir, originals, slot_offset, slot_padded

    def test_load_archives_discovers_sd_and_sd_dlc02_dynamically(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, game_dir, _originals, _offset, _size = (
                self._make_engine_with_two_archives(root)
            )
            # This resembles an sd file but is outside the explicitly allowed naming scheme.
            (game_dir / "sd" / "sd_extra.bhd").write_bytes(b"not a BHD")

            entry_count = patcher.load_archives()

            self.assertEqual(entry_count, 2)
            self.assertEqual(
                [item.bhd_path.name for item in patcher.archives],
                ["sd.bhd", "sd_dlc02.bhd"],
            )

    def test_duplicate_hash_is_installed_in_both_bdts_then_restored(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, game_dir, originals, slot_offset, slot_padded = (
                self._make_engine_with_two_archives(root)
            )
            payload_dir = root / "payload"
            payload_dir.mkdir()
            payload = b"VOICE"
            (payload_dir / "voice.bnk").write_bytes(payload)
            patcher.load_archives()

            plan = patcher.build_plan(payload_dir)

            self.assertEqual(plan.payload_file_count, 1)
            self.assertEqual(plan.matched_file_count, 1)
            self.assertEqual(len(plan.writes), 2)
            self.assertEqual(len(plan.touched_archives), 2)
            written, unmatched = patcher.apply_plan(plan)
            self.assertEqual((written, unmatched), (2, 0))

            expected_slot = payload + b"\0" * (slot_padded - len(payload))
            for name in originals:
                current = (game_dir / "sd" / name).read_bytes()
                self.assertEqual(
                    current[slot_offset : slot_offset + slot_padded], expected_slot
                )
                self.assertEqual(current[:slot_offset], originals[name][:slot_offset])
                self.assertEqual(
                    current[slot_offset + slot_padded :],
                    originals[name][slot_offset + slot_padded :],
                )

            manifests = list((root / "backups").glob("*/*/manifest.json"))
            self.assertEqual(len(manifests), 1)
            manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
            self.assertEqual(
                {record["bdt"] for record in manifest["archives"]}, set(originals)
            )
            self.assertEqual(manifest["state"], "applied")

            patcher.restore_current_backup()

            for name, original in originals.items():
                self.assertEqual((game_dir / "sd" / name).read_bytes(), original)
            restored_manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
            self.assertEqual(restored_manifest["state"], "restored")

    def test_identical_root_and_enus_aliases_share_one_physical_write(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            game_dir = root / "Game"
            sd_dir = game_dir / "sd"
            sd_dir.mkdir(parents=True)
            original = b"O" * 16
            write_archive(
                sd_dir,
                "sd",
                [(engine.hash_path("enus/cs_voice.bnk"), 8, 6, 4)],
                original,
            )
            payload_dir = root / "payload"
            (payload_dir / "enus").mkdir(parents=True)
            payload = b"VOICE"
            (payload_dir / "cs_voice.bnk").write_bytes(payload)
            (payload_dir / "enus" / "cs_voice.bnk").write_bytes(payload)
            patcher = engine.PatchEngine(game_dir, backup_root=root / "backups")
            patcher.load_archives()

            plan = patcher.build_plan(payload_dir)

            self.assertEqual(plan.payload_file_count, 2)
            self.assertEqual(plan.matched_file_count, 2)
            self.assertEqual(len(plan.payload_file_sha256), 2)
            self.assertEqual(len(plan.writes), 1)
            self.assertEqual(
                plan.writes[0].replacement.source_relative,
                "enus/cs_voice.bnk",
            )
            written, unmatched = patcher.apply_plan(plan)
            self.assertEqual((written, unmatched), (1, 0))
            self.assertEqual(
                (sd_dir / "sd.bdt").read_bytes()[4:12],
                payload + b"\0" * 3,
            )

            patcher.restore_current_backup()
            self.assertEqual((sd_dir / "sd.bdt").read_bytes(), original)

    def test_different_root_and_enus_aliases_are_rejected_before_backup(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            game_dir = root / "Game"
            sd_dir = game_dir / "sd"
            sd_dir.mkdir(parents=True)
            original = b"O" * 16
            write_archive(
                sd_dir,
                "sd",
                [(engine.hash_path("enus/voice.bnk"), 8, 6, 4)],
                original,
            )
            payload_dir = root / "payload"
            (payload_dir / "enus").mkdir(parents=True)
            (payload_dir / "voice.bnk").write_bytes(b"VOICE")
            # O zero final produz o mesmo slot preenchido que b"VOICE", mas o
            # arquivo-fonte nao e byte-identico e deve continuar sendo recusado.
            (payload_dir / "enus" / "voice.bnk").write_bytes(b"VOICE\0")
            patcher = engine.PatchEngine(game_dir, backup_root=root / "backups")
            patcher.load_archives()

            with self.assertRaisesRegex(
                engine.CompatibilityError,
                "conteudos diferentes",
            ):
                patcher.build_plan(payload_dir)

            self.assertEqual((sd_dir / "sd.bdt").read_bytes(), original)
            self.assertFalse((root / "backups").exists())

    def test_alias_changed_during_collision_check_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            game_dir = root / "Game"
            sd_dir = game_dir / "sd"
            sd_dir.mkdir(parents=True)
            original = b"O" * 16
            write_archive(
                sd_dir,
                "sd",
                [(engine.hash_path("enus/cs_voice.bnk"), 8, 6, 4)],
                original,
            )
            payload_dir = root / "payload"
            (payload_dir / "enus").mkdir(parents=True)
            root_alias = payload_dir / "cs_voice.bnk"
            root_alias.write_bytes(b"VOICE")
            (payload_dir / "enus" / "cs_voice.bnk").write_bytes(b"VOICE")
            patcher = engine.PatchEngine(game_dir, backup_root=root / "backups")
            patcher.load_archives()
            original_read_bytes = Path.read_bytes
            root_reads = 0

            def racing_read_bytes(path: Path) -> bytes:
                nonlocal root_reads
                if path == root_alias:
                    root_reads += 1
                    if root_reads > 1:
                        return b"CHANGED"
                return original_read_bytes(path)

            with mock.patch.object(Path, "read_bytes", racing_read_bytes):
                with self.assertRaisesRegex(
                    engine.CompatibilityError,
                    "mudou durante o planejamento",
                ):
                    patcher.build_plan(payload_dir)

            self.assertEqual((sd_dir / "sd.bdt").read_bytes(), original)
            self.assertFalse((root / "backups").exists())

    def test_same_offset_with_different_slot_metadata_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            game_dir = root / "Game"
            sd_dir = game_dir / "sd"
            sd_dir.mkdir(parents=True)
            original = b"O" * 20
            write_archive(
                sd_dir,
                "sd",
                [
                    (engine.hash_path("first.bnk"), 8, 6, 4),
                    (engine.hash_path("second.bnk"), 10, 6, 4),
                ],
                original,
            )
            payload_dir = root / "payload"
            payload_dir.mkdir()
            (payload_dir / "first.bnk").write_bytes(b"VOICE")
            (payload_dir / "second.bnk").write_bytes(b"VOICE")
            patcher = engine.PatchEngine(game_dir, backup_root=root / "backups")
            patcher.load_archives()

            with self.assertRaisesRegex(
                engine.CompatibilityError,
                "metadados de slot diferentes",
            ):
                patcher.build_plan(payload_dir)

            self.assertEqual((sd_dir / "sd.bdt").read_bytes(), original)
            self.assertFalse((root / "backups").exists())

    def test_build_plan_rejects_payload_below_minimum_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            game_dir = root / "Game"
            sd_dir = game_dir / "sd"
            sd_dir.mkdir(parents=True)
            original = b"O" * 16
            write_archive(
                sd_dir,
                "sd",
                [(engine.hash_path("voice.bnk"), 8, 6, 4)],
                original,
            )
            payload_dir = root / "payload"
            payload_dir.mkdir()
            (payload_dir / "voice.bnk").write_bytes(b"VOICE")
            (payload_dir / "missing.bnk").write_bytes(b"OTHER")
            patcher = engine.PatchEngine(game_dir, backup_root=root / "backups")
            patcher.load_archives()

            with self.assertRaisesRegex(
                engine.CompatibilityError, "1/2 arquivos encontrados"
            ):
                patcher.build_plan(payload_dir)

            self.assertEqual((sd_dir / "sd.bdt").read_bytes(), original)
            self.assertFalse((root / "backups").exists())

    def test_plan_hashes_unmatched_payload_files_when_coverage_allows_them(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            game_dir = root / "Game"
            sd_dir = game_dir / "sd"
            sd_dir.mkdir(parents=True)
            write_archive(
                sd_dir,
                "sd",
                [(engine.hash_path("voice.bnk"), 8, 6, 4)],
                b"O" * 16,
            )
            payload_dir = root / "payload"
            payload_dir.mkdir()
            (payload_dir / "voice.bnk").write_bytes(b"VOICE")
            (payload_dir / "missing.bnk").write_bytes(b"OTHER")
            patcher = engine.PatchEngine(game_dir, backup_root=root / "backups")
            patcher.load_archives()

            plan = patcher.build_plan(payload_dir, min_match_ratio=0.5)

            self.assertEqual(plan.payload_file_count, 2)
            self.assertEqual(plan.matched_file_count, 1)
            self.assertEqual(plan.unmatched_files, ("missing.bnk",))
            self.assertEqual(
                set(dict(plan.payload_file_sha256)),
                {"voice.bnk", "missing.bnk"},
            )

    def test_legacy_original_backup_blocks_installation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, game_dir, originals, _offset, _size = (
                self._make_engine_with_two_archives(root)
            )
            payload_dir = root / "payload"
            payload_dir.mkdir()
            (payload_dir / "voice.bnk").write_bytes(b"VOICE")
            patcher.load_archives()
            plan = patcher.build_plan(payload_dir)
            (game_dir / "sd" / "sd.bdt.original").write_bytes(originals["sd.bdt"])

            with self.assertRaisesRegex(engine.LegacyBackupError, "instalador antigo"):
                patcher.apply_plan(plan)

            for name, original in originals.items():
                self.assertEqual((game_dir / "sd" / name).read_bytes(), original)

    def test_partial_orphan_stages_are_preserved_before_a_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, game_dir, _originals, _offset, _size = (
                self._make_engine_with_two_archives(root)
            )
            payload = root / "payload"
            payload.mkdir()
            (payload / "voice.bnk").write_bytes(b"VOICE")
            patcher.load_archives()
            stale_stage = game_dir / "sd" / ".sd.bdt.erptbr-stage-dead.tmp"
            stale_restore = game_dir / "sd" / ".sd_dlc02.bdt.erptbr-restore-dead.tmp"
            stale_stage.write_bytes(b"partial")
            stale_restore.write_bytes(b"partial")

            patcher.apply_plan(patcher.build_plan(payload))

            self.assertEqual(stale_stage.read_bytes(), b"partial")
            self.assertEqual(stale_restore.read_bytes(), b"partial")

    def test_non_object_backup_manifest_is_a_controlled_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, _game_dir, _originals, _offset, _size = (
                self._make_engine_with_two_archives(root)
            )
            patcher.load_archives()
            manager = patcher._backup_manager(patcher.archives)
            manager.directory.mkdir(parents=True)
            manager.manifest_path.write_text("[]", encoding="utf-8")

            with self.assertRaisesRegex(engine.BackupError, "invalido"):
                manager._load_manifest()

    def test_current_manifest_with_duplicate_archive_is_a_controlled_error(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, _game_dir, _originals, _offset, _size = (
                self._make_engine_with_two_archives(root)
            )
            patcher.load_archives()
            manager = patcher._backup_manager(patcher.archives)
            with manager.operation_lock():
                manager.prepare()
            manifest = json.loads(manager.manifest_path.read_text(encoding="utf-8"))
            manifest["archives"] = [manifest["archives"][0]] * 2
            manager.manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            with manager.operation_lock():
                with self.assertRaisesRegex(engine.BackupError, "inesperado"):
                    manager.prepare()

    def test_malformed_transaction_maps_are_a_controlled_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, game_dir, originals, _offset, _size = (
                self._make_engine_with_two_archives(root)
            )
            patcher.load_archives()
            manager = patcher._backup_manager(patcher.archives)
            with manager.operation_lock():
                manager.prepare()
            manifest = json.loads(manager.manifest_path.read_text(encoding="utf-8"))
            transaction_id = "a" * 32
            manifest["state"] = "committing"
            manifest["transaction"] = {
                "id": transaction_id,
                "kind": "apply",
                "previous_state": "prepared",
                "pre_sha256": ["sd.bdt"],
                "new_sha256": {},
                "previous_patched_sha256": {},
                "rollback_files": {},
                "displaced_files": {},
            }
            manager.manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            with manager.operation_lock():
                with self.assertRaisesRegex(engine.BackupError, "mapa pre_sha256"):
                    manager.prepare()

            for name, original in originals.items():
                self.assertEqual((game_dir / "sd" / name).read_bytes(), original)

    def test_atomic_manifest_collision_preserves_preexisting_hardlink(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            destination = root / "manifest.json"
            victim = root / "victim.txt"
            victim.write_bytes(b"PRESERVE")
            fixed_hex = "a" * 32
            scratch = root / f".{destination.name}.{fixed_hex}.tmp"
            os.link(victim, scratch)
            fixed_uuid = mock.Mock(hex=fixed_hex)

            with mock.patch.object(engine.uuid, "uuid4", return_value=fixed_uuid):
                with self.assertRaisesRegex(engine.BackupError, "preservado"):
                    engine._atomic_json(destination, {"safe": True})

            self.assertEqual(victim.read_bytes(), b"PRESERVE")
            self.assertTrue(scratch.exists())

    def test_owned_publish_retracts_file_if_a_hardlink_appears(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "private-stage.tmp"
            destination = root / "sd.bdt"
            alias = root / "attacker-alias.bin"
            source.write_bytes(b"EXPECTED")
            identity = engine._regular_file_identity(source, label="stage")
            real_publish = engine._publish_without_replace

            def publish_then_link(src: Path, dst: Path) -> None:
                real_publish(src, dst)
                if dst == destination:
                    os.link(destination, alias)

            with mock.patch.object(
                engine, "_publish_without_replace", side_effect=publish_then_link
            ):
                with self.assertRaisesRegex(engine.BackupError, "hardlink"):
                    engine._publish_owned_without_replace(source, destination, identity)

            self.assertFalse(destination.exists())
            self.assertEqual(source.read_bytes(), b"EXPECTED")
            self.assertEqual(alias.read_bytes(), b"EXPECTED")

    def test_live_hash_rejects_hardlink(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            live = root / "sd.bdt"
            alias = root / "alias.bdt"
            live.write_bytes(b"audio")
            os.link(live, alias)

            with self.assertRaisesRegex(engine.BackupError, "hardlink"):
                engine._sha256_if_file(live)

    def test_partial_baseline_directory_is_preserved_before_backup_creation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, _game_dir, _originals, _offset, _size = (
                self._make_engine_with_two_archives(root)
            )
            patcher.load_archives()
            manager = patcher._backup_manager(patcher.archives)
            stale = manager.directory.parent / f".{manager.fingerprint[:12]}-deadbeef"
            stale.mkdir(parents=True)
            (stale / "sd.bdt.backup").write_bytes(b"partial")

            with manager.operation_lock():
                manager.prepare()

            self.assertEqual((stale / "sd.bdt.backup").read_bytes(), b"partial")
            self.assertTrue(manager.manifest_path.is_file())

    def test_same_size_change_during_first_backup_is_never_blessed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, game_dir, originals, _offset, _size = (
                self._make_engine_with_two_archives(root)
            )
            payload = root / "payload"
            payload.mkdir()
            (payload / "voice.bnk").write_bytes(b"VOICE")
            patcher.load_archives()
            manager = patcher._backup_manager(patcher.archives)
            real_copy = engine._copy_with_sha256
            changed = False
            external = b"X" * len(originals["sd.bdt"])

            def change_before_copy(source: Path, destination: Path) -> str:
                nonlocal changed
                if not changed and destination.name == "sd.bdt.backup":
                    source.write_bytes(external)
                    changed = True
                return real_copy(source, destination)

            with mock.patch.object(
                engine, "_copy_with_sha256", side_effect=change_before_copy
            ):
                with self.assertRaisesRegex(
                    engine.BackupError, "baseline nao foi criado"
                ):
                    patcher.apply_plan(patcher.build_plan(payload))

            self.assertTrue(changed)
            self.assertEqual((game_dir / "sd" / "sd.bdt").read_bytes(), external)
            self.assertFalse(list((root / "backups").glob("*/*/manifest.json")))
            residues = list(
                manager.directory.parent.glob(f".{manager.fingerprint[:12]}-*")
            )
            self.assertEqual(len(residues), 1)
            self.assertTrue(residues[0].is_dir())

    def test_racing_baseline_directory_is_not_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / ".prepared-backup"
            destination = root / ("a" * 64)
            source.mkdir()
            (source / "manifest.json").write_text("{}", encoding="utf-8")
            real_rename = engine.os.rename

            def create_external_then_rename(src: Path, dst: Path) -> None:
                destination.mkdir()
                (destination / "external.txt").write_text("preserve", encoding="utf-8")
                real_rename(src, dst)

            with mock.patch.object(
                engine.os, "rename", side_effect=create_external_then_rename
            ):
                with self.assertRaises(engine.BackupError):
                    engine._rename_directory_without_replace(source, destination)

            self.assertEqual(
                (destination / "external.txt").read_text(encoding="utf-8"),
                "preserve",
            )
            self.assertTrue(source.is_dir())

    def test_partial_baseline_from_prior_fingerprint_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, _game_dir, _originals, _offset, _size = (
                self._make_engine_with_two_archives(root)
            )
            patcher.load_archives()
            manager = patcher._backup_manager(patcher.archives)
            prior = manager.directory.parent / ".0123456789ab-deadbeef"
            prior.mkdir(parents=True)
            (prior / "sd.bdt.backup").write_bytes(b"partial")
            unrelated = manager.directory.parent / ".not-erptbr-user-data"
            unrelated.mkdir()

            with manager.operation_lock():
                manager.prepare()

            self.assertEqual((prior / "sd.bdt.backup").read_bytes(), b"partial")
            self.assertTrue(unrelated.is_dir())
            self.assertTrue(manager.manifest_path.is_file())

    def test_moved_library_while_patched_is_never_blessed_as_original(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, game_dir, _originals, _offset, _size = (
                self._make_engine_with_two_archives(root)
            )
            payload = root / "payload"
            payload.mkdir()
            (payload / "voice.bnk").write_bytes(b"VOICE")
            patcher.load_archives()
            patcher.apply_plan(patcher.build_plan(payload))

            moved_parent = root / "MovedLibrary"
            moved_parent.mkdir()
            moved_game = moved_parent / "Game"
            shutil.move(str(game_dir), str(moved_game))

            fresh = engine.PatchEngine(moved_game, backup_root=root / "backups")
            fresh.load_archives()
            with self.assertRaisesRegex(engine.BackupError, "outra localizacao"):
                fresh.apply_plan(fresh.build_plan(payload))

            self.assertFalse(
                list(
                    (
                        root / "backups" / fresh._backup_manager(fresh.archives).game_id
                    ).glob("*/manifest.json")
                )
            )

    def test_orphan_backup_gc_preserves_manifest_and_unexpected_content(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, _game_dir, _originals, _offset, _size = (
                self._make_engine_with_two_archives(root)
            )
            patcher.load_archives()
            manager = patcher._backup_manager(patcher.archives)
            parent = manager.directory.parent
            with_manifest = parent / ".0123456789ab-abcdefgh"
            with_manifest.mkdir(parents=True)
            (with_manifest / "manifest.json").write_text("{}", encoding="utf-8")
            unexpected = parent / ".fedcba987654-12345678"
            unexpected.mkdir()
            (unexpected / "user.txt").write_text("keep", encoding="utf-8")

            manager.cleanup_orphan_backup_staging()

            self.assertTrue((with_manifest / "manifest.json").is_file())
            self.assertEqual(
                (unexpected / "user.txt").read_text(encoding="utf-8"), "keep"
            )

    def test_completed_foreign_journal_is_cleaned_after_fingerprint_change(
        self,
    ) -> None:
        for state, cleanup_only in (("prepared", True), ("applied", False)):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                patcher, game_dir, originals, _offset, _size = (
                    self._make_engine_with_two_archives(root)
                )
                patcher.load_archives()
                old_manager = patcher._backup_manager(patcher.archives)
                with old_manager.operation_lock():
                    manifest, _created, _hashes = old_manager.prepare()
                transaction_id = "a" * 32
                name = "sd.bdt"
                rollback_name = f".erptbr-{transaction_id}-{name}.rollback"
                displaced_name = f".erptbr-{transaction_id}-{name}.displaced"
                rollback = game_dir / "sd" / rollback_name
                rollback.write_bytes(originals[name])
                original_digest = engine.sha256_file(rollback)
                transaction = {
                    "id": transaction_id,
                    "kind": "apply",
                    "previous_state": "prepared",
                    "pre_sha256": {name: original_digest},
                    "new_sha256": {name: original_digest},
                    "rollback_files": {name: rollback_name},
                    "displaced_files": {name: displaced_name},
                }
                if cleanup_only:
                    transaction["cleanup_only"] = True
                manifest["state"] = state
                manifest["transaction"] = transaction
                old_manager.save_manifest(manifest)

                # A valid padding tail changes the BHD hash/fingerprint without
                # changing its declared logical BHD5 contents.
                (game_dir / "sd" / "sd.bhd").write_bytes(
                    (game_dir / "sd" / "sd.bhd").read_bytes() + b"\0"
                )
                fresh = engine.PatchEngine(game_dir, backup_root=root / "backups")
                fresh.load_archives()
                new_manager = fresh._backup_manager(fresh.archives)
                with new_manager.operation_lock():
                    new_manager.prepare()

                self.assertFalse(rollback.exists())
                old_saved = json.loads(
                    old_manager.manifest_path.read_text(encoding="utf-8")
                )
                self.assertNotIn("transaction", old_saved)
                self.assertTrue(new_manager.manifest_path.is_file())

    def test_foreign_cleanup_preserves_journal_with_extra_file_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, game_dir, originals, _offset, _size = (
                self._make_engine_with_two_archives(root)
            )
            patcher.load_archives()
            old_manager = patcher._backup_manager(patcher.archives)
            with old_manager.operation_lock():
                manifest, _created, _hashes = old_manager.prepare()

            transaction_id = "a" * 32
            name = "sd.bdt"
            extra_name = "sd_dlc99.bdt"
            rollback_name = f".erptbr-{transaction_id}-{name}.rollback"
            displaced_name = f".erptbr-{transaction_id}-{name}.displaced"
            extra_rollback_name = f".erptbr-{transaction_id}-{extra_name}.rollback"
            extra_displaced_name = f".erptbr-{transaction_id}-{extra_name}.displaced"
            rollback = game_dir / "sd" / rollback_name
            rollback.write_bytes(originals[name])
            extra_rollback = game_dir / "sd" / extra_rollback_name
            extra_displaced = game_dir / "sd" / extra_displaced_name
            extra_rollback.write_bytes(b"EXTRA-ROLLBACK")
            extra_displaced.write_bytes(b"EXTRA-DISPLACED")
            digest = engine.sha256_file(rollback)
            manifest["state"] = "applied"
            manifest["transaction"] = {
                "id": transaction_id,
                "kind": "apply",
                "previous_state": "prepared",
                "pre_sha256": {name: digest},
                "new_sha256": {name: digest},
                "rollback_files": {
                    name: rollback_name,
                    extra_name: extra_rollback_name,
                },
                "displaced_files": {
                    name: displaced_name,
                    extra_name: extra_displaced_name,
                },
            }
            old_manager.save_manifest(manifest)

            bhd = game_dir / "sd" / "sd.bhd"
            bhd.write_bytes(bhd.read_bytes() + b"\0")
            fresh = engine.PatchEngine(game_dir, backup_root=root / "backups")
            fresh.load_archives()
            with fresh._backup_manager(fresh.archives).operation_lock():
                with self.assertRaisesRegex(
                    engine.BackupError, "transacao interrompida"
                ):
                    fresh._backup_manager(fresh.archives).prepare()

            saved = json.loads(old_manager.manifest_path.read_text(encoding="utf-8"))
            self.assertIn("transaction", saved)
            self.assertTrue(rollback.exists())
            self.assertEqual(extra_rollback.read_bytes(), b"EXTRA-ROLLBACK")
            self.assertEqual(extra_displaced.read_bytes(), b"EXTRA-DISPLACED")

    def test_partial_commit_failure_rolls_back_both_bdts(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, game_dir, originals, _offset, _size = (
                self._make_engine_with_two_archives(root)
            )
            payload_dir = root / "payload"
            payload_dir.mkdir()
            (payload_dir / "voice.bnk").write_bytes(b"VOICE")
            patcher.load_archives()
            plan = patcher.build_plan(payload_dir)

            real_publish = engine._publish_without_replace
            failure_injected = False

            def fail_second_stage_commit(source: Path, destination: Path) -> None:
                nonlocal failure_injected
                source_path = Path(source)
                destination_path = Path(destination)
                if (
                    not failure_injected
                    and ".erptbr-stage-" in source_path.name
                    and destination_path.name == "sd_dlc02.bdt"
                ):
                    failure_injected = True
                    raise OSError("falha de commit injetada")
                real_publish(source_path, destination_path)

            with mock.patch.object(
                engine, "_publish_without_replace", side_effect=fail_second_stage_commit
            ):
                with self.assertRaisesRegex(
                    engine.PatcherError, "estado anterior foi restaurado"
                ):
                    patcher.apply_plan(plan)

            self.assertTrue(failure_injected)
            for name, original in originals.items():
                self.assertEqual((game_dir / "sd" / name).read_bytes(), original)
            manifests = list((root / "backups").glob("*/*/manifest.json"))
            self.assertEqual(len(manifests), 1)
            manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
            self.assertEqual(manifest["state"], "prepared")

    def test_recover_pending_never_publishes_a_swapped_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            patcher, game_dir, originals, _offset, _size = (
                self._make_engine_with_two_archives(root)
            )
            payload = root / "payload"
            payload.mkdir()
            (payload / "voice.bnk").write_bytes(b"VOICE")
            patcher.load_archives()
            real_publish = engine._publish_without_replace
            commit_failed = False
            rollback_swapped = False
            live = game_dir / "sd" / "sd.bdt"

            def fail_commit_then_swap_rollback(source: Path, destination: Path) -> None:
                nonlocal commit_failed, rollback_swapped
                if (
                    not commit_failed
                    and ".erptbr-stage-" in source.name
                    and destination.name == "sd_dlc02.bdt"
                ):
                    commit_failed = True
                    raise OSError("falha de commit injetada")
                if (
                    commit_failed
                    and not rollback_swapped
                    and source.name.endswith("-sd.bdt.rollback")
                    and destination == live
                ):
                    source.unlink()
                    source.write_bytes(b"Z" * len(originals["sd.bdt"]))
                    rollback_swapped = True
                real_publish(source, destination)

            with mock.patch.object(
                engine,
                "_publish_without_replace",
                side_effect=fail_commit_then_swap_rollback,
            ):
                with self.assertRaisesRegex(
                    engine.BackupError, "nao foi possivel confirmar"
                ):
                    patcher.apply_plan(patcher.build_plan(payload))

            self.assertTrue(commit_failed)
            self.assertTrue(rollback_swapped)
            self.assertFalse(live.exists())
            rollback = next((game_dir / "sd").glob("*-sd.bdt.rollback"))
            self.assertEqual(rollback.read_bytes(), b"Z" * len(originals["sd.bdt"]))

    def test_external_file_racing_into_rollback_name_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, game_dir, originals, _offset, _size = (
                self._make_engine_with_two_archives(root)
            )
            payload = root / "payload"
            payload.mkdir()
            (payload / "voice.bnk").write_bytes(b"VOICE")
            patcher.load_archives()
            real_publish = engine._publish_without_replace
            raced_path: Path | None = None
            external = b"EXTERNAL-RACE"

            def race_rollback(source: Path, destination: Path) -> None:
                nonlocal raced_path
                if raced_path is None and destination.name.endswith(".rollback"):
                    destination.write_bytes(external)
                    raced_path = destination
                real_publish(source, destination)

            with mock.patch.object(
                engine, "_publish_without_replace", side_effect=race_rollback
            ):
                with self.assertRaises(engine.PatcherError):
                    patcher.apply_plan(patcher.build_plan(payload))

            self.assertIsNotNone(raced_path)
            self.assertEqual(raced_path.read_bytes(), external)
            for name, original in originals.items():
                self.assertEqual((game_dir / "sd" / name).read_bytes(), original)

    def test_recovery_keeps_journal_until_deferred_files_are_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, game_dir, originals, _offset, _size = (
                self._make_engine_with_two_archives(root)
            )
            payload = root / "payload"
            payload.mkdir()
            (payload / "voice.bnk").write_bytes(b"VOICE")
            patcher.load_archives()
            real_publish = engine._publish_without_replace
            real_unlink = Path.unlink
            publish_failed = False
            unlink_failed = False

            def fail_second_publish(source: Path, destination: Path) -> None:
                nonlocal publish_failed
                if (
                    not publish_failed
                    and ".erptbr-stage-" in source.name
                    and destination.name == "sd_dlc02.bdt"
                ):
                    publish_failed = True
                    raise OSError("falha de commit injetada")
                real_publish(source, destination)

            def fail_one_recovery_unlink(path: Path, *args, **kwargs) -> None:
                nonlocal unlink_failed
                if not unlink_failed and path.name.endswith(
                    (".rollback", ".displaced")
                ):
                    unlink_failed = True
                    raise PermissionError("arquivo temporariamente bloqueado")
                real_unlink(path, *args, **kwargs)

            with (
                mock.patch.object(
                    engine, "_publish_without_replace", side_effect=fail_second_publish
                ),
                mock.patch.object(Path, "unlink", new=fail_one_recovery_unlink),
            ):
                with self.assertRaisesRegex(
                    engine.PatcherError, "estado anterior foi restaurado"
                ):
                    patcher.apply_plan(patcher.build_plan(payload))

            self.assertTrue(publish_failed)
            self.assertTrue(unlink_failed)
            for name, original in originals.items():
                self.assertEqual((game_dir / "sd" / name).read_bytes(), original)
            manifest_path = next((root / "backups").glob("*/*/manifest.json"))
            interrupted = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(interrupted["state"], "prepared")
            self.assertTrue(interrupted["transaction"]["cleanup_only"])

            retry = engine.PatchEngine(game_dir, backup_root=root / "backups")
            retry.load_archives()
            retry.apply_plan(retry.build_plan(payload))
            completed = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(completed["state"], "applied")
            self.assertNotIn("transaction", completed)
            self.assertFalse(list((game_dir / "sd").glob(".erptbr-*.rollback")))
            self.assertFalse(list((game_dir / "sd").glob(".erptbr-*.displaced")))

    def test_existing_backup_rejects_unknown_same_size_bdt_content(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, game_dir, _originals, _offset, _size = (
                self._make_engine_with_two_archives(root)
            )
            payload_dir = root / "payload"
            payload_dir.mkdir()
            (payload_dir / "voice.bnk").write_bytes(b"VOICE")
            patcher.load_archives()
            plan = patcher.build_plan(payload_dir)
            patcher.apply_plan(plan)

            target = game_dir / "sd" / "sd.bdt"
            tampered = bytearray(target.read_bytes())
            tampered[0] ^= 0xFF
            target.write_bytes(tampered)

            retry = engine.PatchEngine(game_dir, backup_root=root / "backups")
            retry.load_archives()
            retry_plan = retry.build_plan(payload_dir)
            with self.assertRaisesRegex(engine.BackupError, "alterado fora"):
                retry.apply_plan(retry_plan)

    def test_failed_update_from_previous_patch_restores_previous_patch(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first, game_dir, originals, _offset, _size = (
                self._make_engine_with_two_archives(root)
            )
            payload_dir = root / "payload"
            payload_dir.mkdir()
            payload_file = payload_dir / "voice.bnk"
            payload_file.write_bytes(b"VOICE")
            first.load_archives()
            first.apply_plan(first.build_plan(payload_dir))
            previous = {
                name: (game_dir / "sd" / name).read_bytes() for name in originals
            }

            payload_file.write_bytes(b"NOVO!!")
            update = engine.PatchEngine(game_dir, backup_root=root / "backups")
            update.load_archives()
            update_plan = update.build_plan(payload_dir)
            real_publish = engine._publish_without_replace
            failure_injected = False

            def fail_second_new_commit(source: Path, destination: Path) -> None:
                nonlocal failure_injected
                source_path = Path(source)
                destination_path = Path(destination)
                if (
                    not failure_injected
                    and ".erptbr-stage-" in source_path.name
                    and destination_path.name == "sd_dlc02.bdt"
                ):
                    failure_injected = True
                    raise OSError("falha durante update injetada")
                real_publish(source_path, destination_path)

            with mock.patch.object(
                engine, "_publish_without_replace", side_effect=fail_second_new_commit
            ):
                with self.assertRaisesRegex(
                    engine.PatcherError, "estado anterior foi restaurado"
                ):
                    update.apply_plan(update_plan)

            self.assertTrue(failure_injected)
            for name, prior in previous.items():
                self.assertEqual((game_dir / "sd" / name).read_bytes(), prior)

    def test_external_change_during_staging_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first, game_dir, originals, _offset, _size = (
                self._make_engine_with_two_archives(root)
            )
            payload_dir = root / "payload"
            payload_dir.mkdir()
            payload_file = payload_dir / "voice.bnk"
            payload_file.write_bytes(b"VOICE")
            first.load_archives()
            first.apply_plan(first.build_plan(payload_dir))
            previous_sd = (game_dir / "sd" / "sd.bdt").read_bytes()

            payload_file.write_bytes(b"NOVO!!")
            update = engine.PatchEngine(game_dir, backup_root=root / "backups")
            update.load_archives()
            plan = update.build_plan(payload_dir)
            changed_path = game_dir / "sd" / "sd_dlc02.bdt"
            external = b"X" * len(originals["sd_dlc02.bdt"])
            real_copy = engine._copy_with_sha256
            injected = False

            def copy_then_change(source: Path, destination: Path) -> str:
                nonlocal injected
                result = real_copy(source, destination)
                if (
                    not injected
                    and ".erptbr-stage-" in destination.name
                    and destination.name.startswith(".sd_dlc02")
                ):
                    changed_path.write_bytes(external)
                    injected = True
                return result

            with mock.patch.object(
                engine, "_copy_with_sha256", side_effect=copy_then_change
            ):
                with self.assertRaises(engine.BackupError):
                    update.apply_plan(plan)

            self.assertTrue(injected)
            self.assertEqual(changed_path.read_bytes(), external)
            self.assertEqual((game_dir / "sd" / "sd.bdt").read_bytes(), previous_sd)
            manifest_path = next((root / "backups").glob("*/*/manifest.json"))
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["state"], "recovery_required")

    def test_external_change_after_first_publish_prevents_success(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            patcher, game_dir, originals, _offset, _size = (
                self._make_engine_with_two_archives(root)
            )
            payload_dir = root / "payload"
            payload_dir.mkdir()
            (payload_dir / "voice.bnk").write_bytes(b"VOICE")
            patcher.load_archives()
            plan = patcher.build_plan(payload_dir)
            real_publish = engine._publish_without_replace
            external_path = game_dir / "sd" / "sd.bdt"
            external = b"Q" * len(originals["sd.bdt"])
            injected = False

            def publish_then_change(source: Path, destination: Path) -> None:
                nonlocal injected
                real_publish(source, destination)
                if (
                    not injected
                    and destination == external_path
                    and ".erptbr-stage-" in source.name
                ):
                    external_path.write_bytes(external)
                    injected = True

            with mock.patch.object(
                engine, "_publish_without_replace", side_effect=publish_then_change
            ):
                with self.assertRaises(engine.BackupError):
                    patcher.apply_plan(plan)

            self.assertTrue(injected)
            self.assertEqual(external_path.read_bytes(), external)
            manifest = json.loads(
                next((root / "backups").glob("*/*/manifest.json")).read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(manifest["state"], "recovery_required")

    def test_final_manifest_failure_rolls_back_instead_of_claiming_success(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, game_dir, originals, _offset, _size = (
                self._make_engine_with_two_archives(root)
            )
            payload = root / "payload"
            payload.mkdir()
            (payload / "voice.bnk").write_bytes(b"VOICE")
            patcher.load_archives()
            plan = patcher.build_plan(payload)
            real_save = engine.BackupManager.save_manifest
            injected = False

            def fail_applied_save(
                manager: engine.BackupManager, manifest: dict
            ) -> None:
                nonlocal injected
                if not injected and manifest.get("state") == "applied":
                    injected = True
                    raise OSError("falha de manifesto aplicada")
                real_save(manager, manifest)

            with mock.patch.object(
                engine.BackupManager, "save_manifest", new=fail_applied_save
            ):
                with self.assertRaisesRegex(
                    engine.PatcherError, "estado anterior foi restaurado"
                ):
                    patcher.apply_plan(plan)

            self.assertTrue(injected)
            for name, original in originals.items():
                self.assertEqual((game_dir / "sd" / name).read_bytes(), original)
            manifest = json.loads(
                next((root / "backups").glob("*/*/manifest.json")).read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(manifest["state"], "prepared")

    def test_post_success_journal_cleanup_failure_keeps_applied_result(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, game_dir, originals, _offset, _size = (
                self._make_engine_with_two_archives(root)
            )
            payload = root / "payload"
            payload.mkdir()
            (payload / "voice.bnk").write_bytes(b"VOICE")
            patcher.load_archives()
            plan = patcher.build_plan(payload)
            real_save = engine.BackupManager.save_manifest
            applied_saves = 0

            def fail_second_applied_save(
                manager: engine.BackupManager, manifest: dict
            ) -> None:
                nonlocal applied_saves
                if manifest.get("state") == "applied":
                    applied_saves += 1
                    if applied_saves == 2:
                        raise engine.BackupError("scratch do manifesto indisponivel")
                real_save(manager, manifest)

            with mock.patch.object(
                engine.BackupManager, "save_manifest", new=fail_second_applied_save
            ):
                writes, unmatched = patcher.apply_plan(plan)

            self.assertGreater(writes, 0)
            self.assertEqual(unmatched, 0)
            self.assertEqual(applied_saves, 2)
            self.assertNotEqual(
                (game_dir / "sd" / "sd.bdt").read_bytes(), originals["sd.bdt"]
            )
            manifest = json.loads(
                next((root / "backups").glob("*/*/manifest.json")).read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(manifest["state"], "applied")
            self.assertIn("transaction", manifest)

    def test_power_loss_with_missing_live_bdt_is_recovered_before_archive_load(
        self,
    ) -> None:
        class SimulatedPowerLoss(BaseException):
            pass

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, game_dir, originals, _offset, _size = (
                self._make_engine_with_two_archives(root)
            )
            payload = root / "payload"
            payload.mkdir()
            (payload / "voice.bnk").write_bytes(b"VOICE")
            patcher.load_archives()
            plan = patcher.build_plan(payload)
            injected = False
            real_publish = engine._publish_without_replace

            def lose_power_before_first_publish(
                source: Path, destination: Path
            ) -> None:
                nonlocal injected
                if not injected and ".erptbr-stage-" in source.name:
                    injected = True
                    raise SimulatedPowerLoss()
                real_publish(source, destination)

            with mock.patch.object(
                engine,
                "_publish_without_replace",
                side_effect=lose_power_before_first_publish,
            ):
                with self.assertRaises(SimulatedPowerLoss):
                    patcher.apply_plan(plan)

            self.assertTrue(injected)
            self.assertFalse((game_dir / "sd" / "sd.bdt").exists())
            fresh = engine.PatchEngine(game_dir, backup_root=root / "backups")
            fresh.load_archives()
            fresh.restore_current_backup()

            for name, original in originals.items():
                self.assertEqual((game_dir / "sd" / name).read_bytes(), original)

    def test_missing_live_recovery_never_accepts_a_swapped_rollback(self) -> None:
        class SimulatedPowerLoss(BaseException):
            pass

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            patcher, game_dir, originals, _offset, _size = (
                self._make_engine_with_two_archives(root)
            )
            payload = root / "payload"
            payload.mkdir()
            (payload / "voice.bnk").write_bytes(b"VOICE")
            patcher.load_archives()
            real_publish = engine._publish_without_replace
            interrupted = False

            def interrupt_before_stage(source: Path, destination: Path) -> None:
                nonlocal interrupted
                if not interrupted and ".erptbr-stage-" in source.name:
                    interrupted = True
                    raise SimulatedPowerLoss()
                real_publish(source, destination)

            with mock.patch.object(
                engine, "_publish_without_replace", side_effect=interrupt_before_stage
            ):
                with self.assertRaises(SimulatedPowerLoss):
                    patcher.apply_plan(patcher.build_plan(payload))

            live = game_dir / "sd" / "sd.bdt"
            self.assertFalse(live.exists())
            swapped = False

            def swap_rollback_during_publish(source: Path, destination: Path) -> None:
                nonlocal swapped
                if (
                    not swapped
                    and source.name.endswith(".rollback")
                    and destination == live
                ):
                    source.unlink()
                    source.write_bytes(b"Z" * len(originals["sd.bdt"]))
                    swapped = True
                real_publish(source, destination)

            fresh = engine.PatchEngine(game_dir, backup_root=root / "backups")
            with mock.patch.object(
                engine,
                "_publish_without_replace",
                side_effect=swap_rollback_during_publish,
            ):
                with self.assertRaisesRegex(engine.BackupError, "trocad"):
                    fresh.load_archives()

            self.assertTrue(swapped)
            self.assertFalse(live.exists())
            rollback_files = list((game_dir / "sd").glob("*.rollback"))
            self.assertEqual(len(rollback_files), 1)
            self.assertEqual(
                rollback_files[0].read_bytes(), b"Z" * len(originals["sd.bdt"])
            )

    def test_power_loss_after_first_publish_recovers_and_installs_in_one_retry(
        self,
    ) -> None:
        class SimulatedPowerLoss(BaseException):
            pass

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, game_dir, _originals, _offset, _size = (
                self._make_engine_with_two_archives(root)
            )
            payload = root / "payload"
            payload.mkdir()
            (payload / "voice.bnk").write_bytes(b"VOICE")
            patcher.load_archives()
            plan = patcher.build_plan(payload)
            real_publish = engine._publish_without_replace
            injected = False

            def lose_power_after_first_publish(source: Path, destination: Path) -> None:
                nonlocal injected
                real_publish(source, destination)
                if not injected and ".erptbr-stage-" in source.name:
                    injected = True
                    raise SimulatedPowerLoss()

            with mock.patch.object(
                engine,
                "_publish_without_replace",
                side_effect=lose_power_after_first_publish,
            ):
                with self.assertRaises(SimulatedPowerLoss):
                    patcher.apply_plan(plan)
            self.assertTrue(injected)

            fresh = engine.PatchEngine(game_dir, backup_root=root / "backups")
            fresh.load_archives()
            fresh.apply_plan(fresh.build_plan(payload))
            manifest = json.loads(
                next((root / "backups").glob("*/*/manifest.json")).read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(manifest["state"], "applied")
            self.assertNotIn("transaction", manifest)

    def test_steam_verify_before_reopen_closes_any_pending_journal(self) -> None:
        class SimulatedPowerLoss(BaseException):
            pass

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, game_dir, originals, _offset, _size = (
                self._make_engine_with_two_archives(root)
            )
            payload = root / "payload"
            payload.mkdir()
            (payload / "voice.bnk").write_bytes(b"VOICE")
            patcher.load_archives()
            real_publish = engine._publish_without_replace
            injected = False

            def lose_power_after_first_publish(source: Path, destination: Path) -> None:
                nonlocal injected
                real_publish(source, destination)
                if not injected and ".erptbr-stage-" in source.name:
                    injected = True
                    raise SimulatedPowerLoss()

            with mock.patch.object(
                engine,
                "_publish_without_replace",
                side_effect=lose_power_after_first_publish,
            ):
                with self.assertRaises(SimulatedPowerLoss):
                    patcher.apply_plan(patcher.build_plan(payload))
            self.assertTrue(injected)

            # Steam may repair the archives before the patcher is opened again.
            for name, original in originals.items():
                (game_dir / "sd" / name).write_bytes(original)

            fresh = engine.PatchEngine(game_dir, backup_root=root / "backups")
            fresh.load_archives()
            fresh.apply_plan(fresh.build_plan(payload))
            manifest = json.loads(
                next((root / "backups").glob("*/*/manifest.json")).read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(manifest["state"], "applied")
            self.assertNotIn("transaction", manifest)

    @unittest.skipUnless(os.name == "nt", "Windows publisher semantics")
    def test_windows_transaction_does_not_require_hardlink_support(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, game_dir, originals, _offset, _size = (
                self._make_engine_with_two_archives(root)
            )
            payload = root / "payload"
            payload.mkdir()
            (payload / "voice.bnk").write_bytes(b"VOICE")
            patcher.load_archives()
            with mock.patch.object(
                engine.os, "link", side_effect=OSError("hardlinks indisponiveis")
            ):
                patcher.apply_plan(patcher.build_plan(payload))
                patcher.restore_current_backup()
            for name, original in originals.items():
                self.assertEqual((game_dir / "sd" / name).read_bytes(), original)

    def test_game_operation_lock_rejects_second_writer(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            lock_path = Path(temp) / "operation.lock"
            with engine.GameOperationLock(lock_path):
                with self.assertRaisesRegex(engine.PatcherError, "Outra instancia"):
                    with engine.GameOperationLock(lock_path):
                        self.fail("o segundo lock nao pode ser adquirido")

    def test_game_operation_lock_recovers_zero_byte_creation_residue(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            lock_path = Path(temp) / "operation.lock"
            lock_path.write_bytes(b"")

            with engine.GameOperationLock(lock_path):
                pass

            self.assertEqual(lock_path.read_bytes(), b"\0")

    def test_game_operation_lock_rejects_hardlink_without_touching_victim(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            victim = root / "victim.bin"
            victim.write_bytes(b"PRESERVE")
            lock_path = root / "operation.lock"
            os.link(victim, lock_path)

            with self.assertRaisesRegex(engine.BackupError, "hardlink|exclusivo"):
                with engine.GameOperationLock(lock_path):
                    self.fail("a hardlinked lock must never be opened")

            self.assertEqual(victim.read_bytes(), b"PRESERVE")

    def test_restore_finds_backup_for_two_of_three_loaded_archives(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, game_dir, originals, _offset, _size = (
                self._make_engine_with_two_archives(root)
            )
            sd_dir = game_dir / "sd"
            third_original = b"C" * 16
            write_archive(
                sd_dir,
                "sd_dlc03",
                [(engine.hash_path("unrelated.bnk"), 8, 6, 4)],
                third_original,
            )
            payload_dir = root / "payload"
            payload_dir.mkdir()
            (payload_dir / "voice.bnk").write_bytes(b"VOICE")
            patcher.load_archives()
            plan = patcher.build_plan(payload_dir)
            self.assertEqual(len(plan.touched_archives), 2)
            patcher.apply_plan(plan)

            fresh = engine.PatchEngine(game_dir, backup_root=root / "backups")
            fresh.load_archives()
            fresh.restore_current_backup()
            for name, original in originals.items():
                self.assertEqual((sd_dir / name).read_bytes(), original)
            self.assertEqual((sd_dir / "sd_dlc03.bdt").read_bytes(), third_original)

    def test_baseline_covers_archives_added_to_a_later_patch_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            game_dir = root / "Game"
            sd_dir = game_dir / "sd"
            sd_dir.mkdir(parents=True)
            originals = {"sd.bdt": b"A" * 16, "sd_dlc02.bdt": b"B" * 16}
            write_archive(
                sd_dir,
                "sd",
                [(engine.hash_path("first.bnk"), 8, 6, 4)],
                originals["sd.bdt"],
            )
            write_archive(
                sd_dir,
                "sd_dlc02",
                [(engine.hash_path("second.bnk"), 8, 6, 4)],
                originals["sd_dlc02.bdt"],
            )
            payload = root / "payload"
            payload.mkdir()
            (payload / "first.bnk").write_bytes(b"FIRST!")

            first = engine.PatchEngine(game_dir, backup_root=root / "backups")
            first.load_archives()
            first.apply_plan(first.build_plan(payload))
            manifest_path = next((root / "backups").glob("*/*/manifest.json"))
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(
                {record["bdt"] for record in manifest["archives"]}, set(originals)
            )

            (payload / "second.bnk").write_bytes(b"SECOND")
            second = engine.PatchEngine(game_dir, backup_root=root / "backups")
            second.load_archives()
            second.apply_plan(second.build_plan(payload))
            second.restore_current_backup()

            for name, original in originals.items():
                self.assertEqual((sd_dir / name).read_bytes(), original)

    def test_contractive_update_restores_archive_removed_from_new_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            game_dir = root / "Game"
            sd_dir = game_dir / "sd"
            sd_dir.mkdir(parents=True)
            originals = {"sd.bdt": b"A" * 16, "sd_dlc02.bdt": b"B" * 16}
            write_archive(
                sd_dir,
                "sd",
                [(engine.hash_path("first.bnk"), 8, 6, 4)],
                originals["sd.bdt"],
            )
            write_archive(
                sd_dir,
                "sd_dlc02",
                [(engine.hash_path("second.bnk"), 8, 6, 4)],
                originals["sd_dlc02.bdt"],
            )
            payload = root / "payload"
            payload.mkdir()
            (payload / "first.bnk").write_bytes(b"FIRST!")
            second_payload = payload / "second.bnk"
            second_payload.write_bytes(b"SECOND")

            first = engine.PatchEngine(game_dir, backup_root=root / "backups")
            first.load_archives()
            first.apply_plan(first.build_plan(payload))
            self.assertNotEqual(
                (sd_dir / "sd_dlc02.bdt").read_bytes(), originals["sd_dlc02.bdt"]
            )

            second_payload.unlink()
            update = engine.PatchEngine(game_dir, backup_root=root / "backups")
            update.load_archives()
            update.apply_plan(update.build_plan(payload))

            self.assertEqual(
                (sd_dir / "sd_dlc02.bdt").read_bytes(), originals["sd_dlc02.bdt"]
            )
            manifest_path = next((root / "backups").glob("*/*/manifest.json"))
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            records = {item["bdt"]: item for item in manifest["archives"]}
            self.assertNotIn("patched_sha256", records["sd_dlc02.bdt"])

    def test_truncated_foreign_manifest_cannot_bless_patched_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first, game_dir, _originals, _offset, _size = (
                self._make_engine_with_two_archives(root)
            )
            payload = root / "payload"
            payload.mkdir()
            (payload / "voice.bnk").write_bytes(b"VOICE")
            first.load_archives()
            first.apply_plan(first.build_plan(payload))
            old_manifest_path = next((root / "backups").glob("*/*/manifest.json"))
            old_manifest = json.loads(old_manifest_path.read_text(encoding="utf-8"))
            old_manifest["archives"] = [
                item for item in old_manifest["archives"] if item["bdt"] != "sd.bdt"
            ]
            old_manifest_path.write_text(json.dumps(old_manifest), encoding="utf-8")

            bhd = game_dir / "sd" / "sd.bhd"
            bhd.write_bytes(bhd.read_bytes() + b"\0")
            fresh = engine.PatchEngine(game_dir, backup_root=root / "backups")
            fresh.load_archives()
            manager = fresh._backup_manager(fresh.archives)
            with manager.operation_lock():
                with self.assertRaisesRegex(engine.BackupError, "manifesto antigo"):
                    manager.prepare()

            self.assertFalse(manager.manifest_path.exists())

    def test_precommit_guard_runs_for_install_and_restore(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            calls: list[str] = []
            base, game_dir, originals, _offset, _size = (
                self._make_engine_with_two_archives(root)
            )
            patcher = engine.PatchEngine(
                game_dir,
                backup_root=root / "backups",
                precommit_guard=lambda: calls.append("guard"),
            )
            payload = root / "payload"
            payload.mkdir()
            (payload / "voice.bnk").write_bytes(b"VOICE")
            patcher.load_archives()
            patcher.apply_plan(patcher.build_plan(payload))
            patcher.restore_current_backup()

            self.assertEqual(calls, ["guard", "guard"])
            for name, original in originals.items():
                self.assertEqual((game_dir / "sd" / name).read_bytes(), original)

    def test_stage_replacement_after_slot_check_aborts_without_touching_live(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, game_dir, originals, _offset, _size = (
                self._make_engine_with_two_archives(root)
            )
            payload = root / "payload"
            payload.mkdir()
            (payload / "voice.bnk").write_bytes(b"VOICE")
            patcher.load_archives()
            real_hash = engine._sha256_owned_regular
            injected = False

            def replace_then_hash(path: Path, identity: tuple[int, int]) -> str:
                nonlocal injected
                if not injected and ".erptbr-stage-" in path.name:
                    path.unlink()
                    path.write_bytes(b"Z" * 16)
                    injected = True
                return real_hash(path, identity)

            with mock.patch.object(
                engine, "_sha256_owned_regular", side_effect=replace_then_hash
            ):
                with self.assertRaisesRegex(
                    engine.PatcherError, "estado anterior foi restaurado"
                ):
                    patcher.apply_plan(patcher.build_plan(payload))

            self.assertTrue(injected)
            for name, original in originals.items():
                self.assertEqual((game_dir / "sd" / name).read_bytes(), original)

    def test_steam_verify_resolves_recovery_required_then_allows_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first, game_dir, originals, _offset, _size = (
                self._make_engine_with_two_archives(root)
            )
            payload = root / "payload"
            payload.mkdir()
            payload_file = payload / "voice.bnk"
            payload_file.write_bytes(b"VOICE")
            first.load_archives()
            first.apply_plan(first.build_plan(payload))

            payload_file.write_bytes(b"NOVO!!")
            update = engine.PatchEngine(game_dir, backup_root=root / "backups")
            update.load_archives()
            plan = update.build_plan(payload)
            changed_path = game_dir / "sd" / "sd_dlc02.bdt"
            real_copy = engine._copy_with_sha256
            injected = False

            def copy_then_change(source: Path, destination: Path) -> str:
                nonlocal injected
                digest = real_copy(source, destination)
                if not injected and destination.name.startswith(
                    ".sd_dlc02.bdt.erptbr-stage-"
                ):
                    changed_path.write_bytes(b"X" * len(originals["sd_dlc02.bdt"]))
                    injected = True
                return digest

            with mock.patch.object(
                engine, "_copy_with_sha256", side_effect=copy_then_change
            ):
                with self.assertRaises(engine.BackupError):
                    update.apply_plan(plan)
            self.assertTrue(injected)

            # Simulate Steam's successful integrity verification for this build.
            for name, original in originals.items():
                (game_dir / "sd" / name).write_bytes(original)

            retry = engine.PatchEngine(game_dir, backup_root=root / "backups")
            retry.load_archives()
            retry.apply_plan(retry.build_plan(payload))
            manifest = json.loads(
                next((root / "backups").glob("*/*/manifest.json")).read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(manifest["state"], "applied")
            self.assertNotIn("transaction", manifest)

    def test_restore_rechecks_live_hashes_after_long_staging(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, game_dir, originals, _offset, _size = (
                self._make_engine_with_two_archives(root)
            )
            payload = root / "payload"
            payload.mkdir()
            (payload / "voice.bnk").write_bytes(b"VOICE")
            patcher.load_archives()
            patcher.apply_plan(patcher.build_plan(payload))
            patched_sd = (game_dir / "sd" / "sd.bdt").read_bytes()

            fresh = engine.PatchEngine(game_dir, backup_root=root / "backups")
            fresh.load_archives()
            real_copy = engine._copy_with_sha256
            external_path = game_dir / "sd" / "sd_dlc02.bdt"
            external = b"Z" * len(originals["sd_dlc02.bdt"])
            injected = False

            def copy_then_change(source: Path, destination: Path) -> str:
                nonlocal injected
                digest = real_copy(source, destination)
                if not injected and ".erptbr-restore-" in destination.name:
                    external_path.write_bytes(external)
                    injected = True
                return digest

            with mock.patch.object(
                engine, "_copy_with_sha256", side_effect=copy_then_change
            ):
                with self.assertRaisesRegex(
                    engine.BackupError, "estado anterior foi recuperado"
                ):
                    fresh.restore_current_backup()

            self.assertTrue(injected)
            self.assertEqual(external_path.read_bytes(), external)
            self.assertEqual((game_dir / "sd" / "sd.bdt").read_bytes(), patched_sd)

    def test_restore_cleanup_failure_cannot_roll_back_or_remove_live_bdt(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, game_dir, originals, _offset, _size = (
                self._make_engine_with_two_archives(root)
            )
            payload = root / "payload"
            payload.mkdir()
            (payload / "voice.bnk").write_bytes(b"VOICE")
            patcher.load_archives()
            patcher.apply_plan(patcher.build_plan(payload))

            fresh = engine.PatchEngine(game_dir, backup_root=root / "backups")
            fresh.load_archives()
            real_unlink = Path.unlink
            rollback_unlinks = 0

            def fail_second_rollback_cleanup(path: Path, *args, **kwargs) -> None:
                nonlocal rollback_unlinks
                if path.name.endswith(".rollback"):
                    rollback_unlinks += 1
                    if rollback_unlinks == 2:
                        raise PermissionError("falha de limpeza injetada")
                real_unlink(path, *args, **kwargs)

            with mock.patch.object(Path, "unlink", new=fail_second_rollback_cleanup):
                fresh.restore_current_backup()

            self.assertEqual(rollback_unlinks, 2)
            for name, original in originals.items():
                live = game_dir / "sd" / name
                self.assertTrue(live.is_file())
                self.assertEqual(live.read_bytes(), original)
            manifest = json.loads(
                next((root / "backups").glob("*/*/manifest.json")).read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(manifest["state"], "restored")
            self.assertIn("transaction", manifest)

    def test_incomplete_backup_search_includes_current_transaction_states(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            expected: set[Path] = set()
            states = (
                "staging",
                "preparing_commit",
                "committing",
                "restoring",
                "recovery_required",
                "applied",
            )
            for index, state in enumerate(states):
                manifest = root / f"{index:016x}" / f"{index:064x}" / "manifest.json"
                manifest.parent.mkdir(parents=True)
                manifest.write_text(json.dumps({"state": state}), encoding="utf-8")
                if state != "applied":
                    expected.add(manifest)
            malformed = root / ("f" * 16) / ("f" * 64) / "manifest.json"
            malformed.parent.mkdir(parents=True)
            malformed.write_text("{", encoding="utf-8")
            expected.add(malformed)
            self.assertEqual(set(engine.find_incomplete_backups(root)), expected)


class BhdShaIntegrityGuardTests(unittest.TestCase):
    def _make_patcher(
        self,
        root: Path,
        *,
        live_slot: bytes,
        hashed_slot: bytes | None = None,
        extra_entry: tuple[str, tuple[tuple[int, int], ...]] | None = None,
        ranges: tuple[tuple[int, int], ...] = ((0, 2),),
    ) -> tuple[engine.PatchEngine, Path, Path]:
        game_dir = root / "Game"
        sd_dir = game_dir / "sd"
        sd_dir.mkdir(parents=True)
        payload_dir = root / "payload"
        payload_dir.mkdir()
        salt = b"GR_sound"
        offset = 4
        padded = len(live_slot)
        authenticated = hashed_slot if hashed_slot is not None else live_slot

        def digest_for(selected_ranges: tuple[tuple[int, int], ...]) -> bytes:
            selected = b"".join(
                authenticated[start:end]
                for start, end in selected_ranges
                if start != -1 and end != -1
            )
            return hashlib.sha256(selected + salt).digest()

        entries = [
            (
                engine.hash_path("voice.bnk"),
                padded,
                padded,
                offset,
                digest_for(ranges),
                ranges,
            )
        ]
        if extra_entry is not None:
            extra_name, extra_ranges = extra_entry
            entries.append(
                (
                    engine.hash_path(extra_name),
                    padded,
                    padded,
                    offset,
                    digest_for(extra_ranges),
                    extra_ranges,
                )
            )
        bhd_path = sd_dir / "sd.bhd"
        bdt_path = sd_dir / "sd.bdt"
        bhd_path.write_bytes(make_bhd_with_sha(entries, salt))
        bdt_path.write_bytes(b"HEAD" + live_slot + b"TAIL")
        patcher = engine.PatchEngine(game_dir, backup_root=root / "backups")
        patcher.load_archives()
        return patcher, payload_dir, bdt_path

    def test_salted_sha_hashes_ranges_in_order_then_salt(self) -> None:
        slot = b"ABCDEFGH"
        ranges = (
            engine.AESRange(1, 3),
            engine.AESRange(-1, -1),
            engine.AESRange(5, 7),
        )

        actual = engine.calculate_bhd5_salted_sha256(slot, b"salt", ranges)

        self.assertEqual(actual, hashlib.sha256(b"BCFGsalt").digest())

    def test_load_archives_preserves_exact_bhd_salt(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, _payload, _bdt = self._make_patcher(
                root, live_slot=b"ABCDEFGH"
            )

            self.assertEqual(patcher.archives[0].salt, b"GR_sound")

    def test_guard_rejects_invalid_current_bdt_without_creating_backup(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, payload, bdt_path = self._make_patcher(
                root,
                live_slot=b"XYCDEFGH",
                hashed_slot=b"ABCDEFGH",
            )
            (payload / "voice.bnk").write_bytes(b"ABCDEFGH")
            plan = patcher.build_plan(payload)
            before = bdt_path.read_bytes()

            with self.assertRaisesRegex(
                engine.CompatibilityError, "Integridade SHA salted invalida"
            ):
                engine.validate_patch_plan_sha_integrity(plan)
            self.assertFalse((root / "backups").exists())

            with self.assertRaisesRegex(
                engine.CompatibilityError, "Integridade SHA salted invalida"
            ):
                patcher.apply_plan(plan)

            self.assertEqual(bdt_path.read_bytes(), before)
            self.assertEqual(list((root / "backups").glob("*/*/manifest.json")), [])

    def test_guard_rejects_plan_that_invalidates_an_aliased_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, payload, bdt_path = self._make_patcher(
                root,
                live_slot=b"ABCDEFGH",
                ranges=((0, 1),),
                extra_entry=("ambient.bnk", ((1, 2),)),
            )
            (payload / "voice.bnk").write_bytes(b"AZCDEFGH")
            plan = patcher.build_plan(payload)
            before = bdt_path.read_bytes()

            with self.assertRaisesRegex(
                engine.CompatibilityError, "alteraria um range SHA autenticado"
            ):
                patcher.apply_plan(plan)

            self.assertEqual(bdt_path.read_bytes(), before)
            self.assertEqual(list((root / "backups").glob("*/*/manifest.json")), [])

    def test_guard_allows_changes_outside_authenticated_ranges(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, payload, bdt_path = self._make_patcher(
                root,
                live_slot=b"ABCDEFGH",
                ranges=((0, 2),),
            )
            replacement = b"AB123456"
            (payload / "voice.bnk").write_bytes(replacement)

            written, unmatched = patcher.apply_plan(patcher.build_plan(payload))

            self.assertEqual((written, unmatched), (1, 0))
            self.assertEqual(bdt_path.read_bytes()[4:12], replacement)

    def test_scoped_mode_returns_exact_expected_divergence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, payload, _bdt_path = self._make_patcher(
                root,
                live_slot=b"ABCDEFGH",
                ranges=((0, 2),),
            )
            (payload / "voice.bnk").write_bytes(b"XYCDEFGH")
            plan = patcher.build_plan(payload)

            assessment = engine.validate_patch_plan_sha_integrity(
                plan,
                mode=engine.BHD_INTEGRITY_SCOPED_MOD,
            )

            self.assertEqual(assessment.validated_entry_count, 1)
            self.assertEqual(len(assessment.divergent_entries), 1)
            identity = next(iter(assessment.divergent_entries))
            self.assertEqual(identity.archive_path, patcher.archives[0].bdt_path)
            self.assertEqual(identity.entry_index, 0)
            self.assertEqual(identity.file_name_hash, engine.hash_path("voice.bnk"))
            self.assertEqual((identity.file_offset, identity.padded_file_size), (4, 8))

    def test_scoped_mode_never_waives_an_invalid_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, payload, _bdt_path = self._make_patcher(
                root,
                live_slot=b"XYCDEFGH",
                hashed_slot=b"ABCDEFGH",
            )
            (payload / "voice.bnk").write_bytes(b"12345678")
            plan = patcher.build_plan(payload)

            with self.assertRaisesRegex(
                engine.CompatibilityError,
                "Integridade SHA salted invalida",
            ):
                engine.validate_patch_plan_sha_integrity(
                    plan,
                    mode=engine.BHD_INTEGRITY_SCOPED_MOD,
                )

    def test_apply_assesses_untouched_loaded_archive_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first, payload, _bdt_path = self._make_patcher(
                root,
                live_slot=b"ABCDEFGH",
            )
            salt = b"GR_sound"
            pristine = b"IJKLMNOP"
            corrupted = b"XXKLMNOP"
            sd_dir = first.game_dir / "sd"
            (sd_dir / "sd_dlc02.bhd").write_bytes(
                make_bhd_with_sha(
                    [
                        (
                            engine.hash_path("untouched.bnk"),
                            len(pristine),
                            len(pristine),
                            4,
                            hashlib.sha256(pristine[:2] + salt).digest(),
                            ((0, 2),),
                        )
                    ],
                    salt,
                )
            )
            (sd_dir / "sd_dlc02.bdt").write_bytes(b"HEAD" + corrupted + b"TAIL")
            (payload / "voice.bnk").write_bytes(b"ABCDEFGH")
            patcher = engine.PatchEngine(
                first.game_dir,
                backup_root=root / "backups",
            )
            patcher.load_archives()
            plan = patcher.build_plan(payload)

            with self.assertRaisesRegex(
                engine.CompatibilityError,
                "sd_dlc02.bdt.*nao corresponde ao BHD",
            ):
                patcher.apply_plan(
                    plan,
                    bhd_integrity_mode=engine.BHD_INTEGRITY_SCOPED_MOD,
                )

            self.assertEqual(list((root / "backups").glob("*/*/manifest.json")), [])

    def test_unknown_integrity_mode_fails_before_backup(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, payload, bdt_path = self._make_patcher(
                root,
                live_slot=b"ABCDEFGH",
            )
            (payload / "voice.bnk").write_bytes(b"ABCDEFGH")
            plan = patcher.build_plan(payload)
            before = bdt_path.read_bytes()

            with self.assertRaisesRegex(ValueError, "Modo de integridade BHD"):
                patcher.apply_plan(plan, bhd_integrity_mode="permissive")

            self.assertEqual(bdt_path.read_bytes(), before)
            self.assertEqual(list((root / "backups").glob("*/*/manifest.json")), [])

    def _make_staging_fixture(
        self,
        root: Path,
    ) -> tuple[
        engine.PatchEngine,
        engine.PatchPlan,
        engine.BHDIntegrityAssessment,
        Path,
        Path,
    ]:
        patcher, payload, bdt_path = self._make_patcher(
            root,
            live_slot=b"ABCDEFGH",
            ranges=((0, 2),),
        )
        replacement = b"XYCDEFGH"
        (payload / "voice.bnk").write_bytes(replacement)
        plan = patcher.build_plan(payload)
        assessment = engine.validate_patch_plan_sha_integrity(
            plan,
            mode=engine.BHD_INTEGRITY_SCOPED_MOD,
        )
        baseline_path = root / "baseline.bdt"
        stage_path = root / "stage.bdt"
        shutil.copyfile(bdt_path, baseline_path)
        staged = bytearray(bdt_path.read_bytes())
        staged[4:12] = replacement
        stage_path.write_bytes(staged)
        return patcher, plan, assessment, baseline_path, stage_path

    def test_staging_accepts_exact_scoped_divergence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (
                patcher,
                plan,
                expected,
                baseline_path,
                stage_path,
            ) = self._make_staging_fixture(root)
            live_path = patcher.archives[0].bdt_path

            actual = engine.validate_staged_patch_sha_integrity(
                plan,
                patcher.archives,
                baseline_paths={live_path: baseline_path},
                staging_paths={live_path: stage_path},
                expected_divergent_entries=expected.divergent_entries,
            )

            self.assertEqual(actual.validated_entry_count, expected.validated_entry_count)
            self.assertEqual(actual.divergent_entries, expected.divergent_entries)
            self.assertEqual(
                dict(actual.validated_archive_sha256),
                {live_path: hashlib.sha256(stage_path.read_bytes()).hexdigest()},
            )
            stage_stat = stage_path.stat()
            self.assertEqual(
                dict(actual.validated_archive_identities),
                {live_path: (stage_stat.st_dev, stage_stat.st_ino)},
            )

    def test_staging_accepts_restored_archive_removed_from_update_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (
                patcher,
                plan,
                expected,
                baseline_path,
                stage_path,
            ) = self._make_staging_fixture(root)
            live_path = patcher.archives[0].bdt_path

            removed_live = root / "removed-live.bdt"
            removed_baseline = root / "removed-baseline.bdt"
            removed_stage = root / "removed-stage.bdt"
            removed_baseline.write_bytes(b"ORIGINAL")
            # A contractive update stages the immutable baseline for an archive
            # that the new payload no longer targets.
            removed_stage.write_bytes(b"ORIGINAL")
            salt = b"GR_sound"
            removed_entry = engine.FileEntry(
                file_name_hash=engine.hash_path("removed.bnk"),
                padded_file_size=8,
                unpadded_file_size=8,
                file_offset=0,
                sha_hash_offset=1,
                aes_key_offset=0,
                sha_info=engine.SHAHashInfo(
                    hash_bytes=hashlib.sha256(b"ORIGINAL" + salt).digest(),
                    ranges=(engine.AESRange(0, 8),),
                ),
            )
            removed_archive = engine.Archive(
                bhd_path=root / "removed-live.bhd",
                bdt_path=removed_live,
                bhd_sha256="0" * 64,
                bdt_size=8,
                bdt_mtime_ns=0,
                entries=(removed_entry,),
                salt=salt,
            )

            actual = engine.validate_staged_patch_sha_integrity(
                plan,
                (*patcher.archives, removed_archive),
                baseline_paths={
                    live_path: baseline_path,
                    removed_live: removed_baseline,
                },
                staging_paths={
                    live_path: stage_path,
                    removed_live: removed_stage,
                },
                expected_divergent_entries=expected.divergent_entries,
            )

            self.assertEqual(actual.validated_entry_count, 2)
            self.assertEqual(
                actual.divergent_entries,
                expected.divergent_entries,
            )

    def test_staging_rejects_sha_set_broader_than_expected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, plan, _expected, baseline_path, stage_path = (
                self._make_staging_fixture(root)
            )
            live_path = patcher.archives[0].bdt_path

            with self.assertRaisesRegex(
                engine.CompatibilityError,
                "conjunto SHA do staging diverge",
            ):
                engine.validate_staged_patch_sha_integrity(
                    plan,
                    patcher.archives,
                    baseline_paths={live_path: baseline_path},
                    staging_paths={live_path: stage_path},
                    expected_divergent_entries=frozenset(),
                )

    def test_staging_rejects_spillover_outside_planned_slots(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, plan, expected, baseline_path, stage_path = (
                self._make_staging_fixture(root)
            )
            staged = bytearray(stage_path.read_bytes())
            staged[-1] ^= 0xFF
            stage_path.write_bytes(staged)
            live_path = patcher.archives[0].bdt_path

            with self.assertRaisesRegex(engine.CompatibilityError, "spillover"):
                engine.validate_staged_patch_sha_integrity(
                    plan,
                    patcher.archives,
                    baseline_paths={live_path: baseline_path},
                    staging_paths={live_path: stage_path},
                    expected_divergent_entries=expected.divergent_entries,
                )

    def test_staging_rejects_corrupt_baseline_even_in_scoped_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, plan, expected, baseline_path, stage_path = (
                self._make_staging_fixture(root)
            )
            baseline = bytearray(baseline_path.read_bytes())
            baseline[4] ^= 0xFF
            baseline_path.write_bytes(baseline)
            live_path = patcher.archives[0].bdt_path

            with self.assertRaisesRegex(engine.CompatibilityError, "Baseline invalido"):
                engine.validate_staged_patch_sha_integrity(
                    plan,
                    patcher.archives,
                    baseline_paths={live_path: baseline_path},
                    staging_paths={live_path: stage_path},
                    expected_divergent_entries=expected.divergent_entries,
                )

    def test_staging_rejects_extra_path_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, plan, expected, baseline_path, stage_path = (
                self._make_staging_fixture(root)
            )
            live_path = patcher.archives[0].bdt_path
            unrelated = root / "unrelated.bdt"
            unrelated.write_bytes(b"")

            with self.assertRaisesRegex(engine.CompatibilityError, "Mapeamento inexato"):
                engine.validate_staged_patch_sha_integrity(
                    plan,
                    patcher.archives,
                    baseline_paths={
                        live_path: baseline_path,
                        unrelated: unrelated,
                    },
                    staging_paths={live_path: stage_path},
                    expected_divergent_entries=expected.divergent_entries,
                )

    def test_open_staging_guard_rejects_same_size_in_place_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "stage.bdt"
            path.write_bytes(b"01234567")
            stream, opened = engine._open_bdt_for_integrity(
                path,
                expected_size=8,
                label="O staging de teste",
            )
            try:
                with path.open("r+b") as writer:
                    writer.seek(7)
                    writer.write(b"X")
                    writer.flush()
                    os.fsync(writer.fileno())
                # Avoid relying on filesystem timestamp resolution in this
                # concurrency regression: force a distinct same-size mtime.
                os.utime(
                    path,
                    ns=(opened.st_atime_ns, opened.st_mtime_ns + 1_000_000_000),
                )

                with self.assertRaisesRegex(
                    engine.CompatibilityError,
                    "mudou durante a verificacao",
                ):
                    engine._require_open_bdt_unchanged(
                        path,
                        stream,
                        opened,
                        expected_size=8,
                        label="O staging de teste",
                    )
            finally:
                stream.close()

    def test_sha256_file_rejects_same_inode_mutation_during_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "live.bdt"
            original = b"ABCDEFGH"
            path.write_bytes(original)
            initial = path.stat()
            mutated = False

            def mutate_after_first_chunk(_size: int) -> None:
                nonlocal mutated
                if mutated:
                    return
                mutated = True
                with path.open("r+b", buffering=0) as writer:
                    writer.seek(0)
                    writer.write(b"Z")
                    writer.flush()
                    os.fsync(writer.fileno())
                # Restore mtime deliberately: the handle's longitudinal ctime
                # snapshot must still expose this same-inode write.
                os.utime(
                    path,
                    ns=(initial.st_atime_ns, initial.st_mtime_ns),
                )

            with mock.patch.object(engine, "COPY_BUFFER_SIZE", 4):
                with self.assertRaisesRegex(
                    engine.BackupError, "mudou durante o hash"
                ):
                    engine.sha256_file(path, callback=mutate_after_first_chunk)

            self.assertTrue(mutated)
            self.assertEqual(path.read_bytes(), b"ZBCDEFGH")

    def test_owned_sha256_rejects_same_inode_mutation_during_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "stage.bdt"
            path.write_bytes(b"ABCDEFGH")
            identity = engine._regular_file_identity(path, label="O staging de teste")
            initial = path.stat()
            real_sha256 = hashlib.sha256
            mutated = False

            class MutatingDigest:
                def __init__(self) -> None:
                    self._digest = real_sha256()

                def update(self, chunk: bytes) -> None:
                    nonlocal mutated
                    self._digest.update(chunk)
                    if mutated:
                        return
                    mutated = True
                    with path.open("r+b", buffering=0) as writer:
                        writer.seek(0)
                        writer.write(b"Z")
                        writer.flush()
                        os.fsync(writer.fileno())
                    os.utime(
                        path,
                        ns=(
                            initial.st_atime_ns,
                            initial.st_mtime_ns,
                        ),
                    )

                def hexdigest(self) -> str:
                    return self._digest.hexdigest()

            with (
                mock.patch.object(engine, "COPY_BUFFER_SIZE", 4),
                mock.patch.object(
                    engine.hashlib,
                    "sha256",
                    side_effect=MutatingDigest,
                ),
            ):
                with self.assertRaisesRegex(
                    engine.BackupError, "mudou durante o hash"
                ):
                    engine._sha256_owned_regular(path, identity)

            self.assertTrue(mutated)
            self.assertEqual(path.read_bytes(), b"ZBCDEFGH")

    def test_apply_plan_requires_explicit_scoped_mode_for_sha_divergence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, payload, bdt_path = self._make_patcher(
                root,
                live_slot=b"ABCDEFGH",
                ranges=((0, 2),),
            )
            replacement = b"XYCDEFGH"
            (payload / "voice.bnk").write_bytes(replacement)

            written, unmatched = patcher.apply_plan(
                patcher.build_plan(payload),
                bhd_integrity_mode=engine.BHD_INTEGRITY_SCOPED_MOD,
            )

            self.assertEqual((written, unmatched), (1, 0))
            self.assertEqual(bdt_path.read_bytes()[4:12], replacement)

    def test_scoped_reinstall_authenticates_immutable_backup_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first, payload, bdt_path = self._make_patcher(
                root,
                live_slot=b"ABCDEFGH",
                ranges=((0, 2),),
            )
            (payload / "voice.bnk").write_bytes(b"XYCDEFGH")
            first.apply_plan(
                first.build_plan(payload),
                bhd_integrity_mode=engine.BHD_INTEGRITY_SCOPED_MOD,
            )
            self.assertEqual(bdt_path.read_bytes()[4:12], b"XYCDEFGH")

            (payload / "voice.bnk").write_bytes(b"ZZCDEFGH")
            update = engine.PatchEngine(
                first.game_dir,
                backup_root=root / "backups",
            )
            update.load_archives()
            written, unmatched = update.apply_plan(
                update.build_plan(payload),
                bhd_integrity_mode=engine.BHD_INTEGRITY_SCOPED_MOD,
            )

            self.assertEqual((written, unmatched), (1, 0))
            self.assertEqual(bdt_path.read_bytes()[4:12], b"ZZCDEFGH")
            manifest_path = next((root / "backups").glob("*/*/manifest.json"))
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            record = manifest["archives"][0]
            backup_path = manifest_path.parent / record["backup"]
            backup_bytes = backup_path.read_bytes()
            self.assertEqual(backup_bytes[4:12], b"ABCDEFGH")
            self.assertEqual(
                record["sha256"],
                hashlib.sha256(backup_bytes).hexdigest(),
            )

    def test_scoped_reinstall_never_accepts_unknown_live_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first, payload, bdt_path = self._make_patcher(
                root,
                live_slot=b"ABCDEFGH",
                ranges=((0, 2),),
            )
            (payload / "voice.bnk").write_bytes(b"XYCDEFGH")
            first.apply_plan(
                first.build_plan(payload),
                bhd_integrity_mode=engine.BHD_INTEGRITY_SCOPED_MOD,
            )
            tampered = bytearray(bdt_path.read_bytes())
            tampered[-1] ^= 0x55
            bdt_path.write_bytes(tampered)
            before_retry = bdt_path.read_bytes()

            (payload / "voice.bnk").write_bytes(b"ZZCDEFGH")
            retry = engine.PatchEngine(
                first.game_dir,
                backup_root=root / "backups",
            )
            retry.load_archives()
            with self.assertRaisesRegex(engine.BackupError, "alterado fora"):
                retry.apply_plan(
                    retry.build_plan(payload),
                    bhd_integrity_mode=engine.BHD_INTEGRITY_SCOPED_MOD,
                )

            self.assertEqual(bdt_path.read_bytes(), before_retry)

    def test_apply_rejects_same_inode_mutation_after_exact_staging_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            patcher, payload, bdt_path = self._make_patcher(
                root,
                live_slot=b"ABCDEFGH",
                ranges=((0, 2),),
            )
            (payload / "voice.bnk").write_bytes(b"XYCDEFGH")
            plan = patcher.build_plan(payload)
            original_live = bdt_path.read_bytes()
            original_validator = engine.validate_staged_patch_sha_integrity

            def mutate_after_validation(*args: object, **kwargs: object):
                assessment = original_validator(*args, **kwargs)
                staging_paths = kwargs["staging_paths"]
                assert isinstance(staging_paths, dict)
                stage_path = next(iter(staging_paths.values()))
                assert isinstance(stage_path, Path)
                with stage_path.open("r+b") as stream:
                    stream.seek(-1, os.SEEK_END)
                    last = stream.read(1)
                    stream.seek(-1, os.SEEK_END)
                    stream.write(bytes((last[0] ^ 0x55,)))
                    stream.flush()
                    os.fsync(stream.fileno())
                return assessment

            with mock.patch.object(
                engine,
                "validate_staged_patch_sha_integrity",
                side_effect=mutate_after_validation,
            ):
                with self.assertRaisesRegex(
                    engine.PatcherError,
                    "mudou depois da verificacao exata",
                ):
                    patcher.apply_plan(
                        plan,
                        bhd_integrity_mode=engine.BHD_INTEGRITY_SCOPED_MOD,
                    )

            self.assertEqual(bdt_path.read_bytes(), original_live)


if __name__ == "__main__":
    unittest.main()
