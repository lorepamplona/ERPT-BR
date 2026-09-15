from __future__ import annotations

import struct
import unittest

from patcher import bnk, engine


def section(chunk_id: bytes, data: bytes) -> bytes:
    return chunk_id + struct.pack("<I", len(data)) + data


def make_hirc(objects: list[tuple[int, int, bytes]]) -> bytes:
    result = bytearray(struct.pack("<I", len(objects)))
    for type_id, object_id, body in objects:
        payload = struct.pack("<I", object_id) + body
        result.extend(bytes((type_id,)))
        result.extend(struct.pack("<I", len(payload)))
        result.extend(payload)
    return bytes(result)


def make_media(items: list[tuple[int, bytes]]) -> tuple[bytes, bytes]:
    didx = bytearray()
    data = bytearray()
    for media_id, media_data in items:
        offset = (len(data) + 15) // 16 * 16
        data.extend(b"\0" * (offset - len(data)))
        didx.extend(struct.pack("<III", media_id, offset, len(media_data)))
        data.extend(media_data)
    return bytes(didx), bytes(data)


def sound_body(
    *,
    stream_type: int,
    wem_id: int,
    media_size: int = 0,
    plugin_id: int = 1,
    source_bits: int = 0x80,
    tail: bytes = b"sound-settings",
) -> bytes:
    """Build the fixed CAkSound source prefix used by Wwise version 135."""

    return (
        struct.pack(
            "<IBIIB",
            plugin_id,
            stream_type,
            wem_id,
            media_size,
            source_bits,
        )
        + tail
    )


def sound_fields(item: bnk.HircObject) -> tuple[int, int, int]:
    return (
        item.raw[13],
        struct.unpack_from("<I", item.raw, 14)[0],
        struct.unpack_from("<I", item.raw, 18)[0],
    )


def make_bank(
    *,
    objects: list[tuple[int, int, bytes]],
    media: list[tuple[int, bytes]] | None = None,
    header_tail: bytes = b"",
    stid: bytes | None = None,
    unknown: bytes | None = None,
    version: int = 135,
    bank_id: int = 7,
) -> bytes:
    parts = [section(b"BKHD", struct.pack("<II", version, bank_id) + header_tail)]
    if media is not None:
        didx, data = make_media(media)
        parts.extend((section(b"DIDX", didx), section(b"DATA", data)))
    if unknown is not None:
        parts.append(section(b"ENVS", unknown))
    parts.append(section(b"HIRC", make_hirc(objects)))
    if stid is not None:
        parts.append(section(b"STID", stid))
    return b"".join(parts)


def sections_by_id(data: bytes) -> dict[bytes, bnk.BnkSection]:
    return {item.chunk_id: item for item in bnk.parse_bnk(data)}


def media_by_id(data: bytes) -> dict[int, bytes]:
    sections = sections_by_id(data)
    didx = sections[b"DIDX"].data
    media_data = sections[b"DATA"].data
    result = {}
    for offset in range(0, len(didx), 12):
        media_id, data_offset, size = struct.unpack_from("<III", didx, offset)
        result[media_id] = media_data[data_offset : data_offset + size]
    return result


class SafeBnkMergeTests(unittest.TestCase):
    def test_engine_helper_decrypts_merges_and_reencrypts_staging_slot(self) -> None:
        vanilla = make_bank(
            objects=[(2, 10, sound_body(stream_type=1, wem_id=100))]
        )
        payload = make_bank(
            objects=[(2, 10, sound_body(stream_type=2, wem_id=100))]
        )
        padded_size = (len(vanilla) + 15) // 16 * 16
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        aes_ranges = (engine.AESRange(0, padded_size),)
        encrypted_baseline = bytearray(
            vanilla + b"\0" * (padded_size - len(vanilla))
        )
        engine.encrypt_aes_ecb(encrypted_baseline, key, aes_ranges)
        entry = engine.FileEntry(
            file_name_hash=1,
            padded_file_size=padded_size,
            unpadded_file_size=len(vanilla),
            file_offset=0,
            sha_hash_offset=0,
            aes_key_offset=1,
            aes_info=engine.AESKeyInfo(key, aes_ranges),
        )

        prepared = engine.prepare_bnk_slot_from_baseline(
            payload,
            bytes(encrypted_baseline),
            entry,
            external_wem_ids={100},
        )

        decrypted = engine.decrypt_aes_ecb(bytearray(prepared), key, aes_ranges)
        expected = bnk.merge_bnk_with_vanilla(
            vanilla,
            payload,
            external_wem_ids={100},
        )
        self.assertEqual(bytes(decrypted[: len(expected)]), expected)
        self.assertEqual(bytes(decrypted[len(expected) :]), b"\0" * (padded_size - len(expected)))

    def test_cs_main_like_merge_restores_new_vanilla_objects_and_media(self) -> None:
        # This reproduces the important 1.17.1 regression shape: the newer
        # vanilla cs_main has three DIDX entries and 234 HIRC objects that the
        # older translation payload does not know about.
        new_vanilla_objects = [
            (3, 1_000 + index, f"vanilla-{index}".encode())
            for index in range(234)
        ]
        vanilla = make_bank(
            objects=[
                (2, 10, sound_body(stream_type=1, wem_id=10)),
                *new_vanilla_objects,
            ],
            media=[
                (10, b"old-audio"),
                (20, b"new-media-one"),
                (30, b"new-media-two"),
                (40, b"new-media-three"),
            ],
            header_tail=b"vanilla-bkhd",
            stid=b"vanilla-stid",
            unknown=b"vanilla-envs",
        )
        payload = make_bank(
            objects=[
                (2, 10, sound_body(stream_type=2, wem_id=10)),
                (2, 999, sound_body(stream_type=2, wem_id=999)),
            ],
            media=[
                (10, b"translated-audio"),
                (999, b"payload-only-media"),
            ],
            header_tail=b"stale-payload-bkhd",
            stid=b"stale-payload-stid",
            unknown=b"stale-payload-envs",
        )

        merged = bnk.merge_bnk_with_vanilla(
            vanilla,
            payload,
            external_wem_ids=set(),
        )
        self.assertEqual(len(merged), len(vanilla))

        vanilla_sections = sections_by_id(vanilla)
        merged_sections = sections_by_id(merged)
        self.assertEqual(
            [item.chunk_id for item in bnk.parse_bnk(merged)],
            [item.chunk_id for item in bnk.parse_bnk(vanilla)],
        )
        self.assertEqual(merged_sections[b"BKHD"], vanilla_sections[b"BKHD"])
        self.assertEqual(merged_sections[b"STID"], vanilla_sections[b"STID"])
        self.assertEqual(merged_sections[b"ENVS"], vanilla_sections[b"ENVS"])

        merged_objects = bnk.parse_hirc(merged_sections[b"HIRC"].data)
        vanilla_objects = bnk.parse_hirc(vanilla_sections[b"HIRC"].data)
        self.assertEqual(len(merged_objects), 235)
        self.assertEqual(
            [(item.type_id, item.object_id) for item in merged_objects],
            [(item.type_id, item.object_id) for item in vanilla_objects],
        )
        # Replacing embedded DIDX bytes does not prove that an external WEM is
        # present, so the stale PrefetchStreaming -> Streaming delta is filtered.
        self.assertEqual(sound_fields(merged_objects[0])[:2], (1, 10))
        self.assertEqual(merged_objects[0].raw, vanilla_objects[0].raw)
        self.assertNotIn(999, {item.object_id for item in merged_objects})
        self.assertEqual(
            [item.raw for item in merged_objects[1:]],
            [item.raw for item in vanilla_objects[1:]],
        )

        merged_media = media_by_id(merged)
        self.assertEqual(set(merged_media), {10, 20, 30, 40})
        self.assertEqual(merged_media[10], b"translated-audio")
        self.assertEqual(merged_media[20], b"new-media-one")
        self.assertEqual(merged_media[30], b"new-media-two")
        self.assertEqual(merged_media[40], b"new-media-three")

    def test_only_shared_type_two_objects_are_replaced(self) -> None:
        vanilla = make_bank(
            objects=[
                (2, 10, sound_body(stream_type=1, wem_id=100)),
                (3, 10, b"old-event"),
            ],
        )
        payload = make_bank(
            objects=[
                (2, 10, sound_body(stream_type=2, wem_id=100)),
                (3, 10, b"new-event"),
            ],
        )

        merged = bnk.merge_bnk_with_vanilla(
            vanilla,
            payload,
            external_wem_ids={100},
        )
        objects = bnk.parse_hirc(sections_by_id(merged)[b"HIRC"].data)

        self.assertEqual(sound_fields(objects[0])[:2], (2, 100))
        self.assertIn(b"old-event", objects[1].raw)
        self.assertNotIn(b"new-event", objects[1].raw)

    def test_bank_without_embedded_media_stays_without_media(self) -> None:
        vanilla = make_bank(
            objects=[(2, 10, sound_body(stream_type=1, wem_id=100))]
        )
        payload = make_bank(
            objects=[(2, 10, sound_body(stream_type=2, wem_id=100))],
            media=[(100, b"unreferenced-media")],
        )

        merged = bnk.merge_bnk_with_vanilla(
            vanilla,
            payload,
            external_wem_ids=set(),
        )
        sections = sections_by_id(merged)

        self.assertNotIn(b"DIDX", sections)
        self.assertNotIn(b"DATA", sections)
        self.assertEqual(sections[b"HIRC"], sections_by_id(vanilla)[b"HIRC"])

    def test_external_plan_wem_authorizes_only_stream_type_byte(self) -> None:
        vanilla = make_bank(
            objects=[(2, 10, sound_body(stream_type=1, wem_id=1234))]
        )
        payload = make_bank(
            objects=[(2, 10, sound_body(stream_type=2, wem_id=1234))]
        )

        merged = bnk.merge_bnk_with_vanilla(
            vanilla,
            payload,
            external_wem_ids={1234},
        )
        before = bnk.parse_hirc(sections_by_id(vanilla)[b"HIRC"].data)[0].raw
        after = bnk.parse_hirc(sections_by_id(merged)[b"HIRC"].data)[0].raw

        self.assertEqual(len(after), len(before))
        self.assertEqual(after[:13], before[:13])
        self.assertEqual(after[13], 2)
        self.assertEqual(after[14:], before[14:])

    def test_rejects_same_hierarchy_id_with_different_wem_reference(self) -> None:
        vanilla = make_bank(
            objects=[(2, 10, sound_body(stream_type=1, wem_id=100))]
        )
        payload = make_bank(
            objects=[(2, 10, sound_body(stream_type=2, wem_id=200))]
        )

        with self.assertRaisesRegex(bnk.BnkMergeError, "WemId divergente"):
            bnk.merge_bnk_with_vanilla(
                vanilla,
                payload,
                external_wem_ids={100, 200},
            )

    def test_payload_only_didx_media_does_not_authorize_sound_change(self) -> None:
        vanilla = make_bank(
            objects=[(2, 10, sound_body(stream_type=1, wem_id=100))],
            media=[(200, b"vanilla-only")],
        )
        payload = make_bank(
            objects=[(2, 10, sound_body(stream_type=2, wem_id=100))],
            media=[(100, b"payload-only")],
        )

        merged = bnk.merge_bnk_with_vanilla(
            vanilla,
            payload,
            external_wem_ids=set(),
        )

        self.assertEqual(sections_by_id(merged)[b"HIRC"], sections_by_id(vanilla)[b"HIRC"])
        self.assertEqual(media_by_id(merged), {200: b"vanilla-only"})

    def test_shared_didx_media_does_not_authorize_external_stream_change(self) -> None:
        vanilla = make_bank(
            objects=[(2, 10, sound_body(stream_type=1, wem_id=100))],
            media=[(100, b"same-embedded-media")],
        )
        payload = make_bank(
            objects=[(2, 10, sound_body(stream_type=2, wem_id=100))],
            media=[(100, b"same-embedded-media")],
        )

        merged = bnk.merge_bnk_with_vanilla(
            vanilla,
            payload,
            external_wem_ids=set(),
        )

        self.assertEqual(sections_by_id(merged)[b"HIRC"], sections_by_id(vanilla)[b"HIRC"])
        self.assertEqual(media_by_id(merged), {100: b"same-embedded-media"})

    def test_rejects_referenced_sound_delta_beyond_stream_type(self) -> None:
        vanilla = make_bank(
            objects=[
                (
                    2,
                    10,
                    sound_body(stream_type=1, wem_id=100, tail=b"vanilla"),
                )
            ]
        )
        payload = make_bank(
            objects=[
                (
                    2,
                    10,
                    sound_body(stream_type=2, wem_id=100, tail=b"payload"),
                )
            ]
        )

        with self.assertRaisesRegex(bnk.BnkMergeError, "alem de StreamType"):
            bnk.merge_bnk_with_vanilla(
                vanilla,
                payload,
                external_wem_ids={100},
            )

    def test_unprovided_stale_sound_deltas_remain_exactly_vanilla(self) -> None:
        vanilla = make_bank(
            objects=[
                (2, 10, sound_body(stream_type=1, wem_id=100, media_size=400)),
                (2, 11, sound_body(stream_type=1, wem_id=101)),
            ]
        )
        payload = make_bank(
            objects=[
                (2, 10, sound_body(stream_type=1, wem_id=100, media_size=300)),
                (2, 11, sound_body(stream_type=2, wem_id=101)),
            ]
        )

        merged = bnk.merge_bnk_with_vanilla(
            vanilla,
            payload,
            external_wem_ids=set(),
        )

        self.assertEqual(sections_by_id(merged)[b"HIRC"], sections_by_id(vanilla)[b"HIRC"])

    def test_real_regression_shape_changes_only_objects_with_external_wems(self) -> None:
        translated_count = 1_174
        external_authorized_count = 1_010
        stale_size_count = 46
        stale_stream_count = 6
        translated_objects_vanilla = []
        translated_objects_payload = []
        vanilla_media = []
        payload_media = []
        translated_wem_ids: set[int] = set()
        for index in range(translated_count):
            object_id = 100_000 + index
            wem_id = 200_000 + index
            if index < external_authorized_count:
                translated_wem_ids.add(wem_id)
            translated_objects_vanilla.append(
                (2, object_id, sound_body(stream_type=1, wem_id=wem_id, media_size=2))
            )
            translated_objects_payload.append(
                (2, object_id, sound_body(stream_type=2, wem_id=wem_id, media_size=2))
            )
            original_media = bytes((index % 251, 0))
            vanilla_media.append((wem_id, original_media))
            payload_media.append(
                (wem_id, bytes((index % 251, 1)))
                if index < 9
                else (wem_id, original_media)
            )

        stale_objects_vanilla = []
        stale_objects_payload = []
        for index in range(stale_size_count):
            object_id = 300_000 + index
            wem_id = 400_000 + index
            stale_objects_vanilla.append(
                (2, object_id, sound_body(stream_type=1, wem_id=wem_id, media_size=400))
            )
            stale_objects_payload.append(
                (2, object_id, sound_body(stream_type=1, wem_id=wem_id, media_size=300))
            )
        for index in range(stale_stream_count):
            object_id = 500_000 + index
            wem_id = 600_000 + index
            stale_objects_vanilla.append(
                (2, object_id, sound_body(stream_type=1, wem_id=wem_id))
            )
            stale_objects_payload.append(
                (2, object_id, sound_body(stream_type=2, wem_id=wem_id))
            )

        vanilla = make_bank(
            objects=[*translated_objects_vanilla, *stale_objects_vanilla],
            media=vanilla_media,
            bank_id=7,
        )
        payload = make_bank(
            objects=[*translated_objects_payload, *stale_objects_payload],
            media=payload_media,
            bank_id=7,
        )
        merged = bnk.merge_bnk_with_vanilla(
            vanilla,
            payload,
            external_wem_ids=translated_wem_ids,
        )

        vanilla_objects = bnk.parse_hirc(sections_by_id(vanilla)[b"HIRC"].data)
        merged_objects = bnk.parse_hirc(sections_by_id(merged)[b"HIRC"].data)
        self.assertEqual(len(merged_objects), translated_count + 52)
        for before, after in zip(
            vanilla_objects[:external_authorized_count],
            merged_objects[:external_authorized_count],
            strict=True,
        ):
            self.assertIn(sound_fields(after)[1], translated_wem_ids)
            self.assertEqual(after.raw[:13], before.raw[:13])
            self.assertEqual(after.raw[13], 2)
            self.assertEqual(after.raw[14:], before.raw[14:])
        self.assertEqual(
            [item.raw for item in merged_objects[external_authorized_count:]],
            [item.raw for item in vanilla_objects[external_authorized_count:]],
        )
        self.assertEqual(media_by_id(merged), dict(payload_media))
        self.assertEqual(len(merged), len(vanilla))

    def test_rejects_media_that_exceeds_exact_vanilla_data_size(self) -> None:
        vanilla = make_bank(
            objects=[],
            media=[(100, b"A")],
        )
        payload = make_bank(
            objects=[],
            media=[(100, b"payload-is-larger")],
        )

        with self.assertRaisesRegex(bnk.BnkMergeError, "excedem o DATA vanilla"):
            bnk.merge_bnk_with_vanilla(
                vanilla,
                payload,
                external_wem_ids=set(),
            )

    def test_rejects_truncated_type_two_layout_even_when_unreferenced(self) -> None:
        malformed = make_bank(objects=[(2, 10, b"too-short")])

        with self.assertRaisesRegex(bnk.BnkMergeError, "truncado"):
            bnk.merge_bnk_with_vanilla(
                malformed,
                malformed,
                external_wem_ids=set(),
            )

    def test_rejects_unexpected_stream_type_even_when_unreferenced(self) -> None:
        malformed = make_bank(
            objects=[(2, 10, sound_body(stream_type=3, wem_id=100))]
        )

        with self.assertRaisesRegex(bnk.BnkMergeError, "StreamType inesperado"):
            bnk.merge_bnk_with_vanilla(
                malformed,
                malformed,
                external_wem_ids=set(),
            )

    def test_rejects_unsupported_wwise_layout(self) -> None:
        unsupported = make_bank(objects=[], version=136)

        with self.assertRaisesRegex(bnk.BnkMergeError, "Wwise 136"):
            bnk.merge_bnk_with_vanilla(
                unsupported,
                unsupported,
                external_wem_ids=set(),
            )

    def test_external_wem_ids_must_be_explicit_valid_set(self) -> None:
        bank = make_bank(objects=[])

        for invalid in ([10], {True}, {-1}, {1 << 32}, {"10"}):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(bnk.BnkMergeError, "ID|conjunto"):
                    bnk.merge_bnk_with_vanilla(
                        bank,
                        bank,
                        external_wem_ids=invalid,  # type: ignore[arg-type]
                    )

    def test_rejects_different_bank_identity(self) -> None:
        vanilla = make_bank(objects=[], bank_id=7)
        payload = make_bank(objects=[], bank_id=8)

        with self.assertRaisesRegex(bnk.BnkMergeError, "outro banco"):
            bnk.merge_bnk_with_vanilla(
                vanilla,
                payload,
                external_wem_ids=set(),
            )

    def test_rejects_hirc_tail_not_declared_in_object_count(self) -> None:
        malformed_hirc = make_hirc([]) + b"junk"
        malformed = section(b"BKHD", struct.pack("<II", 135, 7)) + section(
            b"HIRC", malformed_hirc
        )

        with self.assertRaisesRegex(bnk.BnkMergeError, "fora da lista"):
            bnk.merge_bnk_with_vanilla(
                malformed,
                malformed,
                external_wem_ids=set(),
            )

    def test_rejects_nonzero_data_padding(self) -> None:
        didx = struct.pack("<III", 10, 1, 1)
        malformed = (
            section(b"BKHD", struct.pack("<II", 135, 7))
            + section(b"DIDX", didx)
            + section(b"DATA", b"XA")
            + section(b"HIRC", make_hirc([]))
        )

        with self.assertRaisesRegex(bnk.BnkMergeError, "nao e zero"):
            bnk.merge_bnk_with_vanilla(
                malformed,
                malformed,
                external_wem_ids=set(),
            )


if __name__ == "__main__":
    unittest.main()
