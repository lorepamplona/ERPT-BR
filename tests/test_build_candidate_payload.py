from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

from patcher import patch_data
from tools import build_candidate_payload


WEM = b"RIFF" + (4).to_bytes(4, "little") + b"WAVE"
BNK = b"BKHD" + (0).to_bytes(4, "little")


def _record(root: Path, relative: str, role: str) -> build_candidate_payload.CandidateFile:
    path = root / Path(*relative.split("/"))
    digest, snapshot = build_candidate_payload._hash_regular(path, label=relative)
    return build_candidate_payload.CandidateFile(
        relative=relative,
        source=path,
        role=role,
        size=snapshot.size,
        sha256=digest,
        snapshot=snapshot,
    )


def _small_build_inputs(
    root: Path,
) -> tuple[Path, Path, Path, tuple[build_candidate_payload.CandidateFile, ...], dict]:
    historical = root / "historical"
    rebuild = root / "rebuild"
    output = root / "candidate"
    historical.mkdir()
    rebuild.mkdir()
    (historical / "100.wem").write_bytes(WEM)
    (rebuild / "a.bnk").write_bytes(BNK)
    records = tuple(
        sorted(
            (
                _record(historical, "100.wem", "WEM histórico autenticado"),
                _record(rebuild, "a.bnk", "BNK reconstruído"),
            ),
            key=lambda item: item.relative.casefold(),
        )
    )
    rebuild_manifest = {
        "algorithm": build_candidate_payload.REBUILD_ALGORITHM,
        "target": {"build_fingerprint": "test-build"},
        "output": {
            "banks_sha256": "11" * 32,
            "alias_tree_sha256": "22" * 32,
        },
    }
    return historical, rebuild, output, records, rebuild_manifest


class CandidatePayloadTests(unittest.TestCase):
    def test_archive_is_deterministic_and_validates_every_inflated_member(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            tree = root / "patch_data"
            (tree / "enus").mkdir(parents=True)
            (tree / "100.wem").write_bytes(WEM)
            (tree / "enus" / "a.bnk").write_bytes(BNK)
            records = tuple(
                sorted(
                    (
                        _record(tree, "100.wem", "WEM histórico autenticado"),
                        _record(tree, "enus/a.bnk", "BNK reconstruído"),
                    ),
                    key=lambda item: item.relative.casefold(),
                )
            )
            tree_sha, total_size, max_size, hashes = (
                build_candidate_payload._tree_identity(tree, records)
            )
            first = root / "first.zip"
            second = root / "second.zip"
            first_size, first_sha = build_candidate_payload.write_deterministic_archive(
                first, tree, records
            )
            second_size, second_sha = build_candidate_payload.write_deterministic_archive(
                second, tree, records
            )

            self.assertEqual((first_size, first_sha), (second_size, second_sha))
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(first) as archive:
                self.assertEqual(
                    archive.namelist(),
                    ["patch_data/100.wem", "patch_data/enus/a.bnk"],
                )
                self.assertEqual(
                    {info.date_time for info in archive.infolist()},
                    {build_candidate_payload.FIXED_ZIP_TIME},
                )

            spec = patch_data.PayloadSpec(
                version="test-rc",
                archive_name="first.zip",
                url="https://example.invalid/first.zip",
                archive_size=first_size,
                sha256=first_sha,
                wem_count=1,
                bnk_count=1,
                uncompressed_size=total_size,
                max_file_size=max_size,
                tree_sha256=tree_sha,
            )
            self.assertEqual(
                build_candidate_payload.validate_archive_contents(
                    first, spec=spec, expected_hashes=hashes
                ),
                tree_sha,
            )

    def test_marker_is_compatible_with_directory_validator(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            tree = Path(temp)
            (tree / "100.wem").write_bytes(WEM)
            (tree / "a.bnk").write_bytes(BNK)
            records = (
                _record(tree, "100.wem", "WEM histórico autenticado"),
                _record(tree, "a.bnk", "BNK reconstruído"),
            )
            tree_sha, total_size, max_size, hashes = (
                build_candidate_payload._tree_identity(tree, records)
            )
            spec = patch_data.PayloadSpec(
                version="test-rc",
                archive_name="candidate.zip",
                url="https://example.invalid/candidate.zip",
                archive_size=123,
                sha256="01" * 32,
                wem_count=1,
                bnk_count=1,
                uncompressed_size=total_size,
                max_file_size=max_size,
                tree_sha256=tree_sha,
            )
            (tree / patch_data.MARKER_FILENAME).write_text(
                json.dumps(build_candidate_payload._marker_data(spec)),
                encoding="utf-8",
            )
            stats = patch_data.validate_patch_directory(
                tree, spec=spec, expected_file_sha256=hashes
            )
            self.assertEqual((stats.wem_count, stats.bnk_count), (1, 1))

    def test_historical_marker_requires_exact_pinned_document(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            marker = build_candidate_payload._marker_data(
                patch_data.PRODUCTION_PAYLOAD
            )
            (root / patch_data.MARKER_FILENAME).write_text(
                json.dumps(marker), encoding="utf-8"
            )
            digest = build_candidate_payload._validate_historical_marker(root)
            self.assertEqual(len(digest), 64)

            marker["unexpected"] = "not-pinned"
            (root / patch_data.MARKER_FILENAME).write_text(
                json.dumps(marker), encoding="utf-8"
            )
            with self.assertRaisesRegex(
                build_candidate_payload.CandidateBuildError,
                "não corresponde exatamente",
            ):
                build_candidate_payload._validate_historical_marker(root)

    def test_rebuild_manifest_and_aggregate_pins_reject_self_consistent_tamper(
        self,
    ) -> None:
        self.assertEqual(
            build_candidate_payload.EXPECTED_REBUILD_MANIFEST_SHA256,
            "211697c3d5af07e40bbc4f9cce091cfd5769c3865d31ee6a7a5ae9bfca370111",
        )
        self.assertEqual(
            build_candidate_payload.EXPECTED_REBUILT_BANKS_SHA256,
            "77d9276e641169274233147d95a325a6413ffb3495105df73be857fa7ed27636",
        )
        self.assertEqual(
            build_candidate_payload.EXPECTED_REBUILT_ALIAS_TREE_SHA256,
            "1d05c510d6c900fa90a7b46c8e300f47d3a99eff70f32f5bf42d67b1fd5dc120",
        )

        def aggregate_hashes(bank_hash: str) -> tuple[str, str]:
            physical = hashlib.sha256()
            physical.update(b"vcmain.bnk\0")
            physical.update(bytes.fromhex(bank_hash))
            aliases = hashlib.sha256()
            for relative in ("enus/vcmain.bnk", "vcmain.bnk"):
                aliases.update(relative.encode("utf-8"))
                aliases.update(b"\0")
                aliases.update(bytes.fromhex(bank_hash))
            return physical.hexdigest(), aliases.hexdigest()

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bank = root / "vcmain.bnk"
            bank.write_bytes(BNK)
            bank_hash = hashlib.sha256(BNK).hexdigest()
            banks_hash, aliases_hash = aggregate_hashes(bank_hash)
            record = {
                "output_path": "vcmain.bnk",
                "output_sha256": bank_hash,
                "output_size": len(BNK),
                "output_aliases": ["vcmain.bnk", "enus/vcmain.bnk"],
                "sound_object_ids_changed": [],
                "sound_object_ids_filtered": [],
            }
            manifest = {
                "schema": build_candidate_payload.REBUILD_SCHEMA,
                "algorithm": build_candidate_payload.REBUILD_ALGORITHM,
                "target": {
                    "steam_build_id": build_candidate_payload.EXPECTED_BUILD_ID,
                    "game_version": build_candidate_payload.EXPECTED_GAME_VERSION,
                },
                "metrics": {
                    "banks_rebuilt": 1,
                    "bank_aliases_verified": 2,
                    "output_alias_files": 2,
                    "identical_alias_pairs": 1,
                    "external_wem_ids": 0,
                    "sound_objects_changed": 0,
                    "sound_objects_filtered": 0,
                },
                "output": {
                    "banks_sha256": banks_hash,
                    "alias_tree_sha256": aliases_hash,
                    "banks": [record],
                },
            }
            manifest_path = root / "manifest.json"
            manifest_path.write_bytes(build_candidate_payload._json_bytes(manifest))
            manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
            empty_sha = hashlib.sha256().hexdigest()
            with (
                mock.patch.object(
                    build_candidate_payload, "EXPECTED_REBUILD_MANIFEST_SHA256", manifest_sha
                ),
                mock.patch.object(
                    build_candidate_payload, "EXPECTED_REBUILT_BANKS_SHA256", banks_hash
                ),
                mock.patch.object(
                    build_candidate_payload,
                    "EXPECTED_REBUILT_ALIAS_TREE_SHA256",
                    aliases_hash,
                ),
                mock.patch.object(build_candidate_payload, "EXPECTED_WEM_COUNT", 0),
                mock.patch.object(build_candidate_payload, "EXPECTED_BNK_COUNT", 2),
                mock.patch.object(
                    build_candidate_payload, "EXPECTED_PHYSICAL_BANK_COUNT", 1
                ),
                mock.patch.object(
                    build_candidate_payload, "EXPECTED_CHANGED_SOUND_OBJECTS", 0
                ),
                mock.patch.object(
                    build_candidate_payload, "EXPECTED_FILTERED_SOUND_OBJECTS", 0
                ),
                mock.patch.object(
                    build_candidate_payload, "EXPECTED_CHANGED_SOUND_IDS_SHA256", empty_sha
                ),
                mock.patch.object(
                    build_candidate_payload, "EXPECTED_FILTERED_SOUND_IDS_SHA256", empty_sha
                ),
                mock.patch.object(
                    build_candidate_payload, "EXPECTED_VCMAIN_FILTERED_IDS_SHA256", empty_sha
                ),
            ):
                build_candidate_payload._validate_rebuild_manifest(root)

                tampered = b"BKHD" + (1).to_bytes(4, "little")
                bank.write_bytes(tampered)
                tampered_hash = hashlib.sha256(tampered).hexdigest()
                tampered_banks, tampered_aliases = aggregate_hashes(tampered_hash)
                record["output_sha256"] = tampered_hash
                manifest["output"]["banks_sha256"] = tampered_banks
                manifest["output"]["alias_tree_sha256"] = tampered_aliases
                manifest_path.write_bytes(build_candidate_payload._json_bytes(manifest))

                with self.assertRaisesRegex(
                    build_candidate_payload.CandidateBuildError,
                    "manifesto de BNK.*canônico",
                ):
                    build_candidate_payload._validate_rebuild_manifest(root)

    def test_archive_content_validation_detects_wrong_per_file_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            tree = root / "patch_data"
            tree.mkdir()
            (tree / "100.wem").write_bytes(WEM)
            record = _record(tree, "100.wem", "WEM histórico autenticado")
            tree_sha, total_size, max_size, _hashes = (
                build_candidate_payload._tree_identity(tree, (record,))
            )
            archive = root / "candidate.zip"
            size, digest = build_candidate_payload.write_deterministic_archive(
                archive, tree, (record,)
            )
            spec = patch_data.PayloadSpec(
                version="test-rc",
                archive_name=archive.name,
                url="https://example.invalid/candidate.zip",
                archive_size=size,
                sha256=digest,
                wem_count=1,
                bnk_count=0,
                uncompressed_size=total_size,
                max_file_size=max_size,
                tree_sha256=tree_sha,
            )
            with self.assertRaisesRegex(
                build_candidate_payload.CandidateBuildError,
                "Conteúdo compactado divergente",
            ):
                build_candidate_payload.validate_archive_contents(
                    archive,
                    spec=spec,
                    expected_hashes={"100.wem": hashlib.sha256(b"wrong").hexdigest()},
                )

    def test_rejects_unsafe_paths_and_existing_archive(self) -> None:
        for value in (
            "../a.wem",
            "a\\b.wem",
            "a//b.wem",
            "C:/a.wem",
            "con.wem",
            "folder./a.wem",
            "marker.json",
        ):
            with self.subTest(value=value):
                with self.assertRaises(build_candidate_payload.CandidateBuildError):
                    build_candidate_payload._safe_relative(value)

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            tree = root / "tree"
            tree.mkdir()
            (tree / "100.wem").write_bytes(WEM)
            record = _record(tree, "100.wem", "WEM histórico autenticado")
            archive = root / "candidate.zip"
            archive.write_bytes(b"occupied")
            with self.assertRaisesRegex(
                build_candidate_payload.CandidateBuildError, "já existe"
            ):
                build_candidate_payload.write_deterministic_archive(
                    archive, tree, (record,)
                )

    def test_same_size_source_mutation_with_restored_mtime_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            tree = root / "tree"
            tree.mkdir()
            source = tree / "100.wem"
            source.write_bytes(WEM)
            record = _record(tree, "100.wem", "WEM histórico autenticado")
            atime_ns = source.stat().st_atime_ns
            source.write_bytes(b"RIFX" + WEM[4:])
            os.utime(
                source,
                ns=(atime_ns, record.snapshot.mtime_ns),
            )

            with self.assertRaisesRegex(
                build_candidate_payload.CandidateBuildError,
                "mudou|divergiu",
            ):
                build_candidate_payload.write_deterministic_archive(
                    root / "candidate.zip", tree, (record,)
                )

    def test_archive_validator_rejects_non_deterministic_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            content = WEM
            relative = "100.wem"
            tree_digest = hashlib.sha256()
            encoded = relative.encode("utf-8")
            tree_digest.update(len(encoded).to_bytes(4, "little"))
            tree_digest.update(encoded)
            tree_digest.update(len(content).to_bytes(8, "little"))
            tree_digest.update(content)
            archive_path = root / "candidate.zip"
            info = zipfile.ZipInfo(
                "patch_data/100.wem",
                date_time=(2026, 1, 1, 0, 0, 0),
            )
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o100644) << 16
            with zipfile.ZipFile(
                archive_path,
                "x",
                compression=zipfile.ZIP_DEFLATED,
            ) as archive:
                archive.writestr(info, content)
            archive_sha, archive_snapshot = build_candidate_payload._hash_regular(
                archive_path, label="ZIP de teste"
            )
            spec = patch_data.PayloadSpec(
                version="test-rc",
                archive_name=archive_path.name,
                url="https://example.invalid/candidate.zip",
                archive_size=archive_snapshot.size,
                sha256=archive_sha,
                wem_count=1,
                bnk_count=0,
                uncompressed_size=len(content),
                max_file_size=len(content),
                tree_sha256=tree_digest.hexdigest(),
            )

            with self.assertRaisesRegex(
                build_candidate_payload.CandidateBuildError,
                "Metadados não determinísticos",
            ):
                build_candidate_payload.validate_archive_contents(
                    archive_path,
                    spec=spec,
                    expected_hashes={relative: hashlib.sha256(content).hexdigest()},
                )

    def test_tree_identity_rejects_unplanned_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            tree = Path(temp)
            (tree / "100.wem").write_bytes(WEM)
            record = _record(tree, "100.wem", "WEM histórico autenticado")
            (tree / "unexpected.bnk").write_bytes(BNK)
            with self.assertRaisesRegex(
                build_candidate_payload.CandidateBuildError,
                "não corresponde exatamente",
            ):
                build_candidate_payload._tree_identity(tree, (record,))

    def test_exclusive_publication_never_replaces_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            staging = root / "staging"
            output = root / "output"
            staging.mkdir()
            (staging / "candidate.txt").write_text("candidate", encoding="utf-8")
            output.mkdir()
            protected = output / "user.txt"
            protected.write_text("keep", encoding="utf-8")
            parent_chain = build_candidate_payload._safe_directory_chain(
                root, label="Raiz de teste"
            )
            validated_bundle = build_candidate_payload._pin_exact_bundle(
                staging,
                expected_files={
                    "candidate.txt": hashlib.sha256(b"candidate").hexdigest()
                },
                expected_directories={""},
                label="Staging de teste",
            )

            with self.assertRaisesRegex(
                build_candidate_payload.CandidateBuildError,
                "apareceu",
            ):
                build_candidate_payload._publish_directory_exclusive(
                    staging,
                    output,
                    output_parent_chain=parent_chain,
                    validated_bundle=validated_bundle,
                )
            self.assertEqual(protected.read_text(encoding="utf-8"), "keep")
            self.assertTrue((staging / "candidate.txt").is_file())

    @unittest.skipUnless(os.name == "nt", "Windows no-replace semantics")
    def test_publication_race_never_replaces_new_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            staging = root / "staging"
            output = root / "output"
            staging.mkdir()
            (staging / "candidate.txt").write_text("candidate", encoding="utf-8")
            parent_chain = build_candidate_payload._safe_directory_chain(
                root, label="Raiz de teste"
            )
            validated_bundle = build_candidate_payload._pin_exact_bundle(
                staging,
                expected_files={
                    "candidate.txt": hashlib.sha256(b"candidate").hexdigest()
                },
                expected_directories={""},
                label="Staging de teste",
            )
            real_rename = os.rename

            def race_rename(source, destination):
                destination = Path(destination)
                destination.mkdir()
                (destination / "user.txt").write_text("keep", encoding="utf-8")
                return real_rename(source, destination)

            with mock.patch.object(
                build_candidate_payload.os,
                "rename",
                side_effect=race_rename,
            ):
                with self.assertRaisesRegex(
                    build_candidate_payload.CandidateBuildError,
                    "sem sobrescrever",
                ):
                    build_candidate_payload._publish_directory_exclusive(
                        staging,
                        output,
                        output_parent_chain=parent_chain,
                        validated_bundle=validated_bundle,
                    )

            self.assertEqual((output / "user.txt").read_text(encoding="utf-8"), "keep")
            self.assertEqual(
                (staging / "candidate.txt").read_text(encoding="utf-8"),
                "candidate",
            )

    @unittest.skipUnless(os.name == "nt", "Windows rename identity semantics")
    def test_publication_rejects_directory_identity_swap_after_rename(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            staging = root / "staging"
            output = root / "output"
            moved = root / "moved-validated-staging"
            staging.mkdir()
            (staging / "candidate.txt").write_text("candidate", encoding="utf-8")
            parent_chain = build_candidate_payload._safe_directory_chain(
                root, label="Raiz de teste"
            )
            validated_bundle = build_candidate_payload._pin_exact_bundle(
                staging,
                expected_files={
                    "candidate.txt": hashlib.sha256(b"candidate").hexdigest()
                },
                expected_directories={""},
                label="Staging de teste",
            )
            real_rename = os.rename

            def swap_after_rename(source, destination):
                real_rename(source, destination)
                real_rename(destination, moved)
                Path(destination).mkdir()

            with mock.patch.object(
                build_candidate_payload.os,
                "rename",
                side_effect=swap_after_rename,
            ):
                with self.assertRaisesRegex(
                    build_candidate_payload.CandidateBuildError,
                    "não é o staging validado",
                ):
                    build_candidate_payload._publish_directory_exclusive(
                        staging,
                        output,
                        output_parent_chain=parent_chain,
                        validated_bundle=validated_bundle,
                    )

            self.assertTrue(output.is_dir())
            self.assertEqual(
                (moved / "candidate.txt").read_text(encoding="utf-8"),
                "candidate",
            )

    def test_exclusive_metadata_writer_never_truncates(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "manifest.json"
            path.write_bytes(b"user-data")
            with self.assertRaisesRegex(
                build_candidate_payload.CandidateBuildError,
                "já existe",
            ):
                build_candidate_payload._write_json_exclusive(path, {"new": True})
            self.assertEqual(path.read_bytes(), b"user-data")

    def test_directory_chain_rejects_a_reparse_component(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            child = root / "child"
            child.mkdir()
            original = build_candidate_payload._is_reparse

            def mark_child(metadata: os.stat_result) -> bool:
                return metadata.st_ino == child.lstat().st_ino or original(metadata)

            with mock.patch.object(
                build_candidate_payload,
                "_is_reparse",
                side_effect=mark_child,
            ):
                with self.assertRaisesRegex(
                    build_candidate_payload.CandidateBuildError,
                    "sem link/reparse",
                ):
                    build_candidate_payload._safe_directory_chain(
                        child, label="Diretório de teste"
                    )

    def test_small_candidate_is_fully_validated_before_exclusive_publish(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            historical, rebuild, output, records, rebuild_manifest = (
                _small_build_inputs(root)
            )
            with (
                mock.patch.object(
                    build_candidate_payload,
                    "EXPECTED_WEM_COUNT",
                    1,
                ),
                mock.patch.object(
                    build_candidate_payload,
                    "EXPECTED_BNK_COUNT",
                    1,
                ),
                mock.patch.object(
                    build_candidate_payload,
                    "EXPECTED_PHYSICAL_BANK_COUNT",
                    1,
                ),
                mock.patch.object(
                    build_candidate_payload,
                    "collect_candidate_files",
                    return_value=(records, rebuild_manifest, "33" * 32, "44" * 32),
                ),
                mock.patch.object(
                    build_candidate_payload,
                    "_revalidate_sources",
                ) as source_revalidation,
            ):
                document = build_candidate_payload.build_candidate(
                    historical_payload=historical,
                    rebuild_root=rebuild,
                    output=output,
                    version="test-rc",
                    archive_name="candidate.zip",
                    url="https://example.invalid/candidate.zip",
                )

            self.assertTrue(output.is_dir())
            self.assertEqual(
                {entry.name for entry in output.iterdir()},
                {
                    "patch_data",
                    "candidate.zip",
                    "candidate-manifest.json",
                    "REPORT.md",
                },
            )
            self.assertEqual(document["statistics"]["file_count"], 2)
            self.assertTrue(document["validation"]["final_bundle_revalidation"])
            source_revalidation.assert_called_once()

    def test_same_size_mtime_tamper_after_staging_validation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            historical, rebuild, output, records, rebuild_manifest = (
                _small_build_inputs(root)
            )
            original_validate = build_candidate_payload._validate_final_bundle
            mutation = {"done": False, "mtime_restored": False}

            def validate_then_tamper(**kwargs):
                snapshot = original_validate(**kwargs)
                bundle_root = Path(kwargs["bundle_root"])
                if bundle_root != output and not mutation["done"]:
                    victim = bundle_root / "patch_data" / "100.wem"
                    before = victim.stat()
                    victim.write_bytes(b"RIFX" + WEM[4:])
                    os.utime(victim, ns=(before.st_atime_ns, before.st_mtime_ns))
                    mutation["done"] = True
                    mutation["mtime_restored"] = (
                        victim.stat().st_mtime_ns == before.st_mtime_ns
                    )
                return snapshot

            with (
                mock.patch.object(build_candidate_payload, "EXPECTED_WEM_COUNT", 1),
                mock.patch.object(build_candidate_payload, "EXPECTED_BNK_COUNT", 1),
                mock.patch.object(
                    build_candidate_payload, "EXPECTED_PHYSICAL_BANK_COUNT", 1
                ),
                mock.patch.object(
                    build_candidate_payload,
                    "collect_candidate_files",
                    return_value=(records, rebuild_manifest, "33" * 32, "44" * 32),
                ),
                mock.patch.object(build_candidate_payload, "_revalidate_sources"),
                mock.patch.object(
                    build_candidate_payload,
                    "_validate_final_bundle",
                    side_effect=validate_then_tamper,
                ),
            ):
                with self.assertRaisesRegex(
                    build_candidate_payload.CandidateBuildError,
                    "Conteúdo|Identidade|SHA-256|diverg",
                ):
                    build_candidate_payload.build_candidate(
                        historical_payload=historical,
                        rebuild_root=rebuild,
                        output=output,
                        version="test-rc",
                        archive_name="candidate.zip",
                        url="https://example.invalid/candidate.zip",
                    )

            self.assertTrue(mutation["done"])
            self.assertTrue(mutation["mtime_restored"])
            self.assertFalse(output.exists())
            self.assertEqual(
                len(tuple(root.glob(".candidate.*.staging"))),
                1,
            )

    def test_post_publish_tamper_is_rejected_and_final_artifact_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            historical, rebuild, output, records, rebuild_manifest = (
                _small_build_inputs(root)
            )
            original_hash = build_candidate_payload._hash_regular
            original_publish = build_candidate_payload._publish_directory_exclusive
            state = {"published": False, "mutated": False, "mtime_restored": False}

            def publish_then_mark(*args, **kwargs):
                result = original_publish(*args, **kwargs)
                state["published"] = True
                return result

            def hash_then_tamper(path, *args, **kwargs):
                result = original_hash(path, *args, **kwargs)
                path = Path(path)
                if (
                    state["published"]
                    and not state["mutated"]
                    and path == output / "REPORT.md"
                ):
                    victim = output / "patch_data" / "100.wem"
                    before = victim.stat()
                    victim.write_bytes(b"RIFX" + WEM[4:])
                    os.utime(victim, ns=(before.st_atime_ns, before.st_mtime_ns))
                    state["mutated"] = True
                    state["mtime_restored"] = (
                        victim.stat().st_mtime_ns == before.st_mtime_ns
                    )
                return result

            with (
                mock.patch.object(build_candidate_payload, "EXPECTED_WEM_COUNT", 1),
                mock.patch.object(build_candidate_payload, "EXPECTED_BNK_COUNT", 1),
                mock.patch.object(
                    build_candidate_payload, "EXPECTED_PHYSICAL_BANK_COUNT", 1
                ),
                mock.patch.object(
                    build_candidate_payload,
                    "collect_candidate_files",
                    return_value=(records, rebuild_manifest, "33" * 32, "44" * 32),
                ),
                mock.patch.object(build_candidate_payload, "_revalidate_sources"),
                mock.patch.object(
                    build_candidate_payload,
                    "_publish_directory_exclusive",
                    side_effect=publish_then_mark,
                ),
                mock.patch.object(
                    build_candidate_payload,
                    "_hash_regular",
                    side_effect=hash_then_tamper,
                ),
            ):
                with self.assertRaisesRegex(
                    build_candidate_payload.CandidateBuildError,
                    r"Artefato\(s\) preservado\(s\).*candidate",
                ):
                    build_candidate_payload.build_candidate(
                        historical_payload=historical,
                        rebuild_root=rebuild,
                        output=output,
                        version="test-rc",
                        archive_name="candidate.zip",
                        url="https://example.invalid/candidate.zip",
                    )

            self.assertTrue(state["published"])
            self.assertTrue(state["mutated"])
            self.assertTrue(state["mtime_restored"])
            self.assertTrue(output.is_dir())
            self.assertEqual(
                (output / "patch_data" / "100.wem").read_bytes(),
                b"RIFX" + WEM[4:],
            )

    def test_exact_bundle_snapshot_covers_marker_manifest_and_empty_directories(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "patch_data").mkdir()
            marker = root / "patch_data" / patch_data.MARKER_FILENAME
            manifest = root / "candidate-manifest.json"
            marker.write_bytes(b'{"marker":true}\n')
            manifest.write_bytes(b'{"manifest":true}\n')
            expected_files = {
                f"patch_data/{patch_data.MARKER_FILENAME}": hashlib.sha256(
                    marker.read_bytes()
                ).hexdigest(),
                "candidate-manifest.json": hashlib.sha256(
                    manifest.read_bytes()
                ).hexdigest(),
            }
            snapshot = build_candidate_payload._pin_exact_bundle(
                root,
                expected_files=expected_files,
                expected_directories={"", "patch_data"},
                label="Bundle de teste",
            )

            before = manifest.stat()
            manifest.write_bytes(b'{"manifest":fals}')
            os.utime(manifest, ns=(before.st_atime_ns, before.st_mtime_ns))
            with self.assertRaisesRegex(
                build_candidate_payload.CandidateBuildError,
                "Conteúdo|Identidade",
            ):
                build_candidate_payload._assert_bundle_snapshot(
                    root,
                    snapshot,
                    label="Bundle de teste",
                    verify_contents=True,
                )

            manifest.write_bytes(b'{"manifest":true}\n')
            (root / "patch_data" / "empty").mkdir()
            with self.assertRaisesRegex(
                build_candidate_payload.CandidateBuildError,
                "Inventário|identidade",
            ):
                build_candidate_payload._pin_exact_bundle(
                    root,
                    expected_files=expected_files,
                    expected_directories={"", "patch_data"},
                    label="Bundle de teste",
                )


if __name__ == "__main__":
    unittest.main()
