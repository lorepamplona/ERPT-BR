from __future__ import annotations

from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

from patcher import patcher_gui


class GuiIntegrationTests(unittest.TestCase):
    def test_v094_production_installation_is_enabled(self) -> None:
        self.assertEqual(patcher_gui.PATCHER_VERSION, "0.9.4")
        self.assertFalse(patcher_gui.INSTALLATION_SUSPENDED)

    def test_startup_never_labels_an_unsupported_build_as_ready(self) -> None:
        app = mock.Mock()
        info = patcher_gui.SteamBuildInfo("99999999", "identified")

        patcher_gui.PatcherApp._finish_startup_status(app, info)

        app._set_stage.assert_called_once_with(
            "unsupported_build",
            "Versao nao suportada (99999999) [ERPT-COMPAT-001]; "
            "abra Diagnostico para copiar o relatorio.",
            finished=True,
        )
        error = app._record_error.call_args.args[0]
        self.assertIsInstance(error, patcher_gui.UnsupportedBuildError)
        self.assertIs(error.build_info, info)

    def test_startup_labels_only_the_pinned_build_as_ready(self) -> None:
        app = mock.Mock()
        info = patcher_gui.SteamBuildInfo("25080141", "identified")

        with mock.patch.object(patcher_gui, "INSTALLATION_SUSPENDED", False):
            patcher_gui.PatcherApp._finish_startup_status(app, info)

        app._record_error.assert_not_called()
        app._set_stage.assert_called_once_with(
            "ready",
            "Jogo compativel detectado; pronto para instalar.",
            finished=True,
        )

    @staticmethod
    def _diagnostic_state_stub() -> patcher_gui.PatcherApp:
        app = object.__new__(patcher_gui.PatcherApp)
        app._diagnostic_lock = threading.Lock()
        app._diagnostic_operation = "install"
        app._diagnostic_stage = "steam_build"
        app._diagnostic_stage_started = 10.0
        app._diagnostic_stage_elapsed = None
        app._diagnostic_write_state = "not_started"
        app._diagnostic_progress = (0, 0)
        app._detected_build_id = "11111111"
        app._build_read_status = "identified"
        app._detected_build_path_key = None
        app._last_error_code = None
        app._last_error_kind = None
        app._last_error_message = None
        app._log_history = []
        app._diagnostic_status = "Identificando"
        return app

    def test_authenticated_plan_covers_alias_not_selected_for_writing(self) -> None:
        selected = mock.Mock()
        selected.replacement.source_relative = "enus/voice.bnk"
        selected.source_sha256 = "a" * 64
        plan = mock.Mock()
        plan.payload_file_sha256 = (
            ("voice.bnk", "a" * 64),
            ("enus/voice.bnk", "a" * 64),
        )
        plan.payload_file_count = 2
        plan.matched_file_count = 2
        plan.writes = (selected,)
        patch_engine = mock.Mock()
        patch_engine.build_plan.return_value = plan

        with mock.patch.object(
            patcher_gui,
            "validate_patch_directory",
        ) as validate:
            result = patcher_gui.build_authenticated_plan(
                patch_engine,
                Path("payload"),
            )

        self.assertIs(result, plan)
        self.assertEqual(
            validate.call_args.kwargs["expected_file_sha256"],
            {
                "voice.bnk": "a" * 64,
                "enus/voice.bnk": "a" * 64,
            },
        )

    def test_close_is_safe_while_diagnostic_collection_finishes(self) -> None:
        app = object.__new__(patcher_gui.PatcherApp)
        app._busy = False
        app._report_collecting = 1
        app._closing = False
        app.destroy = mock.Mock()

        patcher_gui.PatcherApp._on_close(app)

        self.assertTrue(app._closing)
        app.destroy.assert_called_once_with()

    def test_ui_discards_callbacks_after_window_starts_closing(self) -> None:
        app = object.__new__(patcher_gui.PatcherApp)
        app._closing = True
        app.after = mock.Mock()

        patcher_gui.PatcherApp._ui(app, mock.Mock())

        app.after.assert_not_called()

    def test_ui_discards_an_already_queued_callback_after_close(self) -> None:
        app = object.__new__(patcher_gui.PatcherApp)
        app._closing = False
        queued: list[object] = []
        app.after = lambda _delay, callback: queued.append(callback)
        callback = mock.Mock()

        patcher_gui.PatcherApp._ui(app, callback)
        app._closing = True
        queued[0]()

        callback.assert_not_called()

    def test_reads_and_requires_the_pinned_steam_build(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            steamapps = Path(temporary) / "steamapps"
            game = steamapps / "common" / "ELDEN RING" / "Game"
            game.mkdir(parents=True)
            (steamapps / "appmanifest_1245620.acf").write_text(
                '"AppState"\n{\n  "buildid"  "25080141"\n}\n',
                encoding="utf-8",
            )

            self.assertEqual(patcher_gui.steam_build_id(game), "25080141")
            self.assertEqual(patcher_gui.require_supported_build(game), "25080141")

    def test_rejects_a_different_steam_build(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            steamapps = Path(temporary) / "steamapps"
            game = steamapps / "common" / "ELDEN RING" / "Game"
            game.mkdir(parents=True)
            (steamapps / "appmanifest_1245620.acf").write_text(
                '"buildid" "99999999"\n', encoding="utf-8"
            )

            with self.assertRaisesRegex(
                patcher_gui.UnsupportedBuildError,
                r"ERPT-COMPAT-001[\s\S]*Nenhum arquivo foi alterado",
            ) as raised:
                patcher_gui.require_supported_build(game)

            self.assertEqual(raised.exception.code, "ERPT-COMPAT-001")
            self.assertEqual(raised.exception.build_info.build_id, "99999999")
            self.assertEqual(raised.exception.build_info.status, "identified")

    def test_missing_manifest_has_an_explicit_detection_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            game = (
                Path(temporary)
                / "steamapps"
                / "common"
                / "ELDEN RING"
                / "Game"
            )
            game.mkdir(parents=True)

            info = patcher_gui.steam_build_info(game)

            self.assertIsNone(info.build_id)
            self.assertEqual(info.status, "manifest_missing")
            with self.assertRaisesRegex(
                patcher_gui.UnsupportedBuildError,
                "manifesto Steam nao encontrado",
            ):
                patcher_gui.require_supported_build(game, info)

    def test_install_worker_rejects_build_before_creating_engine(self) -> None:
        app = mock.Mock()
        build_error = patcher_gui.UnsupportedBuildError(
            patcher_gui.SteamBuildInfo("11111111", "identified"),
            before_game_writes=True,
        )
        app._validated_context.side_effect = build_error

        with mock.patch.object(patcher_gui, "PatchEngine") as engine_class:
            patcher_gui.PatcherApp._install_worker(app, "selected-game")

        engine_class.assert_not_called()
        app._report_failure.assert_called_once()
        self.assertIs(app._report_failure.call_args.kwargs["exc"], build_error)

    def test_install_worker_suspends_before_engine_or_payload_access(self) -> None:
        app = mock.Mock()
        app._validated_context.return_value = (Path("selected-game"), "25080141")

        with (
            mock.patch.object(patcher_gui, "INSTALLATION_SUSPENDED", True),
            mock.patch.object(patcher_gui, "PatchEngine") as engine_class,
            mock.patch.object(patcher_gui, "ensure_patch_data") as ensure_payload,
        ):
            patcher_gui.PatcherApp._install_worker(app, "selected-game")

        engine_class.assert_not_called()
        ensure_payload.assert_not_called()
        app._report_failure.assert_called_once()
        error = app._report_failure.call_args.kwargs["exc"]
        self.assertIsInstance(error, patcher_gui.InstallationSuspendedError)
        self.assertEqual(error.code, "ERPT-AUDIO-001")
        self.assertIn("Nenhum arquivo novo sera alterado", str(error))

    def test_install_worker_applies_payload_when_suspension_is_disabled(self) -> None:
        app = mock.Mock()
        app._diagnostic_lock = threading.Lock()
        game_dir = Path("selected-game")
        app._validated_context.return_value = (game_dir, "25080141")
        patch_engine = mock.Mock()
        patch_engine.load_archives.return_value = 42
        patch_engine.apply_plan.return_value = (2, 0)
        plan = mock.Mock()
        plan.matched_file_count = 2
        plan.payload_file_count = 2
        plan.match_ratio = 1.0
        plan.writes = (mock.Mock(), mock.Mock())
        plan.unmatched_files = ()

        with (
            mock.patch.object(patcher_gui, "INSTALLATION_SUSPENDED", False),
            mock.patch.object(
                patcher_gui, "PatchEngine", return_value=patch_engine
            ) as engine_class,
            mock.patch.object(
                patcher_gui, "ensure_patch_data", return_value=Path("payload")
            ) as ensure_payload,
            mock.patch.object(
                patcher_gui, "build_authenticated_plan", return_value=plan
            ) as build_plan,
        ):
            patcher_gui.PatcherApp._install_worker(app, "selected-game")

        engine_class.assert_called_once()
        patch_engine.load_archives.assert_called_once_with()
        ensure_payload.assert_called_once()
        build_plan.assert_called_once_with(
            patch_engine, Path("payload"), progress=app._progress
        )
        patch_engine.apply_plan.assert_called_once_with(
            plan,
            progress=app._progress,
            bhd_integrity_mode=patcher_gui.BHD_INTEGRITY_SCOPED_MOD,
        )
        app._report_failure.assert_not_called()
        app._set_stage.assert_any_call(
            "completed",
            "Dublagem instalada com seguranca.",
            write_state="committed",
            finished=True,
        )

    def test_suspension_code_is_preserved_in_diagnostic_state(self) -> None:
        app = self._diagnostic_state_stub()

        code, kind, _message = patcher_gui.PatcherApp._record_error(
            app, patcher_gui.InstallationSuspendedError()
        )

        self.assertEqual(code, "ERPT-AUDIO-001")
        self.assertEqual(kind, "InstallationSuspendedError")
        self.assertEqual(app._last_error_code, "ERPT-AUDIO-001")

    def test_restore_remains_available_while_installation_is_suspended(self) -> None:
        app = mock.Mock()
        game_dir = Path("selected-game")
        app._validated_context.return_value = (game_dir, "25080141")
        patch_engine = mock.Mock()

        with (
            mock.patch.object(patcher_gui, "INSTALLATION_SUSPENDED", True),
            mock.patch.object(
                patcher_gui, "PatchEngine", return_value=patch_engine
            ) as engine_class,
            mock.patch.object(patcher_gui, "ensure_patch_data") as ensure_payload,
        ):
            patcher_gui.PatcherApp._restore_worker(app, "selected-game")

        engine_class.assert_called_once()
        patch_engine.load_archives.assert_called_once_with()
        patch_engine.restore_current_backup.assert_called_once_with()
        ensure_payload.assert_not_called()
        app._report_failure.assert_not_called()
        app._set_stage.assert_any_call(
            "restore_completed",
            "Arquivos originais restaurados e verificados.",
            write_state="restored",
            finished=True,
        )

    def test_restore_failure_points_user_to_steam_verification(self) -> None:
        app = mock.Mock()
        app._validated_context.return_value = (Path("selected-game"), "25080141")
        patch_engine = mock.Mock()
        patch_engine.restore_current_backup.side_effect = patcher_gui.BackupError(
            "backup ausente; use a verificacao da Steam"
        )

        with mock.patch.object(
            patcher_gui, "PatchEngine", return_value=patch_engine
        ):
            patcher_gui.PatcherApp._restore_worker(app, "selected-game")

        app._report_failure.assert_called_once()
        error = app._report_failure.call_args.kwargs["exc"]
        self.assertIn("verificacao da Steam", str(error))

    def test_precommit_build_change_does_not_claim_no_files_changed(self) -> None:
        error = patcher_gui.UnsupportedBuildError(
            patcher_gui.SteamBuildInfo("11111111", "identified"),
            before_game_writes=False,
        )

        self.assertNotIn("Nenhum arquivo foi alterado", str(error))
        self.assertIn("revalidacao de seguranca", str(error))

    def test_error_freezes_stage_elapsed_time_for_later_report(self) -> None:
        app = self._diagnostic_state_stub()
        with mock.patch.object(
            patcher_gui.time, "monotonic", return_value=15.9
        ):
            patcher_gui.PatcherApp._record_error(app, ValueError("falha"))

        with mock.patch.object(
            patcher_gui,
            "build_diagnostic_report",
            return_value="{}\n",
        ) as build_report:
            patcher_gui.PatcherApp._diagnostic_report(app, "")

        self.assertEqual(
            build_report.call_args.kwargs["stage_elapsed_seconds"], 5
        )

    def test_manual_report_does_not_reread_manifest_or_reuse_another_path(self) -> None:
        app = self._diagnostic_state_stub()
        app._last_error_code = "ERPT-INSTALL-001"
        app._detected_build_path_key = patcher_gui.PatcherApp._diagnostic_path_key(
            "original-game"
        )
        with mock.patch.object(
            patcher_gui,
            "steam_build_info",
        ) as read_manifest:
            snapshot = patcher_gui.PatcherApp._diagnostic_snapshot(app, "other-game")

        read_manifest.assert_not_called()
        self.assertIsNone(snapshot["detected_build_id"])
        self.assertEqual(snapshot["build_status"], "not_checked")

    def test_manual_report_keeps_build_already_read_for_the_same_path(self) -> None:
        app = self._diagnostic_state_stub()
        app._detected_build_path_key = patcher_gui.PatcherApp._diagnostic_path_key(
            "selected-game"
        )

        snapshot = patcher_gui.PatcherApp._diagnostic_snapshot(
            app, r".\selected-game"
        )

        self.assertEqual(snapshot["detected_build_id"], "11111111")
        self.assertEqual(snapshot["build_status"], "identified")

    def test_failure_schedules_dialog_before_collecting_diagnostic(self) -> None:
        app = self._diagnostic_state_stub()
        app._status = mock.Mock()
        app._log = mock.Mock()
        scheduled: list[object] = []
        app._ui = scheduled.append

        with mock.patch.object(patcher_gui, "build_diagnostic_report") as build:
            patcher_gui.PatcherApp._report_failure(
                app,
                title="Falha",
                exc=ValueError("erro"),
                selected_path="",
                status_message="Cancelada",
            )

        build.assert_not_called()
        self.assertEqual(len(scheduled), 1)
        with app._diagnostic_lock:
            app._diagnostic_stage = "new_attempt"
            app._last_error_code = None
            app._detected_build_id = "22222222"
        app._show_failure_dialog = mock.Mock()
        scheduled[0]()  # type: ignore[operator]
        snapshot = app._show_failure_dialog.call_args.args[2]
        self.assertEqual(snapshot["stage"], "steam_build")
        self.assertEqual(snapshot["error_code"], "ERPT-DATA-001")
        self.assertEqual(snapshot["detected_build_id"], "11111111")

    def test_diagnostic_button_remains_available_while_install_is_busy(self) -> None:
        app = object.__new__(patcher_gui.PatcherApp)
        app._busy = False
        app.install_button = mock.Mock()
        app.restore_button = mock.Mock()
        app.browse_button = mock.Mock()
        app.path_entry = mock.Mock()
        app.report_button = mock.Mock()

        patcher_gui.PatcherApp._set_busy(app, True)

        self.assertTrue(app._busy)
        app.report_button.configure.assert_not_called()

    def test_optional_movie_payload_is_detected_before_install(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "movie").mkdir()
            (root / "movie" / "intro.bk2").write_bytes(b"untrusted")

            self.assertTrue(patcher_gui.optional_movie_payload_present(root))

    def test_empty_movie_directory_is_not_treated_as_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "movie_dlc").mkdir()

            self.assertFalse(patcher_gui.optional_movie_payload_present(root))

    def test_legacy_movie_sidecar_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            game = Path(temporary)
            sidecar = game / "movie" / "intro.bk2.original"
            sidecar.parent.mkdir()
            sidecar.write_bytes(b"legacy")

            self.assertEqual(patcher_gui.legacy_movie_sidecars(game), [sidecar])

    def test_process_detection_failure_blocks_writes_on_windows(self) -> None:
        with (
            mock.patch.object(patcher_gui.sys, "platform", "win32"),
            mock.patch.object(
                patcher_gui.subprocess,
                "run",
                side_effect=OSError("tasklist unavailable"),
            ),
        ):
            with self.assertRaisesRegex(
                patcher_gui.PatcherError, "Nenhum arquivo sera alterado"
            ):
                patcher_gui.running_blockers()

    def test_process_detection_includes_easy_anticheat_eos(self) -> None:
        result = mock.Mock(
            returncode=0,
            stdout='"EasyAntiCheat_EOS.exe","123","Console","1","10.000 K"\n',
        )
        with (
            mock.patch.object(patcher_gui.sys, "platform", "win32"),
            mock.patch.dict(patcher_gui.os.environ, {"SystemRoot": r"C:\\Windows"}),
            mock.patch.object(patcher_gui.Path, "is_file", return_value=True),
            mock.patch.object(patcher_gui.subprocess, "run", return_value=result),
        ):
            self.assertEqual(
                patcher_gui.running_blockers(),
                ["Easy Anti-Cheat EOS"],
            )


if __name__ == "__main__":
    unittest.main()
