from __future__ import annotations

import json
import unittest
from unittest import mock

from patcher import diagnostics


def make_report(**overrides: object) -> str:
    values: dict[str, object] = {
        "patcher_version": "0.9.5",
        "operation": "install",
        "stage": "validate_build",
        "status": "failed",
        "error_code": "COMPAT-001",
        "error_kind": "unsupported_build",
        "error_message": "Build nao suportado.",
        "supported_game_version": "1.17.1",
        "supported_build_ids": ("25080141",),
        "detected_build_id": "24900000",
        "build_status": "detected",
    }
    values.update(overrides)
    return diagnostics.build_diagnostic_report(**values)  # type: ignore[arg-type]


class DiagnosticReportTests(unittest.TestCase):
    def test_report_has_identity_timestamp_and_a_final_newline(self) -> None:
        report_text = make_report()
        report = json.loads(report_text)

        self.assertTrue(report_text.endswith("\n"))
        self.assertEqual(report["schema"], "erptbr-diagnostic")
        self.assertEqual(report["schema_version"], 1)
        self.assertRegex(
            report["report_id"],
            r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        )
        self.assertRegex(report["created_at_utc"], r"^\d{4}-\d{2}-\d{2}T.*Z$")
        self.assertEqual(report["patcher"]["version"], "0.9.5")
        self.assertEqual(report["operation"]["stage"], "validate_build")
        self.assertIsNone(report["operation"]["stage_elapsed_seconds"])
        self.assertEqual(
            report["operation"]["progress"], {"current": None, "total": None}
        )
        self.assertEqual(
            report["compatibility"]["supported_steam_build_ids"],
            ["25080141"],
        )
        self.assertFalse(report["privacy"]["automatic_upload"])
        self.assertFalse(report["privacy"]["diagnostic_network_access"])
        self.assertFalse(report["privacy"]["game_files_inspected"])

    def test_operation_progress_and_write_state_are_structured_and_bounded(self) -> None:
        report = json.loads(
            make_report(
                stage_elapsed_seconds=17,
                progress_current=-2,
                progress_total=9,
                game_write_state="patch_not_started",
            )
        )

        self.assertEqual(report["operation"]["stage_elapsed_seconds"], 17)
        self.assertEqual(
            report["operation"]["progress"], {"current": 0, "total": 9}
        )
        self.assertEqual(
            report["operation"]["game_write_state"], "patch_not_started"
        )

    def test_sanitizer_redacts_paths_email_secrets_identity_and_steam_id(self) -> None:
        raw = (
            "Falha em \"C:\\Users\\Alice Smith\\Steam\\eldenring.exe\"\n"
            "rede=\\\\server\\share\\private\nunix=/home/alice/game\n"
            "email=alice@example.com\ntoken=very-secret-token\n"
            "Authorization: Bearer abcdefghijklmnop\n"
            "username=Alice\nhostname=DESKTOP-PRIVATE\n"
            "SteamID=76561198012345678\n@private-user\n"
            "SteamID=[U:1:123456]\n"
            "%USERPROFILE%\\private\n"
            "https://example.invalid/report?access=private-query"
        )

        cleaned = diagnostics.sanitize_text(raw, max_chars=4_000)

        for secret in (
            "Alice Smith",
            "server",
            "/home/alice",
            "alice@example.com",
            "very-secret-token",
            "abcdefghijklmnop",
            "DESKTOP-PRIVATE",
            "76561198012345678",
            "@private-user",
            "%USERPROFILE%",
            "private-query",
        ):
            self.assertNotIn(secret, cleaned)
        self.assertIn("[CAMINHO]", cleaned)
        self.assertIn("[EMAIL]", cleaned)
        self.assertIn("[SEGREDO]", cleaned)
        self.assertIn("[STEAM_ID]", cleaned)

    def test_sanitizer_redacts_tricky_paths_and_complete_urls(self) -> None:
        raw = (
            "C:\\Program Files (x86)\\Users\\Alice\\ERPT\n"
            "\\Users\\Alice\\Documents\\ERPT\n"
            "https://hooks.example.invalid/api/webhooks/id/private-secret\n"
            "//server/share/Users/Alice/private\n"
            "path:/home/alice/private\n"
            "\\private.txt"
        )

        cleaned = diagnostics.sanitize_text(raw, max_chars=4_000)

        self.assertNotIn("Alice", cleaned)
        self.assertNotIn("private-secret", cleaned)
        self.assertNotIn("webhooks", cleaned)
        self.assertEqual(
            cleaned.splitlines(),
            [
                "[CAMINHO]",
                "[CAMINHO]",
                "[URL]",
                "[CAMINHO]",
                "path:[CAMINHO]",
                "[CAMINHO]",
            ],
        )

    def test_sensitive_assignments_consume_the_entire_line(self) -> None:
        raw = (
            "Authorization: Basic QWxpY2U6c2VjcmV0\n"
            "Cookie: session=secret123; csrf=private456\n"
            "username=Alice Smith\n"
            "password=correct horse battery staple"
        )

        cleaned = diagnostics.sanitize_text(raw, max_chars=4_000)

        for secret in (
            "QWxpY2U6c2VjcmV0",
            "private456",
            "Smith",
            "horse battery staple",
        ):
            self.assertNotIn(secret, cleaned)
        self.assertEqual(cleaned.count("[SEGREDO]"), 3)
        self.assertIn("username=[IDENTIDADE]", cleaned)

    def test_compound_secrets_and_nonstandard_emails_are_redacted(self) -> None:
        raw = (
            "client_secret=client-value\n"
            "refresh_token=refresh-value\n"
            "AWS_SECRET_ACCESS_KEY=aws-value\n"
            "password_confirmation=confirmation-value\n"
            "credential=credential-value\n"
            "pwd=short-password\n"
            "signingKey=camel-key\n"
            "alice@localhost alice@[192.0.2.1] álïçé@exämple.invalid"
        )

        cleaned = diagnostics.sanitize_text(raw, max_chars=4_000)

        for private_value in (
            "client-value",
            "refresh-value",
            "aws-value",
            "confirmation-value",
            "credential-value",
            "short-password",
            "camel-key",
            "alice@localhost",
            "alice@[192.0.2.1]",
            "álïçé@exämple.invalid",
        ):
            self.assertNotIn(private_value, cleaned)
        self.assertEqual(cleaned.count("[SEGREDO]"), 7)
        self.assertEqual(cleaned.count("[EMAIL]"), 3)

    def test_quoted_and_bracketed_assignments_are_fully_redacted(self) -> None:
        raw = (
            '{"client_secret":"S3cr3tValue"}\n'
            '{"password":"JsonPassword"}\n'
            "{'Authorization': 'Basic QWxpY2U6c2VjcmV0'}\n"
            '{"username":"Alice Example"}\n'
            "password[confirmation]=BracketPassword\n"
            '{"steam.id":"76561198012345678"}'
        )

        cleaned = diagnostics.sanitize_text(raw, max_chars=4_000)

        for private_value in (
            "S3cr3tValue",
            "JsonPassword",
            "QWxpY2U6c2VjcmV0",
            "Alice Example",
            "BracketPassword",
            "76561198012345678",
        ):
            self.assertNotIn(private_value, cleaned)
        self.assertEqual(cleaned.count("[SEGREDO]"), 4)
        self.assertIn("username=[IDENTIDADE]", cleaned)
        self.assertIn("SteamID=[STEAM_ID]", cleaned)

    def test_common_secret_and_identity_aliases_are_redacted(self) -> None:
        raw = (
            '{"passphrase":"private phrase"}\n'
            '{"session_key":"session-secret"}\n'
            '{"proxy_authorization":"Basic private-auth"}\n'
            '{"user_name":"Alice Example"}\n'
            '{"host_name":"PC-Alice"}'
        )

        cleaned = diagnostics.sanitize_text(raw, max_chars=4_000)

        for private_value in (
            "private phrase",
            "session-secret",
            "private-auth",
            "Alice Example",
            "PC-Alice",
        ):
            self.assertNotIn(private_value, cleaned)
        self.assertEqual(cleaned.count("[SEGREDO]"), 3)
        self.assertEqual(cleaned.count("[IDENTIDADE]"), 2)

    def test_report_never_copies_traceback_or_raw_sensitive_values(self) -> None:
        report_text = make_report(
            error_message=(
                "falha C:\\Users\\private-user\\Game\n"
                "Traceback (most recent call last):\n"
                '  File "C:\\Users\\private-user\\tool.py", line 1\n'
                "RuntimeError: token=raw-secret"
            ),
            log_lines=(
                "[INFO] usuario=private-user",
                "Traceback (most recent call last):",
                '  File "C:\\private\\script.py", line 3',
                "ValueError: password=do-not-copy",
                "[INFO] etapa encerrada",
            ),
        )

        self.assertNotIn("private-user", report_text)
        self.assertNotIn("tool.py", report_text)
        self.assertNotIn("script.py", report_text)
        self.assertNotIn("raw-secret", report_text)
        self.assertNotIn("do-not-copy", report_text)
        self.assertNotIn("RuntimeError", report_text)
        self.assertNotIn("ValueError", report_text)
        self.assertIn("[TRACEBACK OMITIDO]", report_text)
        self.assertIn("etapa encerrada", report_text)

    def test_game_inventory_is_disabled_without_touching_the_path(self) -> None:
        path_that_must_not_be_used = mock.Mock()

        report = json.loads(make_report(game_dir=path_that_must_not_be_used))

        self.assertEqual(
            report["game_files"],
            {"scan_status": "disabled_for_race_safety", "items": []},
        )
        self.assertEqual(path_that_must_not_be_used.mock_calls, [])

    def test_message_and_log_are_bounded_and_keep_recent_lines(self) -> None:
        logs = [f"[INFO] line-{index}-" + "x" * 1_000 for index in range(100)]
        report = json.loads(
            make_report(
                error_message="e" * 10_000,
                log_lines=logs,
            )
        )

        self.assertLessEqual(
            len(report["error"]["message"]), diagnostics.MAX_ERROR_MESSAGE_CHARS
        )
        self.assertLessEqual(len(report["recent_log"]), diagnostics.MAX_LOG_LINES)
        self.assertNotIn("line-0-", "\n".join(report["recent_log"]))
        self.assertIn("line-99-", "\n".join(report["recent_log"]))
        self.assertLessEqual(
            len("\n".join(report["recent_log"])), diagnostics.MAX_LOG_TOTAL_CHARS
        )
        self.assertLessEqual(
            len(json.dumps(report, ensure_ascii=False).encode("utf-8")),
            diagnostics.MAX_REPORT_BYTES,
        )

    def test_utf8_report_is_bounded_by_bytes(self) -> None:
        report_text = make_report(
            error_message="🔒" * 10_000,
            log_lines=("🔒" * 1_000 for _ in range(100)),
        )

        self.assertLessEqual(
            len(report_text.encode("utf-8")), diagnostics.MAX_REPORT_BYTES
        )
        json.loads(report_text)

    def test_runtime_fields_are_sanitized_without_hostname(self) -> None:
        with (
            mock.patch.object(diagnostics.platform, "system", return_value="Windows"),
            mock.patch.object(
                diagnostics.platform,
                "release",
                return_value=r"11 C:\Users\private-user token=runtime-secret",
            ),
            mock.patch.object(
                diagnostics.platform,
                "machine",
                return_value="AMD64 hostname=DESKTOP-PRIVATE",
            ),
        ):
            report_text = make_report()

        self.assertNotIn("private-user", report_text)
        self.assertNotIn("runtime-secret", report_text)
        self.assertNotIn("DESKTOP-PRIVATE", report_text)
        self.assertNotIn("node", json.loads(report_text)["runtime"])


if __name__ == "__main__":
    unittest.main()
