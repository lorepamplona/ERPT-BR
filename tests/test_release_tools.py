from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

from tools import build_source_release, verify_source_release


class ReleaseBytesTests(unittest.TestCase):
    def test_cmd_line_endings_are_checkout_independent(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            lf = root / "lf.cmd"
            crlf = root / "crlf.cmd"
            lf.write_bytes(b"@echo off\necho seguro\n")
            crlf.write_bytes(b"@echo off\r\necho seguro\r\n")

            expected = b"@echo off\r\necho seguro\r\n"
            self.assertEqual(build_source_release.release_bytes(lf), expected)
            self.assertEqual(build_source_release.release_bytes(crlf), expected)

    def test_non_cmd_bytes_are_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "payload.bin"
            data = b"\x00\r\n\xff\n"
            source.write_bytes(data)

            self.assertEqual(build_source_release.release_bytes(source), data)

    def test_verifier_rejects_oversized_member_before_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / verify_source_release.FINAL_ARCHIVE_NAME
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as out:
                for relative in sorted(verify_source_release.EXPECTED_FILES):
                    data = (
                        b"x" * (verify_source_release.MAX_MEMBER_SIZE + 1)
                        if relative == "README.md"
                        else b""
                    )
                    out.writestr(f"ERPT-BR-v0.9.4/{relative}", data)

            with self.assertRaisesRegex(SystemExit, "Membro grande demais"):
                verify_source_release.verify(str(archive))

    def test_verifier_rejects_excessive_member_count_before_iteration(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / verify_source_release.FINAL_ARCHIVE_NAME
            with zipfile.ZipFile(archive, "w") as out:
                for index in range(len(verify_source_release.EXPECTED_FILES) + 1):
                    out.writestr(f"ERPT-BR-v0.9.4/extra-{index}.txt", b"")

            with self.assertRaisesRegex(SystemExit, "quantidade inesperada"):
                verify_source_release.verify(str(archive))

    def test_builder_and_verifier_share_the_source_allowlist(self) -> None:
        self.assertEqual(
            set(build_source_release.SOURCE_FILES),
            set(verify_source_release.SOURCE_FILES),
        )
        self.assertIn("ERPT-BR.cmd", build_source_release.SOURCE_FILES)
        root_commands = [
            relative
            for relative in build_source_release.SOURCE_FILES
            if "/" not in relative and relative.casefold().endswith(".cmd")
        ]
        self.assertEqual(root_commands, ["ERPT-BR.cmd"])

    def test_one_click_bootstrap_keeps_authentication_controls(self) -> None:
        root = Path(__file__).resolve().parents[1]
        source = (root / "ERPT-BR.cmd").read_text(encoding="utf-8")

        self.assertIn("--exact --id Python.Python.3.13 --version 3.13.15", source)
        self.assertIn("--scope user --architecture x64", source)
        self.assertIn("InstallAllUsers=0", source)
        self.assertIn("InstallLauncherAllUsers=0", source)
        self.assertIn("PrependPath=0", source)
        self.assertIn("AppendPath=0", source)
        self.assertIn("Microsoft.PowerShell.Utility\\Get-FileHash", source)
        self.assertIn(
            "Microsoft.PowerShell.Security\\Get-AuthenticodeSignature -LiteralPath",
            source,
        )
        self.assertIn("[IO.FileStream]::new", source)
        self.assertIn("[IO.FileOptions]::DeleteOnClose", source)
        self.assertIn('for /f "delims=" %%G in (\'%ERPT_POWERSHELL%', source)
        self.assertNotIn("usebackq", source.casefold())
        self.assertEqual(source.count("goto :install_direct"), 1)
        self.assertIn('call "%~dp0interno\\ABRIR_INTERFACE.cmd"', source)
        self.assertIn("'patcher\\bnk.py'", source)
        self.assertIn("'patcher\\diagnostics.py'", source)
        self.assertNotIn('call "%~dp0interno\\INSTALAR_AMBIENTE.cmd"', source)
        self.assertIn('set "ERPTBR_INTERNAL_CALL=1"', source)
        self.assertIn("Local\\ERPTBR_Installer_", source)
        self.assertNotIn("Local\\ERPTBR_Installer_v091", source)
        self.assertNotIn("docs\\INCIDENTE-0.9.1.md", source)
        self.assertIn("ERPT-PACKAGE-001", source)
        self.assertIn("Arquivo obrigatorio ausente:", source)
        self.assertIn("use Extrair Tudo primeiro", source)
        self.assertLess(
            source.index("rem Recusa ZIP automatico"),
            source.index("call :find_python"),
        )
        for forbidden in (
            "--ignore-security-hash",
            "-ExecutionPolicy Bypass",
            "-EncodedCommand",
            "Invoke-Expression",
            "InstallAllUsers=1",
            "-Verb RunAs",
            "http://",
        ):
            self.assertNotIn(forbidden.casefold(), source.casefold())

    def test_verifier_requires_production_gui_safety_controls(self) -> None:
        root = Path(__file__).resolve().parents[1]
        source = (root / "patcher" / "patcher_gui.py").read_text(encoding="utf-8")

        verify_source_release._verify_gui_controls(source)
        stale = source.replace(
            "bhd_integrity_mode=BHD_INTEGRITY_SCOPED_MOD",
            "bhd_integrity_mode='strict'",
            1,
        )
        with self.assertRaisesRegex(SystemExit, "Controles obrigatorios"):
            verify_source_release._verify_gui_controls(stale)

    def test_internal_launcher_repairs_missing_dependencies_once(self) -> None:
        root = Path(__file__).resolve().parents[1]
        source = (root / "interno" / "ABRIR_INTERFACE.cmd").read_text(
            encoding="utf-8"
        )

        self.assertIn(
            "import tkinter,customtkinter; from Crypto.Cipher import AES", source
        )
        self.assertIn("if defined ERPTBR_REPAIR_ATTEMPTED", source)
        self.assertIn('call "%~dp0INSTALAR_AMBIENTE.cmd"', source)
        self.assertIn("if defined ERPTBR_INSTALL_ONLY exit /b 0", source)
        self.assertIn("if not defined ERPTBR_INTERNAL_CALL", source)
        self.assertIn(
            'for %%I in ("%~dp0..") do set "ERPT_PACKAGE_ROOT=%%~fI\\"', source
        )

    @unittest.skipUnless(os.name == "nt", "Primitivas exclusivas do Windows")
    def test_windows_bootstrap_handle_allows_execution_then_deletes(self) -> None:
        system_root = Path(os.environ["SystemRoot"])
        powershell = (
            system_root
            / "System32"
            / "WindowsPowerShell"
            / "v1.0"
            / "powershell.exe"
        )
        signed_native = system_root / "System32" / "where.exe"
        self.assertTrue(powershell.is_file())
        self.assertTrue(signed_native.is_file())

        with tempfile.TemporaryDirectory() as temp:
            download = Path(temp) / "bootstrap-handle-test.download"
            executable = download.with_suffix(".exe")
            shutil.copy2(signed_native, download)
            environment = os.environ.copy()
            environment["ERPTBR_TEST_DOWNLOAD"] = str(download)
            command = r"""
$ErrorActionPreference='Stop'
Import-Module -Name (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -Force -ErrorAction Stop
Import-Module -Name (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -Force -ErrorAction Stop
$download=$env:ERPTBR_TEST_DOWNLOAD
$hash=(Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash
if([string]::IsNullOrWhiteSpace($hash)){throw 'hash ausente'}
$signature=Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $download
if($signature.Status -ne 'Valid'){throw 'assinatura invalida'}
$path=[IO.Path]::ChangeExtension($download,'.exe')
[IO.File]::Move($download,$path)
$stream=[IO.FileStream]::new($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read,4096,[IO.FileOptions]::DeleteOnClose)
try {
    $process=Start-Process -FilePath $path -ArgumentList @('where.exe') -Wait -PassThru
    if($process.ExitCode -ne 0){throw ('processo retornou '+$process.ExitCode)}
} finally {
    $stream.Dispose()
}
if(Test-Path -LiteralPath $path){throw 'DeleteOnClose nao removeu o scratch'}
"""
            completed = subprocess.run(
                [
                    str(powershell),
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    command,
                ],
                check=False,
                capture_output=True,
                env=environment,
                text=True,
                timeout=30,
            )
            self.assertEqual(
                completed.returncode,
                0,
                msg=f"stdout={completed.stdout}\nstderr={completed.stderr}",
            )
            self.assertFalse(download.exists())
            self.assertFalse(executable.exists())


if __name__ == "__main__":
    unittest.main()
