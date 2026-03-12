#!/usr/bin/env python3
"""
Elden Ring - Dublagem PT-BR Patcher
Aplica a dublagem em português brasileiro diretamente no sd.bdt.
Sem DLL, sem ModEngine — funciona online.
"""
import os
import sys
import struct
import json
import hashlib
import threading
import tempfile
import shutil
import zipfile
import webbrowser
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk
from dataclasses import dataclass, field
from typing import Optional, Callable
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError

# ============================================================
# Config
# ============================================================
PATCHER_VERSION = "0.8.0"
GITHUB_REPO = "lorepamplona/ERPT-BR"
KOFI_URL = "https://ko-fi.com/yelore"
STEAM_APP_ID = 1245620
APP_NAME = "Elden Ring - Dublagem PT-BR"

# ============================================================
# Patching Engine (extracted from elden_ring_sd_tool.py)
# ============================================================

ELDEN_RING_SD_KEY_PEM = """-----BEGIN RSA PUBLIC KEY-----
MIIBCwKCAQEAmYJ/5GJU4boJSvZ81BFOHYTGdBWPHnWYly3yWo01BYjGRnz8NTkz
DHUxsbjIgtG5XqsQfZstZILQ97hgSI5AaAoCGrT8sn0PeXg2i0mKwL21gRjRUdvP
Dp1Y+7hgrGwuTkjycqqsQ/qILm4NvJHvGRd7xLOJ9rs2zwYhceRVrq9XU2AXbdY4
pdCQ3+HuoaFiJ0dW0ly5qdEXjbSv2QEYe36nWCtsd6hEY9LjbBX8D1fK3D2c6C0g
NdHJGH2iEONUN6DMK9t0v2JBnwCOZQ7W+Gt7SpNNrkx8xKEM8gH9na10g9ne11Mi
O1FnLm8i4zOxVdPHQBKICkKcGS1o3C2dfwIEXw/f3w==
-----END RSA PUBLIC KEY-----"""



@dataclass
class AESRange:
    start_offset: int
    end_offset: int


@dataclass
class AESKeyInfo:
    key: bytes
    ranges: list[AESRange] = field(default_factory=list)


@dataclass
class SHAHashInfo:
    hash_bytes: bytes
    ranges: list[AESRange] = field(default_factory=list)


@dataclass
class FileEntry:
    file_name_hash: int
    padded_file_size: int
    unpadded_file_size: int
    file_offset: int
    sha_hash_offset: int
    aes_key_offset: int
    sha_info: Optional[SHAHashInfo] = None
    aes_info: Optional[AESKeyInfo] = None


@dataclass
class Bucket:
    file_entries: list[FileEntry] = field(default_factory=list)


@dataclass
class BHD5:
    magic: bytes = b"BHD5"
    buckets: list[Bucket] = field(default_factory=list)

    def all_entries(self):
        for bucket in self.buckets:
            yield from bucket.file_entries


def read_ranges(data: bytes, offset: int) -> list[AESRange]:
    if offset + 4 > len(data):
        return []
    count = struct.unpack_from("<i", data, offset)[0]
    ranges = []
    pos = offset + 4
    for _ in range(count):
        if pos + 16 > len(data):
            break
        start = struct.unpack_from("<q", data, pos)[0]
        end = struct.unpack_from("<q", data, pos + 8)[0]
        ranges.append(AESRange(start, end))
        pos += 16
    return ranges


def rsa_decrypt_bhd(encrypted: bytes, pem_key: str) -> bytes:
    """Decrypt RSA-encrypted BHD. Mirrors BouncyCastle RsaEngine (UXM/BinderTool)."""
    from Crypto.PublicKey import RSA
    key = RSA.import_key(pem_key)
    n, e = key.n, key.e
    input_block_size = (key.size_in_bits() + 7) // 8   # 256 for 2048-bit
    output_block_size = input_block_size - 1             # 255

    result = bytearray()
    pos = 0
    while pos < len(encrypted):
        block = encrypted[pos:pos + input_block_size]
        if len(block) == 0:
            break
        if len(block) < input_block_size:
            block = block + b'\x00' * (input_block_size - len(block))
        c = int.from_bytes(block, 'big')
        m = pow(c, e, n)
        dec = m.to_bytes(output_block_size, 'big')
        result.extend(dec)
        pos += input_block_size

    return bytes(result)


def parse_bhd5(data: bytes) -> BHD5:
    if data[:4] != b"BHD5":
        raise ValueError(f"Not a BHD5 file: {data[:4]}")

    bhd = BHD5()
    bucket_count = struct.unpack_from("<i", data, 16)[0]
    buckets_offset = struct.unpack_from("<i", data, 20)[0]

    salt_length = struct.unpack_from("<i", data, 24)[0]
    if salt_length > 0 and salt_length < len(data):
        pass  # salt not needed for patching

    pos = buckets_offset
    for _ in range(bucket_count):
        entry_count = struct.unpack_from("<i", data, pos)[0]
        entries_offset = struct.unpack_from("<i", data, pos + 4)[0]
        bucket = Bucket()
        epos = entries_offset
        for _ in range(entry_count):
            if epos + 40 > len(data):
                break
            fhash = struct.unpack_from("<Q", data, epos)[0]
            padded = struct.unpack_from("<i", data, epos + 8)[0]
            unpadded = struct.unpack_from("<i", data, epos + 12)[0]
            foffset = struct.unpack_from("<q", data, epos + 16)[0]
            sha_offset = struct.unpack_from("<q", data, epos + 24)[0]
            aes_offset = struct.unpack_from("<q", data, epos + 32)[0]

            entry = FileEntry(
                file_name_hash=fhash,
                padded_file_size=padded,
                unpadded_file_size=unpadded,
                file_offset=foffset,
                sha_hash_offset=sha_offset,
                aes_key_offset=aes_offset,
            )

            if aes_offset > 0 and aes_offset + 16 <= len(data):
                aes_key = data[aes_offset:aes_offset + 16]
                aes_ranges = read_ranges(data, aes_offset + 16)
                entry.aes_info = AESKeyInfo(aes_key, aes_ranges)

            if sha_offset > 0 and sha_offset + 32 <= len(data):
                sha_hash = data[sha_offset:sha_offset + 32]
                sha_ranges = read_ranges(data, sha_offset + 32)
                entry.sha_info = SHAHashInfo(sha_hash, sha_ranges)

            bucket.file_entries.append(entry)
            epos += 40
        bhd.buckets.append(bucket)
        pos += 8

    return bhd


def hash_path(path: str) -> int:
    h = 0
    normalized = path.replace('\\', '/').strip('/').lower()
    for c in '/' + normalized:
        h = (h * 0x85 + ord(c)) & 0xFFFFFFFFFFFFFFFF
    return h


def encrypt_aes_ecb(data: bytearray, key: bytes, ranges: list[AESRange]) -> bytearray:
    from Crypto.Cipher import AES as _AES
    cipher = _AES.new(key, _AES.MODE_ECB)
    result = bytearray(data)
    for r in ranges:
        start = r.start_offset
        end = min(r.end_offset, len(result))
        if start >= end:
            continue
        chunk = bytes(result[start:end])
        pad_len = (16 - len(chunk) % 16) % 16
        if pad_len:
            chunk += bytes(pad_len)
        enc = cipher.encrypt(chunk)
        result[start:end] = enc[:end - start]
    return result


def fix_wem_for_elden_ring(wem_data: bytes, slot_size: int) -> bytes:
    if len(wem_data) < 12 or wem_data[:4] != b"RIFF" or wem_data[8:12] != b"WAVE":
        return wem_data

    fmt_data = None
    audio_data = None
    pos = 12
    while pos < len(wem_data) - 8:
        cid = wem_data[pos:pos + 4]
        csz = struct.unpack_from("<I", wem_data, pos + 4)[0]
        if csz > len(wem_data):
            break
        if cid == b"fmt ":
            fmt_data = wem_data[pos + 8:pos + 8 + csz]
        elif cid == b"data":
            audio_data = wem_data[pos + 8:pos + 8 + csz]
        pos += 8 + csz
        if csz % 2 == 1:
            pos += 1

    if fmt_data is None or audio_data is None:
        return wem_data

    fmt_chunk_total = 8 + len(fmt_data)
    header_size = 12 + fmt_chunk_total + 8
    data_chunk_content_size = slot_size - header_size
    if data_chunk_content_size < len(audio_data):
        data_chunk_content_size = len(audio_data)

    total_size = header_size + data_chunk_content_size
    riff_size = total_size - 8

    result = bytearray()
    result += b"RIFF"
    result += struct.pack("<I", riff_size)
    result += b"WAVE"
    result += b"fmt "
    result += struct.pack("<I", len(fmt_data))
    result += fmt_data
    result += b"data"
    result += struct.pack("<I", data_chunk_content_size)
    result += audio_data
    result += b"\x00" * (data_chunk_content_size - len(audio_data))

    return bytes(result[:slot_size])


def decrypt_aes_ecb(data: bytearray, key: bytes,
                    ranges: list[AESRange]) -> bytearray:
    """Decrypt AES-ECB ranges in data (inverse of encrypt_aes_ecb)."""
    from Crypto.Cipher import AES as _AES
    cipher = _AES.new(key, _AES.MODE_ECB)
    result = bytearray(data)
    for r in ranges:
        start = r.start_offset
        end = min(r.end_offset, len(result))
        if start >= end:
            continue
        chunk = bytes(result[start:end])
        pad_len = (16 - len(chunk) % 16) % 16
        if pad_len:
            chunk += bytes(pad_len)
        dec = cipher.decrypt(chunk)
        result[start:end] = dec[:end - start]
    return result


# ============================================================
# Steam Detection
# ============================================================

def _get_steam_paths() -> list[str]:
    """Get possible Steam installation paths for the current platform."""
    import platform
    system = platform.system()

    if system == "Windows":
        try:
            import winreg
            for hive in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
                for subkey in [
                    r"SOFTWARE\WOW6432Node\Valve\Steam",
                    r"SOFTWARE\Valve\Steam",
                ]:
                    try:
                        key = winreg.OpenKey(hive, subkey)
                        steam_path = winreg.QueryValueEx(key, "InstallPath")[0]
                        winreg.CloseKey(key)
                        if steam_path:
                            return [steam_path]
                    except (FileNotFoundError, OSError):
                        continue
        except ImportError:
            pass
        # Fallback paths
        return [
            r"C:\Program Files (x86)\Steam",
            r"C:\Program Files\Steam",
        ]

    elif system == "Linux":
        home = os.path.expanduser("~")
        return [
            os.path.join(home, ".steam", "steam"),
            os.path.join(home, ".local", "share", "Steam"),
            os.path.join(home, ".steam", "debian-installation"),
            # Flatpak Steam
            os.path.join(home, ".var", "app", "com.valvesoftware.Steam",
                         ".local", "share", "Steam"),
            # Snap
            os.path.join(home, "snap", "steam", "common", ".steam", "steam"),
        ]

    elif system == "Darwin":  # macOS
        home = os.path.expanduser("~")
        return [
            os.path.join(home, "Library", "Application Support", "Steam"),
        ]

    return []


def _check_game_in_library(steam_path: str) -> Optional[str]:
    """Check if Elden Ring exists in a Steam library path."""
    game_path = os.path.join(steam_path, "steamapps", "common",
                             "ELDEN RING", "Game")
    if os.path.isfile(os.path.join(game_path, "sd", "sd.bhd")):
        return game_path
    return None


def find_elden_ring_steam() -> Optional[str]:
    """Find Elden Ring install path via Steam (Windows, Linux, macOS)."""
    try:
        import re
        for steam_path in _get_steam_paths():
            if not os.path.isdir(steam_path):
                continue

            # Check default library
            result = _check_game_in_library(steam_path)
            if result:
                return result

            # Parse libraryfolders.vdf for additional libraries
            vdf_path = os.path.join(steam_path, "steamapps",
                                    "libraryfolders.vdf")
            if os.path.isfile(vdf_path):
                with open(vdf_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                paths = re.findall(r'"path"\s+"([^"]+)"', content)
                for lib_path in paths:
                    lib_path = lib_path.replace("\\\\", "\\")
                    result = _check_game_in_library(lib_path)
                    if result:
                        return result

    except Exception:
        pass
    return None


def is_game_running() -> bool:
    """Check if Elden Ring is running (cross-platform)."""
    import platform
    try:
        if platform.system() == "Windows":
            result = subprocess.run(
                ['tasklist', '/FI', 'IMAGENAME eq eldenring.exe'],
                capture_output=True, text=True, timeout=5
            )
            return 'eldenring.exe' in result.stdout.lower()
        else:
            # Linux/macOS: check via pgrep
            result = subprocess.run(
                ['pgrep', '-fi', 'eldenring'],
                capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
    except Exception:
        return False


# ============================================================
# Download Manager
# ============================================================

def get_latest_release(repo: str) -> Optional[dict]:
    """Get latest release info from GitHub."""
    headers = {"User-Agent": "EldenRingPTBR-Patcher",
               "Accept": "application/vnd.github+json"}
    # Try /latest first, fall back to /releases list
    for suffix in ("/releases/latest", "/releases"):
        try:
            url = f"https://api.github.com/repos/{repo}{suffix}"
            req = Request(url, headers=headers)
            with urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
                if isinstance(data, list):
                    return data[0] if data else None
                return data
        except Exception:
            continue
    return None


def download_file(url: str, dest: str, callback: Optional[Callable] = None) -> bool:
    """Download a file with progress callback(downloaded, total)."""
    try:
        req = Request(url, headers={"User-Agent": "EldenRingPTBR-Patcher"})
        with urlopen(req, timeout=30) as resp:
            total = int(resp.headers.get('Content-Length', 0))
            downloaded = 0
            with open(dest, 'wb') as f:
                while True:
                    chunk = resp.read(1024 * 256)  # 256 KB chunks
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if callback:
                        callback(downloaded, total)
        return True
    except Exception:
        return False


# ============================================================
# Patch Engine
# ============================================================

class PatchEngine:
    def __init__(self, game_dir: str, log_callback: Callable):
        self.game_dir = game_dir
        self.sd_dir = os.path.join(game_dir, "sd")
        self.log = log_callback
        self.entry_by_hash: dict[int, tuple[FileEntry, str]] = {}

    def load_archives(self) -> int:
        """Load BHD archives, return total entry count."""
        for bhd_file in ['sd.bhd', 'sd_dlc02.bhd']:
            bhd_path = os.path.join(self.sd_dir, bhd_file)
            if not os.path.exists(bhd_path):
                continue
            bdt_path = bhd_path.replace('.bhd', '.bdt')
            if not os.path.exists(bdt_path):
                continue

            self.log(f"Decriptando {bhd_file}...")
            with open(bhd_path, 'rb') as f:
                encrypted = f.read()

            if encrypted[:4] == b"BHD5":
                decrypted = encrypted
            else:
                decrypted = rsa_decrypt_bhd(encrypted, ELDEN_RING_SD_KEY_PEM)

            bhd = parse_bhd5(decrypted)
            count = 0
            for bucket in bhd.buckets:
                for entry in bucket.file_entries:
                    self.entry_by_hash[entry.file_name_hash] = (entry, bdt_path)
                    count += 1
            self.log(f"  {bhd_file}: {count} entradas")

        self.log(f"  Total: {len(self.entry_by_hash)} entradas")
        return len(self.entry_by_hash)

    def scan_replacements(self, wem_dir: str) -> dict[int, str]:
        """Find .wem files that match BHD entries. Returns hash -> filepath."""
        replacements = {}
        for root, dirs, files in os.walk(wem_dir):
            for fname in files:
                if not fname.endswith('.wem'):
                    continue
                full_path = os.path.join(root, fname)
                rel_path = os.path.relpath(full_path, wem_dir).replace(os.sep, '/')

                # Try path hash
                h = hash_path(rel_path)
                if h in self.entry_by_hash:
                    replacements[h] = full_path
                    continue

                # Try with enus/ prefix
                h = hash_path(f"enus/{rel_path}")
                if h in self.entry_by_hash:
                    replacements[h] = full_path
                    continue

                # Try Wwise ID pattern: enus/wem/NN/ID.wem
                stem = Path(fname).stem
                if stem.isdigit():
                    prefix = stem[:2]
                    wem_path = f"enus/wem/{prefix}/{stem}.wem"
                    h = hash_path(wem_path)
                    if h in self.entry_by_hash:
                        replacements[h] = full_path
                        continue

        return replacements

    def create_backup(self) -> bool:
        """Backup sd.bdt -> sd.bdt.original."""
        bdt_path = os.path.join(self.sd_dir, "sd.bdt")
        backup_path = bdt_path + ".original"
        if os.path.exists(backup_path):
            self.log("Backup já existe (sd.bdt.original)")
            return True

        self.log("Criando backup do sd.bdt (pode demorar)...")
        try:
            shutil.copy2(bdt_path, backup_path)
            self.log("Backup criado!")
            return True
        except Exception as ex:
            self.log(f"Erro ao criar backup: {ex}")
            return False

    def restore_backup(self) -> bool:
        """Restore sd.bdt.original -> sd.bdt."""
        bdt_path = os.path.join(self.sd_dir, "sd.bdt")
        backup_path = bdt_path + ".original"
        if not os.path.exists(backup_path):
            self.log("Backup não encontrado (sd.bdt.original)")
            return False

        self.log("Restaurando sd.bdt original...")
        try:
            shutil.copy2(backup_path, bdt_path)
            self.log("Restaurado com sucesso!")
            return True
        except Exception as ex:
            self.log(f"Erro ao restaurar: {ex}")
            return False

    def apply_patches(self, replacements: dict[int, str],
                      progress_callback: Optional[Callable] = None) -> tuple[int, int]:
        """Apply patches to BDT. Returns (success, failed)."""
        success = 0
        failed = 0
        total = len(replacements)

        # Group by BDT file
        by_bdt: dict[str, list[tuple[int, str]]] = {}
        for h, path in replacements.items():
            entry, bdt_path = self.entry_by_hash[h]
            if bdt_path not in by_bdt:
                by_bdt[bdt_path] = []
            by_bdt[bdt_path].append((h, path))

        for bdt_path, items in by_bdt.items():
            self.log(f"Patcheando {os.path.basename(bdt_path)}...")
            with open(bdt_path, 'r+b') as bdt_f:
                for h, wem_path in items:
                    entry, _ = self.entry_by_hash[h]
                    try:
                        with open(wem_path, 'rb') as f:
                            wem_data = f.read()

                        if len(wem_data) > entry.padded_file_size:
                            self.log(f"  SKIP: {os.path.basename(wem_path)} "
                                     f"muito grande ({len(wem_data)} > {entry.padded_file_size})")
                            failed += 1
                            continue

                        # Fix format for Elden Ring
                        wem_data = fix_wem_for_elden_ring(wem_data, entry.padded_file_size)

                        # Pad to padded size
                        padded = bytearray(wem_data)
                        if len(padded) < entry.padded_file_size:
                            padded += b"\x00" * (entry.padded_file_size - len(padded))

                        # Encrypt
                        if entry.aes_info and entry.aes_info.key and entry.aes_info.ranges:
                            padded = encrypt_aes_ecb(padded, entry.aes_info.key,
                                                     entry.aes_info.ranges)

                        # Write
                        bdt_f.seek(entry.file_offset)
                        bdt_f.write(padded)
                        success += 1

                    except Exception as ex:
                        self.log(f"  ERRO: {os.path.basename(wem_path)}: {ex}")
                        failed += 1

                    if progress_callback:
                        progress_callback(success + failed, total)

        return success, failed



# ============================================================
# GUI - Wizard Style Installer (CustomTkinter)
# ============================================================

# Colors
BG_DARK = "#0a0a0f"
BG_CARD = "#141420"
BG_CARD_HOVER = "#1a1a2e"
BG_SIDEBAR = "#0f0f1a"
ACCENT_GOLD = "#c8aa6e"
ACCENT_GOLD_HOVER = "#e0c478"
ACCENT_GOLD_DIM = "#785a28"
TEXT_PRIMARY = "#f0e6d2"
TEXT_SECONDARY = "#a09b8c"
TEXT_MUTED = "#5b5a56"
SUCCESS_GREEN = "#0acf83"
ERROR_RED = "#e84057"
PROGRESS_BG = "#1e1e30"

# Step indicators
STEP_WELCOME = 0
STEP_PATH = 1
STEP_INSTALLING = 2
STEP_DONE = 3


class PatcherApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self.title(APP_NAME)
        self.geometry("750x540")
        self.resizable(False, False)
        self.configure(fg_color=BG_DARK)

        # Set window icon
        base = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
        icon_path = os.path.join(base, "patcher.ico")
        if not os.path.isfile(icon_path):
            icon_path = os.path.join(os.path.dirname(sys.executable), "patcher.ico")
        if os.path.isfile(icon_path):
            try:
                self.iconbitmap(icon_path)
            except Exception:
                pass  # iconbitmap may fail on Linux/macOS

        self._current_step = STEP_WELCOME
        self._pages: dict[int, ctk.CTkFrame] = {}
        self._install_success_count = 0
        self._install_fail_count = 0

        self._build_layout()
        self._build_welcome_page()
        self._build_path_page()
        self._build_installing_page()
        self._build_done_page()
        self._show_page(STEP_WELCOME)

        # Check for updates in background on startup
        threading.Thread(target=self._check_update_silent, daemon=True).start()

    # ── Layout ──

    def _build_layout(self):
        # Sidebar (left) - step indicator + branding
        self.sidebar = ctk.CTkFrame(self, fg_color=BG_SIDEBAR, width=220, corner_radius=0)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        # Sidebar branding
        ctk.CTkLabel(
            self.sidebar, text="ELDEN RING",
            font=ctk.CTkFont("Segoe UI", 11, "bold"),
            text_color=TEXT_MUTED
        ).pack(pady=(30, 0))
        ctk.CTkLabel(
            self.sidebar, text="Dublagem PT-BR",
            font=ctk.CTkFont("Segoe UI", 20, "bold"),
            text_color=ACCENT_GOLD
        ).pack(pady=(2, 5))
        ctk.CTkLabel(
            self.sidebar, text=f"v{PATCHER_VERSION}",
            font=ctk.CTkFont("Segoe UI", 11),
            text_color=TEXT_MUTED
        ).pack()

        # Step indicators
        steps_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        steps_frame.pack(expand=True, fill="both", padx=20, pady=30)

        self._step_labels = []
        step_names = ["Bem-vindo", "Caminho do jogo", "Instalando...", "Concluido"]
        for i, name in enumerate(step_names):
            row = ctk.CTkFrame(steps_frame, fg_color="transparent")
            row.pack(fill="x", pady=6)

            dot = ctk.CTkLabel(
                row, text="●" if i == 0 else "○",
                font=ctk.CTkFont("Segoe UI", 12),
                text_color=ACCENT_GOLD if i == 0 else TEXT_MUTED,
                width=20
            )
            dot.pack(side="left")

            label = ctk.CTkLabel(
                row, text=name,
                font=ctk.CTkFont("Segoe UI", 12, "bold" if i == 0 else "normal"),
                text_color=TEXT_PRIMARY if i == 0 else TEXT_MUTED,
                anchor="w"
            )
            label.pack(side="left", padx=(6, 0))
            self._step_labels.append((dot, label))

        # Sidebar footer
        sidebar_footer = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        sidebar_footer.pack(side="bottom", fill="x", padx=15, pady=15)
        ctk.CTkLabel(
            sidebar_footer,
            text="Funciona online\nSem DLL, sem ModEngine",
            font=ctk.CTkFont("Segoe UI", 10),
            text_color=TEXT_MUTED, justify="center"
        ).pack()

        # Main area (right)
        self.main_area = ctk.CTkFrame(self, fg_color=BG_DARK, corner_radius=0)
        self.main_area.pack(side="right", fill="both", expand=True)

        # Bottom bar with nav buttons (pack BEFORE content so it reserves space)
        self.bottom_bar = ctk.CTkFrame(self.main_area, fg_color=BG_CARD, corner_radius=0, height=60)
        self.bottom_bar.pack(fill="x", side="bottom")

        # Content container (pages go here)
        self.content = ctk.CTkFrame(self.main_area, fg_color="transparent")
        self.content.pack(fill="both", expand=True, padx=35, pady=(20, 10))
        self.bottom_bar.pack_propagate(False)

        bottom_inner = ctk.CTkFrame(self.bottom_bar, fg_color="transparent")
        bottom_inner.pack(fill="both", expand=True, padx=25)

        self.btn_back = ctk.CTkButton(
            bottom_inner, text="< Voltar",
            font=ctk.CTkFont("Segoe UI", 12),
            fg_color="transparent", hover_color=BG_CARD_HOVER,
            text_color=TEXT_SECONDARY, width=100, height=36,
            command=self._go_back
        )
        self.btn_back.pack(side="left", pady=12)

        self.btn_next = ctk.CTkButton(
            bottom_inner, text="Proximo >",
            font=ctk.CTkFont("Segoe UI", 13, "bold"),
            fg_color=ACCENT_GOLD, hover_color=ACCENT_GOLD_HOVER,
            text_color="#0a0a0f", width=140, height=38,
            corner_radius=8, command=self._go_next
        )
        self.btn_next.pack(side="right", pady=12)

        self.btn_cancel = ctk.CTkButton(
            bottom_inner, text="Cancelar",
            font=ctk.CTkFont("Segoe UI", 12),
            fg_color="transparent", hover_color=BG_CARD_HOVER,
            text_color=TEXT_MUTED, width=90, height=36,
            command=self.destroy
        )
        self.btn_cancel.pack(side="right", padx=(0, 8), pady=12)

    # ── Pages ──

    def _build_welcome_page(self):
        page = ctk.CTkFrame(self.content, fg_color="transparent")
        self._pages[STEP_WELCOME] = page

        ctk.CTkLabel(
            page, text="Bem-vindo ao Assistente\nde Instalacao",
            font=ctk.CTkFont("Segoe UI", 24, "bold"),
            text_color=TEXT_PRIMARY, justify="left", anchor="w"
        ).pack(anchor="w", pady=(10, 10))

        ctk.CTkLabel(
            page,
            text=(
                "O Assistente de Instalacao ira aplicar a dublagem em\n"
                "portugues brasileiro no seu Elden Ring.\n\n"
                "O que sera feito:\n"
            ),
            font=ctk.CTkFont("Segoe UI", 13),
            text_color=TEXT_SECONDARY, justify="left", anchor="w"
        ).pack(anchor="w")

        # Feature list
        features = [
            ("Mais de 9.000 dialogos dublados em PT-BR", SUCCESS_GREEN),
            ("Backup automatico do arquivo original", SUCCESS_GREEN),
            ("Funciona online - sem risco de ban", SUCCESS_GREEN),
            ("Restauracao com um clique se quiser voltar", SUCCESS_GREEN),
        ]
        for text, color in features:
            row = ctk.CTkFrame(page, fg_color="transparent")
            row.pack(anchor="w", pady=2)
            ctk.CTkLabel(
                row, text="  ✓  ",
                font=ctk.CTkFont("Segoe UI", 13),
                text_color=color
            ).pack(side="left")
            ctk.CTkLabel(
                row, text=text,
                font=ctk.CTkFont("Segoe UI", 13),
                text_color=TEXT_PRIMARY
            ).pack(side="left")

        ctk.CTkLabel(
            page,
            text='\nClique em "Proximo" para continuar.',
            font=ctk.CTkFont("Segoe UI", 12),
            text_color=TEXT_MUTED, anchor="w"
        ).pack(anchor="w", pady=(15, 0))

    def _build_path_page(self):
        page = ctk.CTkFrame(self.content, fg_color="transparent")
        self._pages[STEP_PATH] = page

        ctk.CTkLabel(
            page, text="Caminho do Elden Ring",
            font=ctk.CTkFont("Segoe UI", 22, "bold"),
            text_color=TEXT_PRIMARY, anchor="w"
        ).pack(anchor="w", pady=(20, 8))

        ctk.CTkLabel(
            page,
            text="Selecione a pasta Game do Elden Ring onde a\ndublagem sera instalada.",
            font=ctk.CTkFont("Segoe UI", 13),
            text_color=TEXT_SECONDARY, justify="left", anchor="w"
        ).pack(anchor="w", pady=(0, 15))

        # Path card
        path_card = ctk.CTkFrame(page, fg_color=BG_CARD, corner_radius=12)
        path_card.pack(fill="x", pady=(0, 10))

        path_inner = ctk.CTkFrame(path_card, fg_color="transparent")
        path_inner.pack(fill="x", padx=20, pady=18)

        ctk.CTkLabel(
            path_inner, text="Pasta do jogo:",
            font=ctk.CTkFont("Segoe UI", 12, "bold"),
            text_color=TEXT_PRIMARY, anchor="w"
        ).pack(anchor="w", pady=(0, 6))

        path_row = ctk.CTkFrame(path_inner, fg_color="transparent")
        path_row.pack(fill="x")

        self.path_var = tk.StringVar()
        self.path_entry = ctk.CTkEntry(
            path_row, textvariable=self.path_var,
            font=ctk.CTkFont("Segoe UI", 12),
            fg_color="#0d0d18", border_color=ACCENT_GOLD_DIM,
            text_color=TEXT_PRIMARY, height=38
        )
        self.path_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))

        ctk.CTkButton(
            path_row, text="Procurar...",
            font=ctk.CTkFont("Segoe UI", 12),
            fg_color=ACCENT_GOLD_DIM, hover_color=ACCENT_GOLD,
            text_color=TEXT_PRIMARY, width=110, height=38,
            corner_radius=8, command=self._browse
        ).pack(side="right")

        self.detect_label = ctk.CTkLabel(
            path_inner, text="",
            font=ctk.CTkFont("Segoe UI", 11),
            text_color=TEXT_SECONDARY, anchor="w"
        )
        self.detect_label.pack(anchor="w", pady=(8, 0))

        # Restore option
        restore_card = ctk.CTkFrame(page, fg_color=BG_CARD, corner_radius=12)
        restore_card.pack(fill="x", pady=(8, 0))

        restore_inner = ctk.CTkFrame(restore_card, fg_color="transparent")
        restore_inner.pack(fill="x", padx=20, pady=14)

        ctk.CTkLabel(
            restore_inner,
            text="Ja instalou antes e quer restaurar o original?",
            font=ctk.CTkFont("Segoe UI", 12),
            text_color=TEXT_SECONDARY, anchor="w"
        ).pack(side="left")

        self.restore_btn = ctk.CTkButton(
            restore_inner, text="Restaurar Original",
            font=ctk.CTkFont("Segoe UI", 11),
            fg_color="transparent", hover_color=BG_CARD_HOVER,
            text_color=ERROR_RED, width=140, height=30,
            border_width=1, border_color=TEXT_MUTED,
            corner_radius=6, command=self._start_restore
        )
        self.restore_btn.pack(side="right")

    def _build_installing_page(self):
        page = ctk.CTkFrame(self.content, fg_color="transparent")
        self._pages[STEP_INSTALLING] = page

        ctk.CTkLabel(
            page, text="Instalando dublagem...",
            font=ctk.CTkFont("Segoe UI", 22, "bold"),
            text_color=TEXT_PRIMARY, anchor="w"
        ).pack(anchor="w", pady=(20, 8))

        self.install_status_label = ctk.CTkLabel(
            page, text="Preparando...",
            font=ctk.CTkFont("Segoe UI", 13),
            text_color=TEXT_SECONDARY, anchor="w"
        )
        self.install_status_label.pack(anchor="w", pady=(0, 20))

        # Progress card
        prog_card = ctk.CTkFrame(page, fg_color=BG_CARD, corner_radius=12)
        prog_card.pack(fill="x", pady=(0, 12))

        prog_inner = ctk.CTkFrame(prog_card, fg_color="transparent")
        prog_inner.pack(fill="x", padx=20, pady=20)

        self.progress = ctk.CTkProgressBar(
            prog_inner, fg_color=PROGRESS_BG,
            progress_color=ACCENT_GOLD, height=12, corner_radius=6
        )
        self.progress.pack(fill="x", pady=(0, 8))
        self.progress.set(0)

        self.progress_label = ctk.CTkLabel(
            prog_inner, text="0%",
            font=ctk.CTkFont("Segoe UI", 12),
            text_color=TEXT_SECONDARY, anchor="w"
        )
        self.progress_label.pack(anchor="w")

        # Log area
        ctk.CTkLabel(
            page, text="Log:",
            font=ctk.CTkFont("Segoe UI", 11),
            text_color=TEXT_MUTED, anchor="w"
        ).pack(anchor="w", pady=(5, 3))

        self.log_text = ctk.CTkTextbox(
            page, fg_color="#08080f",
            text_color="#9090a0", font=ctk.CTkFont("Consolas", 10),
            corner_radius=8, border_width=0, height=130
        )
        self.log_text.pack(fill="both", expand=True)
        self.log_text.configure(state="disabled")

    def _build_done_page(self):
        page = ctk.CTkFrame(self.content, fg_color="transparent")
        self._pages[STEP_DONE] = page

        # Centered content
        center = ctk.CTkFrame(page, fg_color="transparent")
        center.pack(expand=True)

        self.done_icon_label = ctk.CTkLabel(
            center, text="✓",
            font=ctk.CTkFont("Segoe UI", 60, "bold"),
            text_color=SUCCESS_GREEN
        )
        self.done_icon_label.pack(pady=(0, 10))

        self.done_title_label = ctk.CTkLabel(
            center, text="Dublagem instalada\ncom sucesso!",
            font=ctk.CTkFont("Segoe UI", 24, "bold"),
            text_color=TEXT_PRIMARY, justify="center"
        )
        self.done_title_label.pack(pady=(0, 8))

        self.done_detail_label = ctk.CTkLabel(
            center, text="",
            font=ctk.CTkFont("Segoe UI", 13),
            text_color=TEXT_SECONDARY, justify="center"
        )
        self.done_detail_label.pack(pady=(0, 20))

        ctk.CTkLabel(
            center,
            text="Inicie o Elden Ring normalmente e aproveite\na dublagem em portugues!",
            font=ctk.CTkFont("Segoe UI", 13),
            text_color=TEXT_SECONDARY, justify="center"
        ).pack(pady=(0, 20))

        # Ko-fi support button
        ctk.CTkButton(
            center, text="Apoie o projeto no Ko-fi",
            font=ctk.CTkFont("Segoe UI", 14, "bold"),
            fg_color="#ff5e5b", hover_color="#ff7a78",
            text_color="#ffffff", height=44, width=250,
            corner_radius=10,
            command=lambda: webbrowser.open(KOFI_URL)
        ).pack(pady=(0, 10))

        ctk.CTkLabel(
            center,
            text="Sua contribuicao ajuda a manter o projeto ativo!",
            font=ctk.CTkFont("Segoe UI", 11),
            text_color=TEXT_MUTED, justify="center"
        ).pack()

    # ── Page Navigation ──

    def _show_page(self, step: int):
        # Hide all pages
        for page in self._pages.values():
            page.pack_forget()

        # Show target page
        self._pages[step].pack(fill="both", expand=True)
        self._current_step = step

        # Update step indicators
        for i, (dot, label) in enumerate(self._step_labels):
            if i < step:
                dot.configure(text="✓", text_color=SUCCESS_GREEN)
                label.configure(text_color=TEXT_MUTED,
                                font=ctk.CTkFont("Segoe UI", 12))
            elif i == step:
                dot.configure(text="●", text_color=ACCENT_GOLD)
                label.configure(text_color=TEXT_PRIMARY,
                                font=ctk.CTkFont("Segoe UI", 12, "bold"))
            else:
                dot.configure(text="○", text_color=TEXT_MUTED)
                label.configure(text_color=TEXT_MUTED,
                                font=ctk.CTkFont("Segoe UI", 12))

        # Update nav buttons
        if step == STEP_WELCOME:
            self.btn_back.configure(state="disabled", text_color=TEXT_MUTED)
            self.btn_next.configure(text="Proximo >", state="normal",
                                    fg_color=ACCENT_GOLD, command=self._go_next)
            self.btn_cancel.pack(side="right", padx=(0, 8), pady=12)
        elif step == STEP_PATH:
            self.btn_back.configure(state="normal", text_color=TEXT_SECONDARY,
                                    command=self._go_back)
            self.btn_next.configure(text="Instalar", state="normal",
                                    fg_color=ACCENT_GOLD, command=self._go_next)
            self.btn_cancel.pack(side="right", padx=(0, 8), pady=12)
            self._auto_detect()
        elif step == STEP_INSTALLING:
            self.btn_back.configure(state="disabled", text_color=TEXT_MUTED)
            self.btn_next.configure(text="Aguarde...", state="disabled",
                                    fg_color=ACCENT_GOLD_DIM, command=self._go_next)
            self.btn_cancel.pack_forget()
        elif step == STEP_DONE:
            self.btn_back.pack_forget()
            self.btn_next.configure(text="Fechar", state="normal",
                                    fg_color=ACCENT_GOLD, command=self.destroy)
            self.btn_cancel.pack_forget()

    def _find_movie_dirs(self) -> dict[str, str | None]:
        """Check if movie/ and movie_dlc/ folders exist next to the exe/script."""
        found = {}
        exe_dir = os.path.dirname(sys.executable)
        script_dir = os.path.dirname(os.path.abspath(__file__))
        for folder_name in ("movie", "movie_dlc"):
            found[folder_name] = None
            for base in (exe_dir, script_dir):
                candidate = os.path.join(base, folder_name)
                if os.path.isdir(candidate):
                    bk2 = [f for f in os.listdir(candidate) if f.endswith('.bk2')]
                    if bk2:
                        found[folder_name] = candidate
                        break
        return found

    def _go_next(self):
        if self._current_step == STEP_WELCOME:
            self._show_page(STEP_PATH)
        elif self._current_step == STEP_PATH:
            if self._validate():
                # Check for movie folders before proceeding
                movies = self._find_movie_dirs()
                missing = [k for k, v in movies.items() if v is None]
                if missing:
                    msg = (
                        "As seguintes pastas de cutscenes nao foram encontradas "
                        "ao lado do instalador:\n\n"
                    )
                    for m in missing:
                        msg += f"  - {m}/\n"
                    msg += (
                        "\nAs cutscenes (cinematicas) do jogo NAO serao "
                        "traduzidas.\n\n"
                        "Para incluir as cutscenes, baixe o arquivo opcional "
                        "no Nexus Mods e extraia na mesma pasta do instalador.\n\n"
                        "Deseja continuar mesmo assim?"
                    )
                    if not messagebox.askyesno("Cutscenes nao encontradas", msg):
                        return
                self._show_page(STEP_INSTALLING)
                threading.Thread(target=self._install_worker, daemon=True).start()

    def _go_back(self):
        if self._current_step == STEP_PATH:
            self._show_page(STEP_WELCOME)
        elif self._current_step == STEP_INSTALLING:
            self._show_page(STEP_PATH)

    # ── Helpers ──

    def _log(self, msg: str):
        def _append():
            self.log_text.configure(state="normal")
            self.log_text.insert("end", msg + "\n")
            self.log_text.see("end")
            self.log_text.configure(state="disabled")
        self.after(0, _append)

    def _set_status(self, text: str):
        self.after(0, lambda: self.install_status_label.configure(text=text))

    def _set_progress(self, value: float, text: str = ""):
        def _update():
            self.progress.set(value / 100.0)
            self.progress_label.configure(text=text)
        self.after(0, _update)

    def _auto_detect(self):
        path = find_elden_ring_steam()
        if path:
            self.path_var.set(path)
            self.detect_label.configure(
                text="Detectado automaticamente via Steam",
                text_color=SUCCESS_GREEN)
        else:
            self.detect_label.configure(
                text="Nao detectado. Selecione manualmente.",
                text_color=ERROR_RED)

    def _browse(self):
        path = filedialog.askdirectory(title="Selecione a pasta Game do Elden Ring")
        if path:
            self.path_var.set(path)
            if os.path.isfile(os.path.join(path, "sd", "sd.bhd")):
                self.detect_label.configure(
                    text="Pasta valida!", text_color=SUCCESS_GREEN)
            else:
                self.detect_label.configure(
                    text="sd/sd.bhd nao encontrado nesta pasta",
                    text_color=ERROR_RED)

    def _validate(self) -> bool:
        path = self.path_var.get()
        if not path:
            messagebox.showerror("Erro", "Selecione a pasta do Elden Ring.")
            return False
        if not os.path.isfile(os.path.join(path, "sd", "sd.bhd")):
            messagebox.showerror("Erro",
                                 "sd/sd.bhd nao encontrado.\n"
                                 "Selecione a pasta Game do Elden Ring.")
            return False
        if is_game_running():
            messagebox.showerror("Erro",
                                 "Elden Ring esta rodando.\n"
                                 "Feche o jogo antes de aplicar o patch.")
            return False
        return True

    # ── Install Worker ──

    def _install_worker(self):
        try:
            game_dir = self.path_var.get()
            engine = PatchEngine(game_dir, self._log)

            self._set_status("Carregando arquivos do jogo...")
            self._set_progress(0, "Carregando BHD...")
            engine.load_archives()

            self._set_status("Procurando dados de patch...")
            patch_dir = self._get_or_download_patches()
            if not patch_dir:
                self._set_status("Erro ao obter dados de patch")
                self.after(0, self._show_install_error)
                return

            self._set_status("Procurando arquivos de audio...")
            self._set_progress(0, "Escaneando...")
            replacements = engine.scan_replacements(patch_dir)
            self._log(f"Encontrados {len(replacements)} arquivos para substituir")

            if not replacements:
                self._set_status("Nenhum arquivo de audio encontrado!")
                self.after(0, self._show_install_error)
                return

            self._set_status("Criando backup do sd.bdt...")
            self._set_progress(0, "Backup...")
            if not engine.create_backup():
                self._set_status("Erro ao criar backup!")
                return

            self._set_status("Aplicando dublagem...")

            def on_progress(done, total_):
                pct = (done / total_) * 100
                self._set_progress(pct, f"{done}/{total_} ({pct:.0f}%)")

            success, failed = engine.apply_patches(replacements, on_progress)
            self._install_success_count = success
            self._install_fail_count = failed

            self._set_progress(100, "100%")
            self._log(f"\nPronto! {success} arquivos aplicados.")
            if failed > 0:
                self._log(f"  {failed} erros (veja log acima)")

            # Copy movie files if present
            movies_copied = self._install_movies(game_dir)

            # Move to done page
            def _go_done():
                detail = f"{success} arquivos dublados aplicados com sucesso."
                if failed > 0:
                    detail += f"\n{failed} arquivos com erro."
                if text_patched:
                    detail += "\nCreditos de dublagem adicionados ao menu."
                if movies_copied > 0:
                    detail += f"\n{movies_copied} cutscenes dubladas instaladas."
                self.done_detail_label.configure(text=detail)
                self._show_page(STEP_DONE)
                webbrowser.open(KOFI_URL)
            self.after(500, _go_done)

        except Exception as ex:
            self._set_status(f"Erro: {ex}")
            self._log(f"\nERRO: {ex}")
            self.after(0, self._show_install_error)

    def _get_or_download_patches(self) -> Optional[str]:
        """Get patch data directory. First check local, then download."""
        local_paths = [
            os.path.join(os.path.dirname(sys.executable), "patch_data"),
            os.path.join(os.path.dirname(__file__), "patch_data"),
            os.path.join(os.path.expanduser("~"), ".elden_ring_ptbr", "patch_data"),
        ]
        for p in local_paths:
            if os.path.isdir(p):
                wem_count = sum(1 for _, _, files in os.walk(p)
                                for f in files if f.endswith('.wem'))
                if wem_count > 100:
                    self._log(f"Usando dados locais: {p} ({wem_count} arquivos)")
                    return p

        self._log("Dados locais nao encontrados. Baixando do servidor...")
        self._set_status("Baixando dados de dublagem...")

        release = get_latest_release(GITHUB_REPO)
        if not release:
            self._log("Erro: nao foi possivel conectar ao servidor.")
            return None

        zip_url = None
        for asset in release.get('assets', []):
            if 'patch_data' in asset['name'] and asset['name'].endswith('.zip'):
                zip_url = asset['browser_download_url']
                break

        if not zip_url:
            self._log("Erro: arquivo de patch nao encontrado no release.")
            return None

        cache_dir = os.path.join(os.path.expanduser("~"), ".elden_ring_ptbr")
        os.makedirs(cache_dir, exist_ok=True)
        zip_path = os.path.join(cache_dir, "patch_data.zip")

        def on_dl_progress(downloaded, total):
            if total > 0:
                pct = (downloaded / total) * 100
                mb_done = downloaded / (1024 * 1024)
                mb_total = total / (1024 * 1024)
                self._set_progress(pct, f"Baixando: {mb_done:.0f}/{mb_total:.0f} MB")

        self._log(f"Baixando: {zip_url}")
        if not download_file(zip_url, zip_path, on_dl_progress):
            self._log("Erro no download!")
            return None

        self._set_status("Extraindo arquivos...")
        self._set_progress(0, "Extraindo...")
        extract_dir = os.path.join(cache_dir, "patch_data")
        if os.path.exists(extract_dir):
            shutil.rmtree(extract_dir)

        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(extract_dir)

        self._log(f"Extraido para: {extract_dir}")
        return extract_dir

    def _install_movies(self, game_dir: str) -> int:
        """Copy dubbed movie/movie_dlc .bk2 files to game folder with backup."""
        copied = 0
        movies = self._find_movie_dirs()

        for folder_name, src in movies.items():
            if not src:
                continue

            dest = os.path.join(game_dir, folder_name)
            if not os.path.isdir(dest):
                continue

            bk2_files = [f for f in os.listdir(src) if f.endswith('.bk2')]
            if not bk2_files:
                continue

            self._log(f"\nInstalando cutscenes: {folder_name}/")
            self._set_status(f"Copiando cutscenes ({folder_name})...")

            for fname in bk2_files:
                src_file = os.path.join(src, fname)
                dest_file = os.path.join(dest, fname)
                backup_file = dest_file + ".original"

                # Backup original if not already backed up
                if os.path.isfile(dest_file) and not os.path.isfile(backup_file):
                    self._log(f"  Backup: {fname} -> {fname}.original")
                    shutil.copy2(dest_file, backup_file)

                self._log(f"  Copiando: {fname} ({os.path.getsize(src_file)/(1024*1024):.0f} MB)")
                shutil.copy2(src_file, dest_file)
                copied += 1

        if copied > 0:
            self._log(f"{copied} cutscenes instaladas com sucesso.")
        return copied

    def _show_install_error(self):
        """Show error state on install page: enable Back, show Retry."""
        self.btn_back.configure(
            state="normal", text_color=TEXT_SECONDARY,
            command=lambda: self._show_page(STEP_PATH))
        self.btn_next.configure(
            text="Tentar novamente", state="normal",
            fg_color=ACCENT_GOLD, command=self._retry_install)

    def _retry_install(self):
        """Reset install page and retry."""
        self.progress.set(0)
        self.progress_label.configure(text="0%")
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")
        self.install_status_label.configure(text="Preparando...")
        self.btn_back.configure(state="disabled", text_color=TEXT_MUTED)
        self.btn_next.configure(text="Aguarde...", state="disabled",
                                fg_color=ACCENT_GOLD_DIM)
        threading.Thread(target=self._install_worker, daemon=True).start()

    # ── Restore ──

    def _start_restore(self):
        if not self._validate():
            return
        self.restore_btn.configure(state="disabled")
        threading.Thread(target=self._restore_worker, daemon=True).start()

    def _restore_worker(self):
        try:
            game_dir = self.path_var.get()
            engine = PatchEngine(game_dir, lambda msg: None)

            restored_bdt = engine.restore_backup()

            # Restore movie backups too
            movies_restored = 0
            for folder_name in ("movie", "movie_dlc"):
                folder = os.path.join(game_dir, folder_name)
                if not os.path.isdir(folder):
                    continue
                for fname in os.listdir(folder):
                    if fname.endswith('.bk2.original'):
                        original = os.path.join(folder, fname)
                        target = os.path.join(folder, fname[:-9])  # remove .original
                        shutil.copy2(original, target)
                        os.remove(original)
                        movies_restored += 1

            if restored_bdt or text_restored or movies_restored > 0:
                msg = ""
                if restored_bdt:
                    msg += "sd.bdt original restaurado com sucesso!"
                if text_restored:
                    msg += "\nTexto do menu restaurado."
                if movies_restored > 0:
                    msg += f"\n{movies_restored} cutscenes originais restauradas."
                self.after(0, lambda: messagebox.showinfo("Sucesso", msg.strip()))
            else:
                self.after(0, lambda: messagebox.showerror(
                    "Erro",
                    "Backup nao encontrado (sd.bdt.original).\n"
                    "A dublagem nunca foi instalada neste PC."))
        except Exception as ex:
            self.after(0, lambda: messagebox.showerror("Erro", str(ex)))
        finally:
            self.after(0, lambda: self.restore_btn.configure(state="normal"))

    # ── Auto-update check ──

    def _check_update_silent(self):
        """Check for updates on startup. Shows banner on welcome page if available."""
        try:
            release = get_latest_release(GITHUB_REPO)
            if not release:
                return
            latest = release.get('tag_name', '').lstrip('v')
            if not latest or latest <= PATCHER_VERSION:
                return
            url = release.get('html_url', '')

            def _show_update():
                # Add update banner to welcome page
                banner = ctk.CTkFrame(
                    self._pages[STEP_WELCOME],
                    fg_color="#1a2a1a", corner_radius=10,
                    border_width=1, border_color=SUCCESS_GREEN
                )
                banner.pack(fill="x", pady=(8, 0))
                inner = ctk.CTkFrame(banner, fg_color="transparent")
                inner.pack(fill="x", padx=12, pady=8)
                ctk.CTkLabel(
                    inner,
                    text=f"Nova versao disponivel: v{latest}  (atual: v{PATCHER_VERSION})",
                    font=ctk.CTkFont("Segoe UI", 12),
                    text_color=SUCCESS_GREEN, anchor="w"
                ).pack(side="left")
                ctk.CTkButton(
                    inner, text="Baixar",
                    font=ctk.CTkFont("Segoe UI", 11, "bold"),
                    fg_color=SUCCESS_GREEN, hover_color="#0ee090",
                    text_color="#0a0a0f", width=80, height=28,
                    corner_radius=6,
                    command=lambda: webbrowser.open(url)
                ).pack(side="right")
            self.after(0, _show_update)
        except Exception:
            pass  # Silently ignore update check failures


# ============================================================
# Entry point
# ============================================================

if __name__ == "__main__":
    app = PatcherApp()
    app.mainloop()
