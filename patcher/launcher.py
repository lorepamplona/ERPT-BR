#!/usr/bin/env python3
"""
Elden Ring - Dublagem PT-BR
Launcher minimalista: baixa o patcher mais recente do GitHub e executa.

Este arquivo é buildado UMA VEZ como EldenRing_Dublagem_PTBR.exe.
Todo o código do patcher vive em patcher_gui.py no GitHub — cada commit
chega automaticamente para o usuário na próxima abertura, sem rebuild.
"""

import os
import sys
import stat
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
import urllib.request
import urllib.error
from pathlib import Path

# Pré-importa tudo que patcher_gui.py usa para que o Nuitka empacote os módulos.
# Nuitka analisa estaticamente — se não importar aqui, não vai no exe.
def _preload_for_nuitka():  # nunca é chamado em runtime
    import customtkinter                    # noqa
    from Crypto.Cipher import AES           # noqa
    from Crypto.PublicKey import RSA        # noqa
    from Crypto.Cipher import _raw_ecb      # noqa

# ── Configuração ──────────────────────────────────────────────────────────────

# URL do script principal no GitHub (raw). Altere o branch se necessário.
SCRIPT_URL = (
    "https://raw.githubusercontent.com/lorepamplona/ERPT-BR/main/patcher_gui.py"
)

# Pasta de cache local: %LOCALAPPDATA%\EldenRingPTBR\
CACHE_DIR = Path(os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))) / "EldenRingPTBR"
CACHED_SCRIPT = CACHE_DIR / "patcher_gui.py"

# ── Splash (janela de "Carregando...") ────────────────────────────────────────

def _make_splash() -> tk.Tk:
    root = tk.Tk()
    root.overrideredirect(True)
    root.configure(bg="#0a0a0f")
    w, h = 320, 80
    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
    root.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")
    tk.Label(
        root,
        text="⚔  Elden Ring Dublagem PT-BR",
        bg="#0a0a0f", fg="#c8aa6e",
        font=("Segoe UI", 13, "bold"),
    ).pack(expand=True)
    tk.Label(
        root,
        text="Verificando atualização...",
        bg="#0a0a0f", fg="#5b5a56",
        font=("Segoe UI", 9),
    ).pack()
    root.update()
    return root


def _close_splash(splash: tk.Tk):
    try:
        splash.destroy()
    except Exception:
        pass

# ── Download ──────────────────────────────────────────────────────────────────

def _fetch_script() -> bytes | None:
    """Tenta baixar o script mais recente do GitHub. Retorna None se falhar."""
    try:
        req = urllib.request.Request(
            SCRIPT_URL,
            headers={"User-Agent": "EldenRingPTBR-Launcher/1.0"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read()
    except Exception:
        return None


def _fatal(msg: str):
    root = tk.Tk()
    root.withdraw()
    from tkinter import messagebox
    messagebox.showerror("Elden Ring PT-BR", msg)
    root.destroy()

# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    splash = _make_splash()

    # Tenta baixar versão mais recente
    data = _fetch_script()

    if data is not None:
        # Salva no cache apenas se o conteúdo mudou (evita I/O desnecessário)
        try:
            if not CACHED_SCRIPT.exists() or CACHED_SCRIPT.read_bytes() != data:
                CACHED_SCRIPT.write_bytes(data)
        except Exception:
            pass
        script_code = data
    elif CACHED_SCRIPT.exists():
        # Offline mas tem cache — usa última versão baixada
        script_code = CACHED_SCRIPT.read_bytes()
    else:
        _close_splash(splash)
        _fatal(
            "Sem conexão com a internet.\n\n"
            "O patcher precisa de internet na primeira execução para baixar o programa.\n"
            "Conecte-se e tente novamente."
        )
        return

    _close_splash(splash)

    # Executa o script baixado no mesmo processo (mesmo Python, mesmos módulos)
    globs = {
        "__name__": "__main__",
        "__file__": str(CACHED_SCRIPT),
        "__spec__": None,
    }
    exec(compile(script_code.decode("utf-8"), str(CACHED_SCRIPT), "exec"), globs)  # noqa: S102


if __name__ == "__main__":
    main()
