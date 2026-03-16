@echo off
echo Buildando Launcher (exe minimalista - distribuir uma vez)...
echo.

python -m nuitka ^
  --onefile ^
  --enable-plugin=tk-inter ^
  --include-package=customtkinter ^
  --include-package-data=customtkinter ^
  --include-module=Crypto.Cipher.AES ^
  --include-module=Crypto.PublicKey.RSA ^
  --include-module=Crypto.Cipher._raw_ecb ^
  --include-module=tkinter ^
  --include-module=tkinter.messagebox ^
  --windows-console-mode=disable ^
  --windows-icon-from-ico=patcher.ico ^
  --output-filename=EldenRing_Dublagem_PTBR.exe ^
  --output-dir=dist ^
  --assume-yes-for-downloads ^
  launcher.py

echo.
if exist "dist\EldenRing_Dublagem_PTBR.exe" (
    echo BUILD OK! Distribua dist\EldenRing_Dublagem_PTBR.exe uma unica vez.
    echo Atualizacoes futuras: so commitar patcher_gui.py no GitHub.
) else (
    echo BUILD FALHOU! Veja erros acima.
)
pause
