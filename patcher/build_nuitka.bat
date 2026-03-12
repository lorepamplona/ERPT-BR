@echo off
echo Building Elden Ring PT-BR Patcher (Nuitka)...
echo This may take 5-15 minutes on first build...
echo.

python -m nuitka ^
  --onefile ^
  --enable-plugin=tk-inter ^
  --include-package-data=customtkinter ^
  --include-module=Crypto.Cipher.AES ^
  --include-module=Crypto.PublicKey.RSA ^
  --include-module=Crypto.Cipher._raw_ecb ^
  --include-data-files=patcher.ico=patcher.ico ^
  --windows-console-mode=disable ^
  --windows-icon-from-ico=patcher.ico ^
  --output-filename=EldenRing_Dublagem_PTBR.exe ^
  --output-dir=dist ^
  --assume-yes-for-downloads ^
  patcher_gui.py

echo.
if exist "dist\EldenRing_Dublagem_PTBR.exe" (
    echo Build OK! Check dist\ folder.
) else (
    echo Build FAILED! Check errors above.
)
pause
