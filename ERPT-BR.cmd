@echo off
setlocal EnableExtensions DisableDelayedExpansion
cd /d "%~dp0"

if defined ERPTBR_NONINTERACTIVE set "ERPTBR_ONECLICK_CALLER_NONINTERACTIVE=1"

if not defined SystemRoot goto :windows_environment_missing
if not defined LOCALAPPDATA goto :windows_environment_missing
set "ERPT_POWERSHELL=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%ERPT_POWERSHELL%" goto :windows_environment_missing

rem Um mutex do Windows impede dois cliques simultaneos de recriarem o mesmo venv.
if defined ERPTBR_ONECLICK_MUTEX_HELD goto :main
set "ERPTBR_ONECLICK_SELF=%~f0"
set "ERPTBR_ONECLICK_MUTEX_HELD=1"
"%ERPT_POWERSHELL%" -NoLogo -NoProfile -NonInteractive -Command "$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value.Replace('-','_'); $mutex=[Threading.Mutex]::new($false,('Local\ERPTBR_Installer_'+$sid)); $owned=$false; $code=1; try { try { $owned=$mutex.WaitOne(0,$false) } catch [Threading.AbandonedMutexException] { $owned=$true }; if(-not $owned) { Write-Host 'Outra instalacao do ERPT-BR ja esta em andamento.'; $code=75 } else { & $env:ERPTBR_ONECLICK_SELF; $code=$LASTEXITCODE } } finally { if($owned) { [void]$mutex.ReleaseMutex() }; $mutex.Dispose() }; exit $code"
exit /b %ERRORLEVEL%

:main
echo ERPT-BR - instalador da dublagem PT-BR
echo --------------------------------------
echo Este script prepara o Python oficial no seu perfil, se necessario,
echo instala a interface com as dependencias offline e abre o instalador.
echo Compativel com Elden Ring 1.17.1, Steam BuildID 25080141.
echo Nenhum executavel proprio do projeto e usado.
echo.

rem Recusa ZIP automatico do GitHub e release incompleto antes de instalar Python.
set "ERPT_PACKAGE_ROOT=%~dp0"
"%ERPT_POWERSHELL%" -NoLogo -NoProfile -NonInteractive -Command "$ErrorActionPreference='Stop'; try { Import-Module -Name (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -Force -ErrorAction Stop; $root=$env:ERPT_PACKAGE_ROOT; $required=@('interno\INSTALAR_AMBIENTE.cmd','interno\ABRIR_INTERFACE.cmd','patcher\__init__.py','patcher\bnk.py','patcher\engine.py','patcher\diagnostics.py','patcher\patch_data.py','patcher\patcher_gui.py','patcher\patcher.ico','patcher\requirements-win64.lock'); $wheels=@{'wheelhouse\customtkinter-5.2.2-py3-none-any.whl'='14ad3e7cd3cb3b9eb642b9d4e8711ae80d3f79fb82545ad11258eeffb2e6b37c';'wheelhouse\darkdetect-0.8.0-py3-none-any.whl'='a7509ccf517eaad92b31c214f593dbcf138ea8a43b2935406bbd565e15527a85';'wheelhouse\packaging-26.3-py3-none-any.whl'='d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c';'wheelhouse\pycryptodome-3.23.0-cp37-abi3-win_amd64.whl'='c75b52aacc6c0c260f204cbdd834f76edc9fb0d8e0da9fbf8352ef58202564e2'}; foreach($relative in $required+$wheels.Keys) { $path=Join-Path $root $relative; if(-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw ('Arquivo obrigatorio ausente: '+$relative) }; $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop; if($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw ('Arquivo obrigatorio e um link inseguro: '+$relative) } }; $payload=Join-Path $root 'patch_data'; if(-not (Test-Path -LiteralPath $payload -PathType Container)) { throw 'Pasta obrigatoria ausente: patch_data' }; $payloadItem=Get-Item -LiteralPath $payload -Force -ErrorAction Stop; if($payloadItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'A pasta patch_data e um link inseguro' }; foreach($entry in $wheels.GetEnumerator()) { $actual=(Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath (Join-Path $root $entry.Key) -Algorithm SHA256).Hash; if($actual -ne $entry.Value) { throw ('Wheel ausente ou adulterado: '+$entry.Key) } } } catch { Write-Host ('ERPT-PACKAGE-001: '+$_.Exception.Message) -ForegroundColor Red; exit 1 }"
if errorlevel 1 goto :invalid_package

call :find_python
if not errorlevel 1 goto :python_ready

set "ERPT_WINGET=%LOCALAPPDATA%\Microsoft\WindowsApps\winget.exe"
if not exist "%ERPT_WINGET%" goto :install_direct

echo CPython 3.13.15 x64 ou manutencao mais nova nao encontrado.
echo Instalando pelo WinGet da Microsoft somente para este usuario...
"%ERPT_WINGET%" install --exact --id Python.Python.3.13 --version 3.13.15 --source winget --scope user --architecture x64 --silent --disable-interactivity --accept-package-agreements --accept-source-agreements --override "/passive InstallAllUsers=0 Include_exe=1 Include_lib=1 Include_dev=1 Include_launcher=1 InstallLauncherAllUsers=0 Include_pip=1 Include_tcltk=1 Include_freethreaded=0 Include_test=0 Include_doc=0 Include_debug=0 Include_symbols=0 PrependPath=0 AppendPath=0 AssociateFiles=0 Shortcuts=0"
if errorlevel 1 goto :winget_failed
call :find_python
if errorlevel 1 goto :python_install_invalid
goto :python_ready

:install_direct
set "ERPT_CURL=%SystemRoot%\System32\curl.exe"
if not exist "%ERPT_CURL%" goto :no_safe_downloader
set "ERPT_BOOTSTRAP_ROOT=%LOCALAPPDATA%\ERPT-BR\bootstrap"
"%ERPT_POWERSHELL%" -NoLogo -NoProfile -NonInteractive -Command "$ErrorActionPreference='Stop'; $p=$env:ERPT_BOOTSTRAP_ROOT; $parent=Split-Path -Parent $p; foreach($candidate in @($parent,$p)) { if(Test-Path -LiteralPath $candidate) { $item=Get-Item -LiteralPath $candidate -Force; if(-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw ('Caminho de bootstrap inseguro: '+$candidate) } } else { New-Item -ItemType Directory -Path $candidate -ErrorAction Stop | Out-Null } }"
if errorlevel 1 goto :unsafe_bootstrap

for /f "delims=" %%G in ('%ERPT_POWERSHELL% -NoLogo -NoProfile -NonInteractive -Command "[Guid]::NewGuid().ToString('N')"') do set "ERPT_BOOTSTRAP_GUID=%%G"
if not defined ERPT_BOOTSTRAP_GUID goto :download_failed
set "ERPT_BOOTSTRAP_FILE=%ERPT_BOOTSTRAP_ROOT%\python-3.13.15-amd64-%ERPT_BOOTSTRAP_GUID%.download"

echo WinGet nao esta disponivel nesta instalacao do Windows.
echo Baixando 29.452.944 bytes do instalador oficial em python.org...
"%ERPT_CURL%" --fail --show-error --progress-bar --proto "=https" --tlsv1.2 --retry 2 --connect-timeout 20 --output "%ERPT_BOOTSTRAP_FILE%" "https://www.python.org/ftp/python/3.13.15/python-3.13.15-amd64.exe"
if errorlevel 1 goto :download_failed

echo Conferindo tamanho, SHA-256, assinatura digital e publicador...
"%ERPT_POWERSHELL%" -NoLogo -NoProfile -NonInteractive -Command "$ErrorActionPreference='Stop'; Import-Module -Name (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -Force -ErrorAction Stop; Import-Module -Name (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -Force -ErrorAction Stop; $path=$env:ERPT_BOOTSTRAP_FILE; $expected='EDEC09C4853AEAE9AC36EFB8C9F95B6B8E2FEE65EEE56D9767A8B7C69C574403'; $publisher='CN=Python Software Foundation, O=Python Software Foundation, L=Beaverton, S=Oregon, C=US'; $item=Get-Item -LiteralPath $path -Force; if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -ne 29452944) { throw 'Tamanho ou tipo do instalador invalido.' }; $hash=(Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash; if($hash -ne $expected) { throw 'SHA-256 do instalador invalido.' }; $signature=Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $path; if($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or $signature.SignerCertificate.Subject -ne $publisher) { throw 'Assinatura ou publicador do instalador invalido.' }; $executable=[IO.Path]::ChangeExtension($path,'.exe'); [IO.File]::Move($path,$executable); $path=$executable; $stream=[IO.FileStream]::new($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read,4096,[IO.FileOptions]::DeleteOnClose); try { if($stream.Length -ne 29452944) { throw 'O instalador mudou antes da execucao.' }; $sha=[Security.Cryptography.SHA256]::Create(); try { $handleHash=[BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','') } finally { $sha.Dispose() }; if($handleHash -ne $expected) { throw 'O instalador mudou antes da execucao.' }; $local=$env:LOCALAPPDATA; if([string]::IsNullOrWhiteSpace($local)) { throw 'LOCALAPPDATA ausente.' }; $target=Join-Path $local 'Programs\Python\Python313'; $log=Join-Path (Split-Path -Parent $path) 'python-3.13.15-install.log'; $q=[char]34; $arguments=@('/passive',('/log '+$q+$log+$q),'InstallAllUsers=0',('TargetDir='+$q+$target+$q),'Include_exe=1','Include_lib=1','Include_dev=1','Include_launcher=1','InstallLauncherAllUsers=0','Include_pip=1','Include_tcltk=1','Include_freethreaded=0','Include_test=0','Include_doc=0','Include_debug=0','Include_symbols=0','PrependPath=0','AppendPath=0','AssociateFiles=0','Shortcuts=0'); $process=Start-Process -FilePath $path -ArgumentList $arguments -Wait -PassThru; if($process.ExitCode -ne 0 -and $process.ExitCode -ne 3010) { throw ('O instalador oficial retornou '+$process.ExitCode+'.') } } finally { $stream.Dispose() }"
if errorlevel 1 goto :direct_install_failed
call :find_python
if errorlevel 1 goto :python_install_invalid

:python_ready
echo CPython 3.13 x64 compativel validado.
echo Preparando ou abrindo o ERPT-BR...
set "ERPTBR_NONINTERACTIVE=1"
set "ERPTBR_INTERNAL_CALL=1"
call "%~dp0interno\ABRIR_INTERFACE.cmd"
if errorlevel 1 goto :launcher_failed
if defined ERPTBR_INSTALL_ONLY goto :success_install_only
exit /b 0

:success_install_only
echo Instalacao de um clique validada sem abrir a interface.
exit /b 0

:find_python
set "ERPT_PY="
set "ERPT_PY_SWITCH="
set "ERPT_CANDIDATE=%LOCALAPPDATA%\Programs\Python\Launcher\py.exe"
set "ERPT_CANDIDATE_SWITCH=-3.13"
call :check_python
if not errorlevel 1 exit /b 0
set "ERPT_CANDIDATE=%SystemRoot%\py.exe"
set "ERPT_CANDIDATE_SWITCH=-3.13"
call :check_python
if not errorlevel 1 exit /b 0
set "ERPT_CANDIDATE=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
set "ERPT_CANDIDATE_SWITCH="
call :check_python
if not errorlevel 1 exit /b 0
exit /b 1

:check_python
if not exist "%ERPT_CANDIDATE%" exit /b 1
set "ERPT_FILE_TO_CHECK=%ERPT_CANDIDATE%"
"%ERPT_POWERSHELL%" -NoLogo -NoProfile -NonInteractive -Command "$item=Get-Item -LiteralPath $env:ERPT_FILE_TO_CHECK -Force -ErrorAction SilentlyContinue; if($null -eq $item -or $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { exit 1 }"
if errorlevel 1 exit /b 1
"%ERPT_CANDIDATE%" %ERPT_CANDIDATE_SWITCH% -I -S -c "import struct,sys,sysconfig,tkinter; raise SystemExit(0 if sys.implementation.name == 'cpython' and sys.version_info[:2] == (3,13) and sys.version_info[2] >= 15 and sys.version_info.releaselevel == 'final' and struct.calcsize('P') == 8 and sysconfig.get_platform().lower() == 'win-amd64' and not sysconfig.get_config_var('Py_GIL_DISABLED') else 1)" >nul 2>&1
if errorlevel 1 exit /b 1
set "ERPT_PY=%ERPT_CANDIDATE%"
set "ERPT_PY_SWITCH=%ERPT_CANDIDATE_SWITCH%"
exit /b 0

:winget_failed
echo.
echo ERRO: o WinGet existe, mas recusou ou nao concluiu a instalacao oficial.
echo O fallback direto nao foi acionado para nao contornar politica, antivirus ou cancelamento.
echo Repare o App Installer/WinGet ou instale manualmente pelo endereco abaixo:
echo https://www.python.org/downloads/release/python-31315/
goto :failed

:download_failed
echo.
echo ERRO: nao foi possivel concluir o download HTTPS do instalador oficial.
goto :failed

:direct_install_failed
echo.
echo ERRO: o instalador baixado nao passou pela autenticacao ou nao concluiu.
echo Nenhum arquivo nao autenticado foi executado.
goto :failed

:unsafe_bootstrap
echo.
echo ERRO: a pasta de bootstrap tem um link, reparse point ou tipo inesperado.
echo Ela foi preservada para revisao: "%ERPT_BOOTSTRAP_ROOT%"
goto :failed

:no_safe_downloader
echo.
echo ERRO: WinGet e o curl do Windows nao estao disponiveis.
echo Instale manualmente o Python oficial 3.13.15 x64 por:
echo https://www.python.org/downloads/release/python-31315/
goto :failed

:python_install_invalid
echo.
echo ERRO: a instalacao terminou, mas o CPython 3.13 x64 compativel com Tkinter nao foi validado.
goto :failed

:launcher_failed
echo.
echo ERRO: nao foi possivel preparar ou abrir a interface do ERPT-BR.
goto :failed

:windows_environment_missing
echo.
echo ERRO: o ambiente padrao do Windows nao foi localizado com seguranca.
goto :failed

:invalid_package
echo.
echo ERRO: este pacote esta incompleto ou uma dependencia nao passou pelo SHA-256.
echo O diagnostico ERPT-PACKAGE-001 acima identifica o arquivo exato.
echo Se abriu o CMD dentro do ZIP, feche esta janela e use Extrair Tudo primeiro.
echo Use ERPT-BR-v0.9.5-Windows.zip da pagina Releases, extraido por inteiro.
echo Nao use o ZIP automatico chamado apenas de Source code.
goto :failed

:failed
echo Nada foi instalado nos arquivos do Elden Ring.
if not defined ERPTBR_ONECLICK_CALLER_NONINTERACTIVE pause
exit /b 1
