@echo off
setlocal EnableExtensions DisableDelayedExpansion
if not defined ERPTBR_INTERNAL_CALL (
  echo Este e um componente interno. Use ERPT-BR.cmd na pasta principal.
  if not defined ERPTBR_NONINTERACTIVE pause
  exit /b 2
)
for %%I in ("%~dp0..") do set "ERPT_PACKAGE_ROOT=%%~fI\"
cd /d "%ERPT_PACKAGE_ROOT%"

echo ERPT-BR - instalacao transparente em codigo-fonte
echo -------------------------------------------------
echo Este script cria um ambiente Python local e instala somente os
echo quatro pacotes verificados que acompanham este release.
echo.

if not defined LOCALAPPDATA set "LOCALAPPDATA=%ERPT_PACKAGE_ROOT%.localdata"
call :find_python
if errorlevel 1 goto :python_missing

set "ERPT_ROOT=%LOCALAPPDATA%\ERPT-BR"
set "ERPT_VENV=%ERPT_ROOT%\venv-0.9.5"
set "ERPT_SITE=%ERPT_VENV%\Lib\site-packages"

"%ERPT_PY%" %ERPT_PY_SWITCH% -I -S -c "import os,stat; rp=getattr(stat,'FILE_ATTRIBUTE_REPARSE_POINT',0); paths=(os.environ['ERPT_ROOT'],os.environ['ERPT_VENV']); roots_bad=[p for p in paths if os.path.lexists(p) and (not stat.S_ISDIR(os.lstat(p).st_mode) or bool(getattr(os.lstat(p),'st_file_attributes',0)&rp))]; walk=list(os.walk(paths[1],followlinks=False,onerror=lambda error: (_ for _ in ()).throw(error))) if not roots_bad and os.path.isdir(paths[1]) else []; nested=[os.path.join(base,name) for base,dirs,files in walk for name in dirs+files]; bad=roots_bad+[p for p in nested if bool(getattr(os.lstat(p),'st_file_attributes',0)&rp)]; raise SystemExit(1 if bad else 0)" >nul 2>&1
if errorlevel 1 goto :unsafe_environment

if not exist "%ERPT_PACKAGE_ROOT%wheelhouse\" (
  echo ERRO: a pasta wheelhouse nao foi encontrada.
  echo Baixe e extraia ERPT-BR-v0.9.5-Windows.zip completo da pagina Releases.
  goto :failed
)

echo Recriando ambiente isolado em "%ERPT_VENV%"...
"%ERPT_PY%" %ERPT_PY_SWITCH% -I -S -m venv --clear --copies "%ERPT_VENV%"
if errorlevel 1 goto :failed

"%ERPT_PY%" %ERPT_PY_SWITCH% -I -S -c "import os,stat; rp=getattr(stat,'FILE_ATTRIBUTE_REPARSE_POINT',0); root=os.environ['ERPT_VENV']; paths=((root,1),(os.path.join(root,'Scripts'),1),(os.path.join(root,'Scripts','python.exe'),0),(os.path.join(root,'Scripts','pythonw.exe'),0),(os.environ['ERPT_SITE'],1)); bad=[p for p,want_dir in paths if not os.path.lexists(p) or bool(stat.S_ISDIR(os.lstat(p).st_mode)) != bool(want_dir) or bool(getattr(os.lstat(p),'st_file_attributes',0)&rp)]; raise SystemExit(1 if bad else 0)" >nul 2>&1
if errorlevel 1 goto :unsafe_environment

echo Instalando dependencias verificadas offline...
"%ERPT_VENV%\Scripts\python.exe" -I -S -c "import runpy,sys; sys.prefix=sys.exec_prefix=sys.argv[1]; sys.path.append(sys.argv[2]); sys.argv=['pip']+sys.argv[3:]; runpy.run_module('pip',run_name='__main__')" "%ERPT_VENV%" "%ERPT_SITE%" --isolated install ^
  --disable-pip-version-check ^
  --no-input ^
  --no-index ^
  --find-links "%ERPT_PACKAGE_ROOT%wheelhouse" ^
  --require-hashes ^
  --only-binary=:all: ^
  -r "%ERPT_PACKAGE_ROOT%patcher\requirements-win64.lock"
if errorlevel 1 goto :failed

"%ERPT_VENV%\Scripts\python.exe" -I -S -c "import runpy,sys; sys.prefix=sys.exec_prefix=sys.argv[1]; sys.path.append(sys.argv[2]); sys.argv=['pip']+sys.argv[3:]; runpy.run_module('pip',run_name='__main__')" "%ERPT_VENV%" "%ERPT_SITE%" --isolated check
if errorlevel 1 goto :failed

"%ERPT_VENV%\Scripts\python.exe" -I -S -c "import sys; sys.path.append(sys.argv[1]); import tkinter,customtkinter; from Crypto.Cipher import AES" "%ERPT_SITE%"
if errorlevel 1 goto :failed

echo.
echo Ambiente do ERPT-BR preparado com sucesso.
if not defined ERPTBR_NONINTERACTIVE pause
exit /b 0

:python_missing
echo.
echo ERRO: CPython 3.13 x64 compativel com Tkinter nao foi encontrado.
echo Instale-o pelo site https://www.python.org/downloads/release/python-31315/
echo Baixe "Windows installer (64-bit)" e mantenha Python Launcher e Tcl/Tk selecionados.
echo Nao e necessario instalar para todos os usuarios. Depois execute ERPT-BR.cmd novamente.
goto :failed

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
"%ERPT_CANDIDATE%" %ERPT_CANDIDATE_SWITCH% -I -S -c "import struct,sys,sysconfig,tkinter; raise SystemExit(0 if sys.implementation.name == 'cpython' and sys.version_info[:2] == (3,13) and sys.version_info[2] >= 15 and sys.version_info.releaselevel == 'final' and struct.calcsize('P') == 8 and sysconfig.get_platform().lower() == 'win-amd64' and not sysconfig.get_config_var('Py_GIL_DISABLED') else 1)" >nul 2>&1
if errorlevel 1 exit /b 1
set "ERPT_PY=%ERPT_CANDIDATE%"
set "ERPT_PY_SWITCH=%ERPT_CANDIDATE_SWITCH%"
exit /b 0

:unsafe_environment
echo.
echo ERRO: o ambiente isolado tem um link, reparse point ou tipo inesperado.
echo Ele foi preservado e nenhum arquivo do jogo foi alterado.
echo Nao apague "%ERPT_ROOT%", pois ela pode conter backups do jogo.
echo Revise esse caminho e mova somente o item inesperado antes de tentar de novo.
goto :failed

:failed
echo.
echo Nada foi instalado nos arquivos do Elden Ring.
if not defined ERPTBR_NONINTERACTIVE pause
exit /b 1
