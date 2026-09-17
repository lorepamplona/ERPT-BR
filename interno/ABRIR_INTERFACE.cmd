@echo off
setlocal EnableExtensions DisableDelayedExpansion
if not defined ERPTBR_INTERNAL_CALL (
  echo Este e um componente interno. Use ERPT-BR.cmd na pasta principal.
  if not defined ERPTBR_NONINTERACTIVE pause
  exit /b 2
)
for %%I in ("%~dp0..") do set "ERPT_PACKAGE_ROOT=%%~fI\"
cd /d "%ERPT_PACKAGE_ROOT%"

if not defined LOCALAPPDATA set "LOCALAPPDATA=%ERPT_PACKAGE_ROOT%.localdata"
set "ERPT_ROOT=%LOCALAPPDATA%\ERPT-BR"
set "ERPT_VENV=%ERPT_ROOT%\venv-0.9.5"
set "ERPT_SITE=%ERPT_VENV%\Lib\site-packages"

if not exist "%ERPT_VENV%\Scripts\pythonw.exe" (
  goto :repair
)

:validate
call :find_python
if errorlevel 1 goto :repair
"%ERPT_PY%" %ERPT_PY_SWITCH% -I -S -c "import os,stat,struct,sys,sysconfig; rp=getattr(stat,'FILE_ATTRIBUTE_REPARSE_POINT',0); root=os.environ['ERPT_VENV']; paths=((os.environ['ERPT_ROOT'],1),(root,1),(os.path.join(root,'Scripts'),1),(os.path.join(root,'Scripts','pythonw.exe'),0),(os.environ['ERPT_SITE'],1)); root_bad=not os.path.lexists(root) or not stat.S_ISDIR(os.lstat(root).st_mode) or bool(getattr(os.lstat(root),'st_file_attributes',0)&rp); walk=list(os.walk(root,followlinks=False,onerror=lambda error: (_ for _ in ()).throw(error))) if not root_bad else []; nested=[os.path.join(base,name) for base,dirs,files in walk for name in dirs+files]; bad=[p for p,want_dir in paths if not os.path.lexists(p) or bool(stat.S_ISDIR(os.lstat(p).st_mode)) != bool(want_dir) or bool(getattr(os.lstat(p),'st_file_attributes',0)&rp)]+[p for p in nested if bool(getattr(os.lstat(p),'st_file_attributes',0)&rp)]; wrong=sys.implementation.name != 'cpython' or sys.version_info[:2] != (3,13) or sys.version_info[2] < 15 or sys.version_info.releaselevel != 'final' or struct.calcsize('P') != 8 or sysconfig.get_platform().lower() != 'win-amd64' or bool(sysconfig.get_config_var('Py_GIL_DISABLED')); raise SystemExit(1 if bad or wrong else 0)" >nul 2>&1
if errorlevel 1 goto :repair

"%ERPT_VENV%\Scripts\python.exe" -I -S -c "import struct,sys,sysconfig; raise SystemExit(0 if sys.implementation.name == 'cpython' and sys.version_info[:2] == (3,13) and sys.version_info[2] >= 15 and sys.version_info.releaselevel == 'final' and struct.calcsize('P') == 8 and sysconfig.get_platform().lower() == 'win-amd64' and not sysconfig.get_config_var('Py_GIL_DISABLED') else 1)" >nul 2>&1
if errorlevel 1 goto :repair
"%ERPT_VENV%\Scripts\pythonw.exe" -I -S -c "import struct,sys,sysconfig; raise SystemExit(0 if sys.implementation.name == 'cpython' and sys.version_info[:2] == (3,13) and sys.version_info[2] >= 15 and sys.version_info.releaselevel == 'final' and struct.calcsize('P') == 8 and sysconfig.get_platform().lower() == 'win-amd64' and not sysconfig.get_config_var('Py_GIL_DISABLED') else 1)"
if errorlevel 1 goto :repair
"%ERPT_VENV%\Scripts\python.exe" -I -S -c "import sys; sys.path.append(sys.argv[1]); import tkinter,customtkinter; from Crypto.Cipher import AES" "%ERPT_SITE%" >nul 2>&1
if errorlevel 1 goto :repair

if defined ERPTBR_INSTALL_ONLY exit /b 0

"%ERPT_VENV%\Scripts\pythonw.exe" -I -S -c "import runpy,sys; sys.path.extend((sys.argv[1],sys.argv[2])); runpy.run_module('patcher.patcher_gui',run_name='__main__')" "%ERPT_PACKAGE_ROOT%." "%ERPT_SITE%"
if errorlevel 1 (
  echo O ERPT-BR terminou com erro. Execute ERPT-BR.cmd novamente para reparar o ambiente.
  if not defined ERPTBR_NONINTERACTIVE pause
  exit /b 1
)
exit /b 0

:repair
if defined ERPTBR_REPAIR_ATTEMPTED (
  echo O ambiente continuou invalido depois da tentativa de reparo.
  exit /b 1
)
set "ERPTBR_REPAIR_ATTEMPTED=1"
echo O ambiente Python precisa ser recriado ou revisado com seguranca.
call "%~dp0INSTALAR_AMBIENTE.cmd"
if errorlevel 1 exit /b 1
goto :validate

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
