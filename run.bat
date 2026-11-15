@echo off
setlocal
cd /d "%~dp0"
title PhishGuard

set "PY=py -3.12"
%PY% -c "import sys" >nul 2>nul
if errorlevel 1 set "PY=python"
%PY% -c "import sys" >nul 2>nul
if errorlevel 1 (
    echo [!] Python 3.12 was not found.
    echo     Install it from https://www.python.org/downloads/ and tick
    echo     "Add python.exe to PATH" during installation.
    pause
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo First run: creating virtual environment...
    %PY% -m venv .venv
    if errorlevel 1 goto :fail
)

".venv\Scripts\python.exe" -c "import streamlit, sklearn" >nul 2>nul
if errorlevel 1 (
    echo Installing dependencies, please wait...
    ".venv\Scripts\python.exe" -m pip install --upgrade pip >nul 2>nul
    ".venv\Scripts\python.exe" -m pip install -r requirements.txt
    if errorlevel 1 goto :fail
)

".venv\Scripts\python.exe" -c "import sklearn.ensemble" >nul 2>nul
if errorlevel 1 (
    echo Applying Smart App Control workaround...
    ".venv\Scripts\python.exe" fix_sklearn_dll.py
    if errorlevel 1 goto :fail
    ".venv\Scripts\python.exe" -c "import sklearn.ensemble" >nul 2>nul
    if errorlevel 1 goto :fail
)

".venv\Scripts\python.exe" -m streamlit run app.py
exit /b 0

:fail
echo.
echo Startup failed. Check the messages above.
pause
exit /b 1
