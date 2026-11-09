@echo off
setlocal
set ROOT=%~dp0..
cd /d "%ROOT%"
if not exist .venv\Scripts\python.exe (
  py -3.12 -m venv .venv || exit /b 1
)
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip || exit /b 1
python -m pip install -r requirements-cli.txt || exit /b 1
python -m PyInstaller --noconfirm --clean --onefile --console --name VM-SSH-CLI --paths src --collect-all paramiko --collect-all cryptography --collect-all bcrypt --collect-all nacl src\vmssh\cli\main.py
if errorlevel 1 exit /b 1
if not exist 01-CLI mkdir 01-CLI
copy /y dist\VM-SSH-CLI.exe 01-CLI\VM-SSH-CLI.exe || exit /b 1
 echo CLI build completed.
