@echo off
setlocal
set ROOT=%~dp0..
cd /d "%ROOT%"
if not exist .venv\Scripts\python.exe (
  py -3.12 -m venv .venv || exit /b 1
)
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip || exit /b 1
python -m pip install -r requirements-gui.txt || exit /b 1
python -m PyInstaller --noconfirm --clean --onefile --windowed --name VM-SSH-GUI --paths src --collect-all PySide6 --collect-all paramiko --collect-all cryptography --collect-all bcrypt --collect-all nacl --collect-all shiboken6 src\vmssh\gui\main.py
if errorlevel 1 exit /b 1
if not exist 02-GUI mkdir 02-GUI
copy /y dist\VM-SSH-GUI.exe 02-GUI\VM-SSH-GUI.exe || exit /b 1
 echo GUI build completed.
