@echo off
REM Quick activation script for the virtual environment
REM This script activates the venv and keeps the command prompt open

call venv\Scripts\activate.bat
if errorlevel 1 (
    echo ERROR: Virtual environment not found!
    echo Please run setup_env.bat first to create the environment.
    pause
    exit /b 1
)

echo Virtual environment activated!
echo.
echo You can now run:
echo   python sniffer_gui.py    (for GUI)
echo   python sniffer.py        (for CLI)
echo.
echo Type 'deactivate' to exit the virtual environment.
echo.

cmd /k
