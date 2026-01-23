@echo off
REM Batch script to set up virtual environment for Network Packet Sniffer
REM Run this script in Command Prompt (as Administrator if needed)

echo ========================================
echo Network Packet Sniffer - Environment Setup
echo ========================================
echo.

REM Check if Python is installed
echo Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found!
    echo Please install Python 3.6+ from https://www.python.org/
    pause
    exit /b 1
)

python --version
echo.

REM Create virtual environment
echo Creating virtual environment...
if exist venv (
    echo Virtual environment already exists. Removing old one...
    rmdir /s /q venv
)

python -m venv venv
if errorlevel 1 (
    echo ERROR: Failed to create virtual environment!
    pause
    exit /b 1
)

echo Virtual environment created successfully!
echo.

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Upgrade pip
echo.
echo Upgrading pip...
python -m pip install --upgrade pip

REM Install requirements
echo.
echo Installing required packages...
pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: Failed to install requirements!
    pause
    exit /b 1
)

REM Install the package in development mode (optional)
echo.
echo Installing package in development mode...
pip install -e .

echo.
echo ========================================
echo Setup Complete!
echo ========================================
echo.
echo To activate the environment, run:
echo   venv\Scripts\activate.bat
echo.
echo Or use the activate.bat file:
echo   activate.bat
echo.
echo To run the GUI:
echo   python sniffer_gui.py
echo.
echo To run the CLI version:
echo   python sniffer.py
echo.
pause
