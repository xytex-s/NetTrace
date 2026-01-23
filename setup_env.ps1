# PowerShell script to set up virtual environment for Network Packet Sniffer
# Run this script in PowerShell (as Administrator if needed)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Network Packet Sniffer - Environment Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if Python is installed
Write-Host "Checking Python installation..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    Write-Host "Found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Python not found!" -ForegroundColor Red
    Write-Host "Please install Python 3.6+ from https://www.python.org/" -ForegroundColor Red
    exit 1
}

# Check Python version
$version = python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
$majorVersion = [int]($version.Split('.')[0])
$minorVersion = [int]($version.Split('.')[1])

if ($majorVersion -lt 3 -or ($majorVersion -eq 3 -and $minorVersion -lt 6)) {
    Write-Host "ERROR: Python 3.6+ required. Found Python $version" -ForegroundColor Red
    exit 1
}

# Create virtual environment
Write-Host ""
Write-Host "Creating virtual environment..." -ForegroundColor Yellow
if (Test-Path "venv") {
    Write-Host "Virtual environment already exists. Removing old one..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force "venv"
}

python -m venv venv

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to create virtual environment!" -ForegroundColor Red
    exit 1
}

Write-Host "Virtual environment created successfully!" -ForegroundColor Green

# Activate virtual environment
Write-Host ""
Write-Host "Activating virtual environment..." -ForegroundColor Yellow
& "venv\Scripts\Activate.ps1"

if ($LASTEXITCODE -ne 0) {
    Write-Host "WARNING: Could not activate virtual environment automatically." -ForegroundColor Yellow
    Write-Host "Please run: .\venv\Scripts\Activate.ps1" -ForegroundColor Yellow
}

# Upgrade pip
Write-Host ""
Write-Host "Upgrading pip..." -ForegroundColor Yellow
python -m pip install --upgrade pip

# Install requirements
Write-Host ""
Write-Host "Installing required packages..." -ForegroundColor Yellow
pip install -r requirements.txt

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to install requirements!" -ForegroundColor Red
    exit 1
}

# Install the package in development mode (optional)
Write-Host ""
Write-Host "Installing package in development mode..." -ForegroundColor Yellow
pip install -e .

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Setup Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "To activate the environment, run:" -ForegroundColor Yellow
Write-Host "  .\venv\Scripts\Activate.ps1" -ForegroundColor White
Write-Host ""
Write-Host "Or use the activate.bat file:" -ForegroundColor Yellow
Write-Host "  .\activate.bat" -ForegroundColor White
Write-Host ""
Write-Host "To run the GUI:" -ForegroundColor Yellow
Write-Host "  python sniffer_gui.py" -ForegroundColor White
Write-Host ""
Write-Host "To run the CLI version:" -ForegroundColor Yellow
Write-Host "  python sniffer.py" -ForegroundColor White
Write-Host ""
