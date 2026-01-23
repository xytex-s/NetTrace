# PowerShell script to activate the virtual environment
# Run: .\activate.ps1

if (Test-Path "venv\Scripts\Activate.ps1") {
    & "venv\Scripts\Activate.ps1"
    Write-Host "Virtual environment activated!" -ForegroundColor Green
    Write-Host ""
    Write-Host "You can now run:" -ForegroundColor Yellow
    Write-Host "  python sniffer_gui.py    (for GUI)" -ForegroundColor White
    Write-Host "  python sniffer.py        (for CLI)" -ForegroundColor White
    Write-Host ""
    Write-Host "Type 'deactivate' to exit the virtual environment." -ForegroundColor Yellow
} else {
    Write-Host "ERROR: Virtual environment not found!" -ForegroundColor Red
    Write-Host "Please run setup_env.ps1 or setup_env.bat first to create the environment." -ForegroundColor Red
}
