# Environment Setup Guide

This guide will help you set up a virtual environment with all required dependencies for NetTrace.

## Quick Setup

### Option 1: Automated Setup (Recommended)

**For PowerShell:**
```powershell
.\setup_env.ps1
```

**For Command Prompt:**
```cmd
setup_env.bat
```

These scripts will:
- Check Python installation
- Create a virtual environment (`venv`)
- Install all required packages
- Set up the package in development mode

### Option 2: Manual Setup

1. **Create virtual environment:**
   ```powershell
   python -m venv venv
   ```

2. **Activate the environment:**
   
   **PowerShell:**
   ```powershell
   .\venv\Scripts\Activate.ps1
   ```
   
   **Command Prompt:**
   ```cmd
   venv\Scripts\activate.bat
   ```

3. **Upgrade pip:**
   ```bash
   python -m pip install --upgrade pip
   ```

4. **Install requirements:**
   ```bash
   pip install -r requirements.txt
   ```

5. **Install package in development mode (optional):**
   ```bash
   pip install -e .
   ```

## Activating the Environment

After setup, you can activate the environment using:

**PowerShell:**
```powershell
.\activate.ps1
# or
.\venv\Scripts\Activate.ps1
```

**Command Prompt:**
```cmd
activate.bat
# or
venv\Scripts\activate.bat
```

**Quick Activation Scripts:**
- `activate.bat` - Opens a new command prompt with venv activated
- `activate.ps1` - Activates venv in current PowerShell session

## Verifying Installation

Once the environment is activated, verify the installation:

```bash
python -c "import psutil; print('psutil version:', psutil.__version__)"
python -c "from sniffer import PacketFilter; print('Sniffer module loaded successfully')"
```

## Running the Application

With the environment activated:

**GUI Version:**
```bash
python sniffer_gui.py
```

**CLI Version:**
```bash
python sniffer.py
```

## Deactivating the Environment

When you're done, deactivate the environment:

```bash
deactivate
```

## Requirements

- **Python 3.6+** (Python 3.14.2 tested)
- **pip** (comes with Python)
- **Administrator/root privileges** (required for running the sniffer)

## Installed Packages

The following packages are installed in the virtual environment:

- **psutil** (>=5.9.0) - For network interface detection and system information

## Troubleshooting

### "Python not found" Error

- Ensure Python is installed and added to PATH
- Download from: https://www.python.org/
- During installation, check "Add Python to PATH"

### "Activate.ps1 cannot be loaded" Error (PowerShell)

Run this command in PowerShell (as Administrator):
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### "Permission denied" Error

- On Windows: Run PowerShell/CMD as Administrator
- On Linux/macOS: Use `sudo` when running the sniffer (not for setup)

### Virtual Environment Not Found

If you see "venv not found", run the setup script again:
```powershell
.\setup_env.ps1
```

## Project Structure

```
NetTrace/
├── venv/                 # Virtual environment (created by setup)
├── sniffer.py           # CLI version
├── sniffer_gui.py       # GUI version
├── requirements.txt     # Python dependencies
├── setup.py            # Package configuration
├── setup_env.ps1       # PowerShell setup script
├── setup_env.bat       # Batch setup script
├── activate.ps1        # PowerShell activation helper
└── activate.bat        # Batch activation helper
```

## Notes

- The virtual environment (`venv/`) is excluded from version control (see `.gitignore`)
- Each developer should create their own virtual environment
- The environment is platform-specific (Windows/Linux/macOS)
- Always activate the environment before running the application
