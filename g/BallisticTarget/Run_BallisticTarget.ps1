# Run_BallisticTarget.ps1
# This script will launch BallisticTarget from the USB drive.

Stop = "Stop"

# Set the USB directory path dynamically
\ = "\"

# Define the EXE path
\ = "\\BallisticTarget.exe"

# Check if the EXE exists on the USB drive
if (-not (Test-Path \)) {
    Write-Host "ERROR: BallisticTarget.exe not found on USB drive." -ForegroundColor Red
    exit
}

# Launch the EXE
Start-Process -FilePath \
Write-Host "BallisticTarget launched from USB." -ForegroundColor Green
