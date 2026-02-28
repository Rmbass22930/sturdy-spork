# PowerShell script to remove BOM (Byte Order Mark) and non-printable characters from a Python file

# Specify the path to your Python file (change this path to your specific file location)
$filePath = "G:\BallisticTarget\src\BallisticTargetGUI.py"

# Check if the file exists
if (Test-Path $filePath) {
    Write-Host "File found. Proceeding to clean BOM and non-printable characters..." -ForegroundColor Green

    # Read the content of the file
    $fileContent = Get-Content $filePath -Raw

    # Remove the BOM (Byte Order Mark) if present
    $fileContent = $fileContent.TrimStart([char]0xFEFF)

    # Remove any other non-printable characters (e.g., control characters)
    $fileContent = $fileContent -replace '[^\x20-\x7E]' # Removes non-printable characters

    # Save the cleaned content back to the file
    Set-Content $filePath -Value $fileContent -Encoding UTF8

    Write-Host "BOM and non-printable characters removed successfully!" -ForegroundColor Green
} else {
    Write-Host "ERROR: The specified file does not exist." -ForegroundColor Red
}