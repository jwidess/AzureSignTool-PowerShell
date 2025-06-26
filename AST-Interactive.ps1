# AST-Interactive.ps1
# https://github.com/jwidess/AzureSignTool-PowerShell
# Author: Justin Widen
## =====================================
# This script facilitates file signing with Azure Key Vault and AzureSignTool. It authenticates with Azure CLI,
# retrieves an access token, and uses AzureSignTool to sign files with a certificate stored in Azure Key Vault.
#
# Usage:
#   1. First run: You'll be prompted to sign in to Azure CLI.
#   2. Subsequent runs: Your cached Azure credentials will be used automatically. (If signed in across Windows)
#   3. The script will then prompt for files to sign, or you can specify file paths directly via the -FilePath param.
#
# Requirements:
#   - AzureSignTool must be installed, typically with WinGet (https://github.com/vcsjones/AzureSignTool)
#   - Azure CLI must be installed, typically with WinGet (https://learn.microsoft.com/en-us/cli/azure/install-azure-cli)
#   - Access to Azure Key Vault must be configured.
#
# Script Parameters:
#   -FilePath: (Optional) One or more file paths to sign. 
#       If provided, the script will sign these files directly and skip the GUI file selector and confirmation prompt.
#       Example: .\AST-Interactive.ps1 -FilePath "C:\Path\To\File1.exe","C:\Path\To\File2.dll"
#   If -FilePath is not provided, the script will prompt with a GUI file selector and ask for confirmation before signing.
#
param(
    [Parameter(Mandatory = $false, Position = 0)]
    [string[]]$FilePath
)

#! ============================================================
# Azure Key Vault Configuration
# These values are specific to your Azure environment
$KeyVaultUri = "<KEY VAULT URI>"    # Key Vault URL
$CertificateName = "<CERTIFICATE NAME>"     # Certificate name in Key Vault

# Timestamp server URL
$TimestampUrl = "<TIMESTAMP URL>"  # e.g. "http://timestamp.digicert.com"
#! ============================================================

# Check if AzureSignTool is installed
if (-not (Get-Command azuresigntool -ErrorAction SilentlyContinue)) {
    Write-Host "❌ AzureSignTool is not installed" -ForegroundColor Red
    Write-Host "📥 Please install AzureSignTool using WinGet:" -ForegroundColor Cyan
    Write-Host "   winget install AzureSignTool" -ForegroundColor Yellow
    Write-Host "💡 After installing, close and reopen PowerShell, then relaunch this script" -ForegroundColor Cyan
    exit 1
}
Write-Host "✔️ AzureSignTool found: $(Get-Command azuresigntool | Select-Object -ExpandProperty Source)" -ForegroundColor Green

# Check if Azure CLI is installed
if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    Write-Host "❌ Azure CLI (az) is not installed" -ForegroundColor Red
    Write-Host "📥 Please install Azure CLI using WinGet:" -ForegroundColor Cyan
    Write-Host "   winget install --exact --id Microsoft.AzureCLI" -ForegroundColor Yellow
    Write-Host "💡 After installing, close and reopen PowerShell, then relaunch this script" -ForegroundColor Cyan
    exit 1
}
Write-Host "✔️ Azure CLI found: $(Get-Command az | Select-Object -ExpandProperty Source)" -ForegroundColor Green

# If running from a UNC path, set current directory to a local path to avoid warnings
$originalPath = $PWD.ProviderPath
$changedDir = $false
if ($originalPath -like "\\*") {
    Set-Location $env:TEMP
    $changedDir = $true
}

# Warn if FilePath parameter is used about interactive sign-in limitations
if ($FilePath -and $FilePath.Count -gt 0) {
    Write-Host "⚠️  Notice: When using the -FilePath parameter, Azure CLI interactive sign-in may not work properly in headless or non-interactive environments.",
    "To avoid issues, run this script in an interactive PowerShell session at least once to cache your Azure credentials." -ForegroundColor Yellow
}

try {
    # Ensure user is logged in to Azure CLI
    $azAccount = az account show 2>$null
    if (-not $azAccount) {
        Write-Host "🔑 Please log in to Azure..." -ForegroundColor Cyan
        az login --allow-no-subscriptions
        $azAccount = az account show 2>$null
        if (-not $azAccount) {
            Write-Host "❌ Azure login failed. Exiting." -ForegroundColor Red
            exit 1
        }
    }
    else {
        try {
            $azAccountObj = $azAccount | ConvertFrom-Json
            $azUser = $azAccountObj.user.name
            Write-Host "✔️ Azure CLI logged in as: $azUser" -ForegroundColor White
        }
        catch {
            Write-Host "✔️ Azure CLI is already logged in." -ForegroundColor Green
        }
    }

    # Get access token for Key Vault
    Write-Host "🔑 Acquiring Azure Key Vault access token via Azure CLI..." -ForegroundColor Cyan
    $token = az account get-access-token --resource https://vault.azure.net --query accessToken -o tsv
    if (-not $token) {
        Write-Host "❌ Failed to acquire access token from Azure CLI." -ForegroundColor Red
        exit 1
    }
    $tokenPreview = $token.Substring(0, 10) + ("...")
    Write-Host ("✔️ Access token acquired: " + $tokenPreview) -ForegroundColor Green

    # Get the file paths to sign and validate them
    Write-Host "============================================================" -ForegroundColor White

    if (-not $FilePath -or $FilePath.Count -eq 0) {
        Write-Host "📂 Please specify the file(s) to sign in the File Dialog GUI" -ForegroundColor Cyan
        # Prompt user with a GUI file selector for files to sign
        Add-Type -AssemblyName System.Windows.Forms
        $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
        $openFileDialog.Title = "Select file(s) to sign"
        $openFileDialog.Filter = "All files (*.*)|*.*"
        $openFileDialog.Multiselect = $true
        $null = $openFileDialog.ShowDialog()
        $filePaths = $openFileDialog.FileNames
    }
    else {
        $filePaths = $FilePath
    }

    if ($filePaths.Count -eq 0) {
        Write-Host "❌ No files selected." -ForegroundColor Red
        exit 1
    }

    # Validate all files
    $validFiles = @()
    $invalidFiles = @()
    foreach ($file in $filePaths) {
        if (-not (Test-Path $file)) {
            Write-Host "❌ File not found: $file" -ForegroundColor Red
            $invalidFiles += $file
        }
        else {
            $fullPath = (Resolve-Path $file).ProviderPath
            $validFiles += $fullPath
        }
    }

    # If -FilePath param is used and any file is invalid, exit immediately
    if ($FilePath -and $FilePath.Count -gt 0 -and $invalidFiles.Count -gt 0) {
        Write-Host "❌ One or more provided file paths were not found. No files will be signed." -ForegroundColor Red
        exit 1
    }

    if ($validFiles.Count -eq 0) {
        Write-Host "❌ No valid files to sign." -ForegroundColor Red
        exit 1
    }

    # List selected files and ask to proceed (only if using GUI)
    Write-Host "`nThe following files will be signed:" -ForegroundColor Red
    for ($i = 0; $i -lt $validFiles.Count; $i++) {
        # Print a numbered list of the files to be signed.
        # Uses PowerShell's string formatting operator (-f):
        #   "  [{0}] {1}" -f ($i+1), $validFiles[$i]
        #   {0} is replaced with the file number (starting from 1),
        #   {1} is replaced with the file path.
        Write-Host ("  [{0}] {1}" -f ($i + 1), $validFiles[$i]) -ForegroundColor White
    }

    $skipConfirmation = $FilePath -and $FilePath.Count -gt 0
    if (-not $skipConfirmation) {
        $proceed = Read-Host -Prompt "`nProceed with signing these files? (Y/N)"
        if ($proceed -notin @('Y', 'y', 'Yes', 'yes')) {
            Write-Host "Operation cancelled by user." -ForegroundColor Red
            exit 0
        }
    }

    # Sign each valid file
    foreach ($FileToSign in $validFiles) {
        Write-Host "`n📜 Signing file: $FileToSign" -ForegroundColor Cyan
        $signCommand = @(
            "azuresigntool sign",
            "-kvu `"$KeyVaultUri`"",
            "-kvc `"$CertificateName`"",
            "-kva `"$token`"",
            "-tr `"$TimestampUrl`"",
            "-td sha256",
            "`"$FileToSign`""
        ) -join ' '
        Invoke-Expression $signCommand
    }
    Write-Host "✔️ Finished!" -ForegroundColor Green
    pause
}
finally {
    # Restore to original directory if it was changed
    if ($changedDir) {
        Set-Location $originalPath
    }
}
