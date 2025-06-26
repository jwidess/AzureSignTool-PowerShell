# AST-SecretBased.ps1
# https://github.com/jwidess/AzureSignTool-PowerShell
# Author: Justin Widen
## =====================================
# This script facilitates file signing using AzureSignTool(AST) and an Azure Key Vault(AKV) stored certificate.
# It securely manages the client secret, used for auth, by storing it in Windows Credential Manager(WCM).
#
# Usage:
#   1. First run: You'll be prompted for the Azure client secret.
#   2. Subsequent runs: The secret will be retrieved automatically from WCM.
#   3. The script will then prompt for files to sign, or you can specify file paths directly via the -FilePath param.
#
# Requirements:
#   - AzureSignTool must be installed, typically with WinGet (https://github.com/vcsjones/AzureSignTool)
#   - Access to Azure Key Vault must be configured.
#
# Script Parameters:
#   -FilePath: (Optional) One or more file paths to sign. 
#       If provided, the script will sign these files directly and skip the GUI file selector and confirmation prompt.
#       Example: .\AST-SecretBased.ps1 -FilePath "C:\Path\To\File1.exe","C:\Path\To\File2.dll"
#   If -FilePath is not provided, the script will prompt with a GUI file selector and ask for confirmation before signing.
#

param(
    [Parameter(Mandatory = $false, Position = 0)]
    [string[]]$FilePath
)

#! ============================================================
# Azure Key Vault Configuration
# These values are specific to your Azure environment
$ClientId = "<CLIENT ID>"   # Azure AD Application ID
$TenantId = "<TENANT ID>"   # Azure AD Tenant ID
$KeyVaultUri = "<KEY VAULT URI>"    # Key Vault URL
$CertificateName = "<CERTIFICATE NAME>"     # Certificate name in Key Vault

# Credential Manager Configuration
$credLabel = "AzureSignTool-SecretBased"  # Unique identifier for the credential in Windows Credential Manager

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

# Install CredentialManager module if not already installed
if (-not (Get-Module -ListAvailable -Name CredentialManager)) {
    Write-Host "📥 Installing CredentialManager module..." -ForegroundColor Cyan
    try {
        Install-Module -Name CredentialManager -Force -Scope CurrentUser -ErrorAction Stop
        Write-Host "✔️ CredentialManager module installed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "❌ Failed to install CredentialManager module. Error: $_" -ForegroundColor Red
        Write-Host "💡 Try running PowerShell as Administrator and run this script again" -ForegroundColor Yellow
        exit 1
    }
}

Import-Module CredentialManager

function Get-StoredSecret {
    # Attempts to retrieve the stored credential from Windows Credential Manager
    Write-Host "🔍 Searching for credential: $credLabel" -ForegroundColor Cyan
    try {
        $cred = Get-StoredCredential -Target $credLabel
        if ($cred) {
            $plainSecret = $cred.Password | ConvertFrom-SecureString -AsPlainText
            if ($plainSecret.Length -eq 40) {
                $preview = $plainSecret.Substring(0, 5) + ('*' * 35)
                Write-Host ("✔️ Credential found successfully. Preview: " + $preview) -ForegroundColor Green
                return $plainSecret
            }
            else {
                Write-Host "❌ Stored secret is invalid (must be exactly 40 characters)." -ForegroundColor Red
                return $null
            }
        }
    }
    catch {
        Write-Host "❌ Error retrieving credential: $_" -ForegroundColor Red
    }
    Write-Host "❌ No credential found" -ForegroundColor Yellow
    return $null
}

function Set-StoredSecret {
    param(
        [Parameter(Mandatory = $true)]
        [string]$secret
    )
    if ($secret.Length -ne 40) {
        Write-Host "❌ The client secret must be exactly 40 characters long." -ForegroundColor Red
        return
    }
    # Stores the secret in Windows Credential Manager using cmdkey
    Write-Host "🔒 Storing credential..." -ForegroundColor Cyan
    cmdkey /generic:$credLabel /user:AzureClient /pass:$secret | Out-Null
    Write-Host "✔️ Credential stored successfully" -ForegroundColor Green
}

# Attempt to retrieve the stored secret
$secret = Get-StoredSecret
while (-not $secret) {
    Write-Host "`n📝 Please enter your Azure Client Secret (exactly 40 characters)" -ForegroundColor Cyan
    $secureSecret = Read-Host -Prompt "Azure Client Secret" -AsSecureString
    $plainSecret = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureSecret)
    )
    if ($plainSecret.Length -ne 40) {
        Write-Host "❌ The client secret must be exactly 40 characters long. Please try again." -ForegroundColor Red
        continue
    }
    Set-StoredSecret -secret $plainSecret
    $secret = $plainSecret
}
Write-Host "🔑 Using stored Azure client secret" -ForegroundColor Green

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
        $fullPath = (Resolve-Path $file).Path
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
        "-kvi `"$ClientId`"",
        "-kvs `"$secret`"",
        "-kvt `"$TenantId`"",
        "-tr $TimestampUrl",
        "-td sha256",
        "`"$FileToSign`""
    ) -join ' '
    Invoke-Expression $signCommand
}
Write-Host "✔️ Finished!" -ForegroundColor Green
pause
