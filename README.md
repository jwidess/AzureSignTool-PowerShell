# AzureSignTool PowerShell Signing Scripts

These PowerShell scripts are used for easily signing files with AzureSignTool and a, in our case HSM-backed, certificate in Azure Key Vault. For our use case we acquired an EVCS cert from SSLTrust.com and followed their guides to setup our certificate, which [can be found here](https://www.ssltrust.com.au/help/setup-guides/code-signing-on-azure-key-vault-with-signtool).

## Script Versions & Authentication Methods

This repository currently provides two script versions for different authentication scenarios:

### 1. `AST-SecretBased.ps1` (Client Secret Authentication)
- This method is based on the example given by SSLTrust in their tutorial linked above.
- Uses a Microsoft Entra ID (Azure AD) Application Client Secret for authentication.
- The client secret is stored in Windows Credential Manager (WCM).
- Suitable for automated, service, or CI/CD scenarios where interactive login is not possible.

### 2. `AST-Interactive.ps1` (Azure CLI Authentication)
- This is my **preferred method as** session-based authentication and Microsoft's Entra/Azure account requirements enforce MFA, providing added security.
- Uses Azure CLI for interactive authentication.
- No client secret is required; relies on the user's Azure CLI session.
- Suitable for interactive use, especially for users who already use Azure CLI.

## Features
- Supports both interactive (GUI) and automated (parameterized) file selection
- Signs one or multiple files in a single run
- Validates prerequisites, credentials, and file paths

## Requirements
- PowerShell 7+
- [AzureSignTool](https://github.com/vcsjones/AzureSignTool) (install via WinGet: `winget install AzureSignTool`)
- Access to Azure Key Vault and a certificate to sign with
- For `AST-SecretBased.ps1`: Microsoft Entra ID Application with a generated Client Secret
- For `AST-Interactive.ps1`: [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) (install via WinGet: `winget install --exact --id Microsoft.AzureCLI`)

## Usage

### **1. `AST-SecretBased.ps1` (Client Secret)**

#### Replace Placeholder Values:
Before running the script, edit `AST-SecretBased.ps1` and replace the placeholder values for your environment:
- `$ClientId` (Azure AD Application ID)
- `$TenantId` (Azure AD Tenant ID)
- `$KeyVaultUri` (Key Vault URI)
- `$CertificateName` (Certificate name in Key Vault)
- `$TimestampUrl` (Timestamp server URL)

Update these with your actual Azure and certificate details before use.

### Interactive (GUI) Mode
Run the script without parameters to select files using a file dialog:
```powershell
.\AST-SecretBased.ps1
```
- On first run, you will be prompted for your Azure client secret (stored securely in WCM for future use).
- Select one or more files to sign in the GUI dialog.
- Review the list and confirm to proceed with signing.

### Automated/Scripted Mode
Pass one or more file paths directly using the `-FilePath` parameter:
```powershell
.\AST-SecretBased.ps1 -FilePath "C:\Path\To\File1.exe","C:\Path\To\File2.dll"
```
- The script will skip the GUI and confirmation prompt, and sign the specified files directly.
- If any file is not found, the script will exit and not sign any files.

### **2. `AST-Interactive.ps1` (Azure CLI)**

#### Replace Placeholder Values:
Before running the script, edit `AST-Interactive.ps1` and replace the placeholder values for your environment:
- `$KeyVaultUri` (Key Vault URI)
- `$CertificateName` (Certificate name in Key Vault)
- `$TimestampUrl` (Timestamp server URL)

### Interactive (GUI) Mode
Run the script without parameters to select files using a file dialog:
```powershell
.\AST-Interactive.ps1
```
- On first run, you will be prompted to sign in to Azure CLI (if not already signed in).
- Select one or more files to sign in the GUI dialog.
- Review the list and confirm to proceed with signing.

### Automated/Scripted Mode
Pass one or more file paths directly using the `-FilePath` parameter:
```powershell
.\AST-Interactive.ps1 -FilePath "C:\Path\To\File1.exe","C:\Path\To\File2.dll"
```
- The script will skip the GUI and confirmation prompt, and sign the specified files directly.
- If any file is not found, the script will exit and not sign any files.

## Security
- For `AST-SecretBased.ps1`, the Azure client secret is stored securely in Windows Credential Manager and never written to disk in plain text. The secret must be exactly 40 characters long. The script will show a preview of the first 5 characters of the stored secret for verification.
- For `AST-Interactive.ps1`, authentication is handled by Azure CLI and no client secret is required.


## Troubleshooting
- Ensure AzureSignTool is installed and available in your PATH.
- For `AST-Interactive.ps1`, ensure Azure CLI is installed and you are signed in.
- Make sure you have access to the Azure Key Vault and the required certificate.