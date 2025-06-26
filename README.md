# AzureSignTool PowerShell Signing Scripts

These PowerShell scripts are used for signing files with Azure Key Vault and an HSM-backed certificate in the cloud. For our use case we acquired an EVCS cert from SSLTrust.com and followed their guides which [can be found here](https://www.ssltrust.com.au/help/setup-guides/code-signing-on-azure-key-vault-with-signtool).

## Features
- Securely manages Azure client secret using Windows Credential Manager (WCM)
- Supports both interactive (GUI) and automated (parameterized) file selection
- Signs one or multiple files in a single run
- Validates client secret and file paths for security and reliability

## Requirements
- PowerShell 7+
- [AzureSignTool](https://github.com/vcsjones/AzureSignTool) (install via WinGet: `winget install AzureSignTool`)
- Access to Azure Key Vault via a unique Client Secret (From a Microsoft Entra ID Application)

## Usage

### Replace Placeholder Values
Before running the script, open `AST-SecretBased.ps1` and replace the placeholder values for your environment:
- `$ClientId` (Azure AD Application ID)
- `$TenantId` (Azure AD Tenant ID)
- `$KeyVaultUri` (Key Vault URI)
- `$CertificateName` (Certificate name in Key Vault)
- `$TimestampUrl` (Timestamp server URL)

Example values are provided as comments in the script. Update these with your actual Azure and certificate details before use.

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

## Security
- The Azure client secret is stored securely in Windows Credential Manager and never written to disk in plain text.
- The secret must be exactly 40 characters long.
- The script will show a preview of the first 5 characters of the stored secret for verification.

## Release Notes
Can be found at the top of the PS1 file.

## Troubleshooting
- If you see errors about missing modules, try running PowerShell as Administrator.
- Ensure AzureSignTool is installed and available in your PATH.
- Make sure you have access to the Azure Key Vault and the required certificate.