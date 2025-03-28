-- Block a Compromised User -- 

Ensure required module is installed and imported 

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) { Install-Module Microsoft.Graph -Scope CurrentUser -Force } Import-Module Microsoft.Graph 

Connect to Microsoft Graph 

Connect-MgGraph -Scopes "User.ReadWrite.All" 

Prompt for the user UPN to block 

$UserPrincipalName = Read-Host "Enter the UPN of the user to block (e.g., user@contoso.com)" if ([string]::IsNullOrWhiteSpace($UserPrincipalName)) { Write-Host "No user specified. Exiting." -ForegroundColor Red return } 

Write-Host "🚫 Blocking user: $UserPrincipalName..." -ForegroundColor Yellow 

try { Update-MgUser -UserId $UserPrincipalName -AccountEnabled:$false Write-Host "✅ User blocked successfully." -ForegroundColor Green } catch { Write-Host "❌ Failed to block user: $_" -ForegroundColor Red } 