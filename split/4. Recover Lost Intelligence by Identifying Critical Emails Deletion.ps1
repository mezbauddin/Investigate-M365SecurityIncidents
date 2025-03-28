-- Recover Lost Intelligence by Identifying Critical Emails Deletion -- 

Ensure required module is installed and imported 

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) { Install-Module Microsoft.Graph -Scope CurrentUser -Force } Import-Module Microsoft.Graph 

Connect to Microsoft Graph 

Connect-MgGraph -Scopes "Mail.Read" 

Prompt for the mailbox to check 

$mailbox = Read-Host "Enter the email address to check for deleted items (e.g., ceo@company.com)" 

if ([string]::IsNullOrWhiteSpace($mailbox)) { Write-Host "No email address provided. Exiting." -ForegroundColor Red return } 

Write-Host "🔍 Checking deleted items for $mailbox..." -ForegroundColor Yellow 

$Uri = "https://graph.microsoft.com/v1.0/users/$mailbox/mailFolders/deletedItems/messages" $deleted = Invoke-MgGraphRequest -Uri $Uri 

if ($deleted.value.Count -gt 0) { foreach ($msg in $deleted.value) { Write-Host "[WARNING] Deleted: $($msg.subject) | Received: $($msg.receivedDateTime)" -ForegroundColor Red } } else { Write-Host "No deleted emails found in $mailbox." -ForegroundColor Green } 