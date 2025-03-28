-- Spot Privilege Escalations in Mailbox Permissions -- 

Ensure required module is installed and imported 

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) { Install-Module Microsoft.Graph -Scope CurrentUser -Force } Import-Module Microsoft.Graph 

Connect to Microsoft Graph 

Connect-MgGraph -Scopes "AuditLog.Read.All" 

Set investigation window (last 7 days) 

$StartDate = (Get-Date).AddDays(-7).ToString("yyyy-MM-ddTHH:mm:ssZ") $EndDate = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ") 

Write-Host "🔐 Checking for mailbox permission changes..." -ForegroundColor Yellow 

Build query URL (adjust the activityDisplayName if needed) 

$Uri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=activityDisplayName eq 'Update mailbox permissions' and activityDateTime ge $StartDate and activityDateTime le $EndDate" $results = Invoke-MgGraphRequest -Uri $Uri 

if ($results.value.Count -gt 0) { foreach ($record in $results.value) { Write-Host "⚠️ $($record.activityDateTime) - $($record.initiatedBy.user.userPrincipalName) updated mailbox permissions." -ForegroundColor Red } } else { Write-Host "No mailbox permission changes detected in the specified time period." -ForegroundColor Green } 

 