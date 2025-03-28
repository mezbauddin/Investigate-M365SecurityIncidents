# Detect Suspicious Mailbox Exports
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "AuditLog.Read.All"

Write-Host "Scanning for mailbox export activities in the last 7 days..." -ForegroundColor Cyan

# Set time period variables (7 days)
$StartDate = (Get-Date).AddDays(-7).ToString("yyyy-MM-ddTHH:mm:ssZ")
$EndDate = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")

# Check for mailbox exports (run for each activity type)
$exportActivities = @("Export mailbox", "Export mailbox content", "New-MailboxExportRequest", 
                    "Start-MailboxExportRequest", "Export eDiscovery search results")
Write-Host "Monitoring for these activities: $($exportActivities -join ', ')" -ForegroundColor Cyan

# Get all export activities in one variable
$allExports = @()
foreach ($activity in $exportActivities) {
    Write-Host "Checking for: $activity..." -ForegroundColor Gray
    $encodedActivity = [System.Web.HttpUtility]::UrlEncode("'$activity'")
    $Uri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=activityDisplayName eq $encodedActivity and activityDateTime ge $StartDate and activityDateTime le $EndDate"
    $results = Invoke-MgGraphRequest -Uri $Uri
    if ($results.value.Count -gt 0) {
        Write-Host "  Found $($results.value.Count) instances" -ForegroundColor Yellow
        $allExports += $results.value
    }
}

# Display results in a simple table
if ($allExports.Count -gt 0) {
    Write-Host "`nDETECTED $($allExports.Count) EXPORT OPERATIONS:" -ForegroundColor Red
    $allExports | Sort-Object activityDateTime -Descending | 
        Select-Object @{N="Date";E={($_.activityDateTime -as [DateTime]).ToString("yyyy-MM-dd HH:mm")}},
                     @{N="User";E={$_.initiatedBy.user.userPrincipalName}},
                     activityDisplayName,
                     @{N="Target";E={$_.targetResources.displayName -join ", "}} |
        Format-Table -AutoSize
    
    Write-Host "`nRecommended security actions:" -ForegroundColor Yellow
    Write-Host "1. Verify these exports were authorized" -ForegroundColor Cyan
    Write-Host "2. Check what data was exported" -ForegroundColor Cyan
    Write-Host "3. Consider implementing mailbox export approval process" -ForegroundColor Cyan
} else {
    Write-Host "`nNo mailbox export activities detected in the specified time period." -ForegroundColor Green
}

Write-Host "`nIf you also have Exchange Online PowerShell connected, you can check:" -ForegroundColor Cyan
Write-Host "Get-MailboxExportRequest | Get-MailboxExportRequestStatistics | Format-Table Identity,Status,FilePath,PercentComplete" -ForegroundColor Gray