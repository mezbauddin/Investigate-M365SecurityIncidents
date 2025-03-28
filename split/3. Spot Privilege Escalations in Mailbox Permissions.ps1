# Spot Privilege Escalations in Mailbox Permissions
Connect-MgGraph -Scopes "AuditLog.Read.All"

Write-Host "Checking for mailbox permission changes in the last 7 days..." -ForegroundColor Cyan

# Set time period to search (last 7 days)
$StartDate = (Get-Date).AddDays(-7).ToString("yyyy-MM-ddTHH:mm:ssZ")
$EndDate = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")

# Define activities to search (add or remove as needed)
$permissionActivities = @("Update mailbox permissions", "Add recipient permissions", "Add full access permission", "Add-MailboxPermission", "Add send as permission")
Write-Host "Searching for these permission activities: $($permissionActivities -join ', ')" -ForegroundColor Cyan

# Search for each permission activity
$allPermissionChanges = @()
foreach ($activity in $permissionActivities) {
    $encodedActivity = [System.Web.HttpUtility]::UrlEncode("'$activity'")
    $Uri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=activityDisplayName eq $encodedActivity and activityDateTime ge $StartDate and activityDateTime le $EndDate"
    $results = Invoke-MgGraphRequest -Uri $Uri
    if ($results.value.Count -gt 0) { 
        Write-Host "Found $($results.value.Count) instances of '$activity'" -ForegroundColor Yellow
        $allPermissionChanges += $results.value 
    }
}

# Display results in a table format
if ($allPermissionChanges.Count -gt 0) {
    Write-Host "`nFound $($allPermissionChanges.Count) total mailbox permission changes:" -ForegroundColor Yellow
    $allPermissionChanges | Sort-Object activityDateTime -Descending | 
        Select-Object @{N="Date";E={($_.activityDateTime -as [DateTime]).ToString("yyyy-MM-dd HH:mm")}}, 
                     @{N="User";E={if($_.initiatedBy.user.userPrincipalName){$_.initiatedBy.user.userPrincipalName}else{"System"}}}, 
                     activityDisplayName,
                     @{N="Target";E={if($_.targetResources){$_.targetResources.displayName -join ", "}else{""}}} |
        Format-Table -AutoSize
} else {
    Write-Host "`nNo mailbox permission changes detected in the last 7 days" -ForegroundColor Green
}

Write-Host "Scan complete" -ForegroundColor Cyan