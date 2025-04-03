# Spot Privilege Escalations in Mailbox Permissions

# Prompt user for the period (7, 30, 90 days)
$validPeriods = @("7", "30", "90")
do {
    $selectedPeriod = Read-Host "Enter the reporting period in days (7, 30, 90)"
} while ($selectedPeriod -notin $validPeriods)
Write-Host "`nChecking for mailbox permission changes in the last $selectedPeriod days... Please wait." -ForegroundColor Cyan
# Define time range
$StartDate = (Get-Date).AddDays(-[int]$selectedPeriod)
$EndDate   = Get-Date
# Define relevant mailbox permission operations to search for
$permissionActivities = @(
    "Add-MailboxPermission", "Remove-MailboxPermission", "Set-MailboxPermission",
    "Add-MailboxFolderPermission", "Remove-MailboxFolderPermission", "Set-MailboxFolderPermission"
)
# Perform the audit log search
Write-Host "`nQuerying audit logs...." -ForegroundColor Yellow
[array]$allPermissionChanges = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations $permissionActivities -ResultSize 5000 
Write-Host "`nSearch complete. Processing results..." -ForegroundColor Cyan
# Display results
if ($allPermissionChanges.Count -gt 0) {
    Write-Host "`nFound $($allPermissionChanges.Count) mailbox permission change events in the last $selectedPeriod days:" -ForegroundColor Yellow
    
    $allPermissionChanges | Select-Object @{
        Name="Date"; Expression={ $_.CreationDate.ToString("yyyy-MM-dd HH:mm") }
    }, @{
        Name="Actor"; Expression={ if ($_.UserIds) { ($_.UserIds -join ", ") } else { "System" } }
    }, @{
        Name="Action"; Expression={ $_.Operations }
    }, @{
        Name="Target"; Expression={ ($_ | Select-Object -ExpandProperty auditdata | ConvertFrom-Json).ObjectId }
    } | Format-Table -AutoSize
} else {
    Write-Host "`nNo mailbox permission changes detected in the last $selectedPeriod days." -ForegroundColor Green
}
Write-Host "`nScan complete." -ForegroundColor Cyan
