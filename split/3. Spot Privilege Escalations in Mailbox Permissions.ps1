# Spot Privilege Escalations in Mailbox Permissions

$periods = @("7", "30", "90")
do { $days = Read-Host "Enter reporting period in days (7, 30, 90)" } while ($days -notin $periods)

$start = (Get-Date).AddDays(-[int]$days)
$end = Get-Date
$ops = @(
    "Add-MailboxPermission", "Remove-MailboxPermission", "Set-MailboxPermission",
    "Add-MailboxFolderPermission", "Remove-MailboxFolderPermission", "Set-MailboxFolderPermission"
)
Write-Host "`nSearching mailbox permission changes for the last $days days..." -ForegroundColor Cyan
$sessionId = [guid]::NewGuid().ToString()
$cmd = "Initialize"
$results = @()
do {
    $batch = Search-UnifiedAuditLog -StartDate $start -EndDate $end -Operations $ops `
        -ResultSize 5000 -SessionId $sessionId -SessionCommand $cmd
    if ($batch) {
        $results += $batch
        $cmd = "ReturnNextPreviewPage"
    }
} while ($batch.Count -eq 5000)
if ($results.Count -gt 0) {
    Write-Host "`nFound $($results.Count) permission change events. Displaying and exporting..." -ForegroundColor Yellow
    $parsed = $results | ForEach-Object {
        $data = $_.AuditData | ConvertFrom-Json
        [PSCustomObject]@{
            Date       = $_.CreationDate.ToString("yyyy-MM-dd HH:mm")
            Actor      = if ($_.UserIds) { ($_.UserIds -join ", ") } else { "System" }
            Action     = ($_.Operations -join ", ")
            Target     = $data.ObjectId
            Cmdlet     = $data.Operation
            Parameters = ($data.Parameters | ConvertTo-Json -Compress)
        }
    }
    $parsed | Format-Table -AutoSize
    $parsed | Export-Csv -Path "MailboxPermissionChanges.csv" -NoTypeInformation -Encoding UTF8
    Write-Host "`nExported to 'MailboxPermissionChanges.csv'" -ForegroundColor Green
} else {
    Write-Host "`nNo permission changes found." -ForegroundColor Green
}
Write-Host "`nMailbox permission audit completed successfully." -ForegroundColor Cyan
