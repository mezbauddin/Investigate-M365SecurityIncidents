# Recover Lost Intelligence by Identifying Critical Emails Deletion
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Mail.Read"

# Replace with actual email address
$mailbox = "user@yourdomain.com"
Write-Host "Checking deleted items for mailbox: $mailbox" -ForegroundColor Cyan

# Get count of deleted items
$countUri = "https://graph.microsoft.com/v1.0/users/$mailbox/mailFolders/deletedItems/messages?`$count=true"
$countResponse = Invoke-MgGraphRequest -Uri $countUri -Headers @{"ConsistencyLevel"="eventual"}
Write-Host "Found $($countResponse.'@odata.count') total deleted items" -ForegroundColor Cyan

# Get deleted emails (top 50)
Write-Host "Retrieving the 50 most recent deleted emails..." -ForegroundColor Cyan
$baseUri = "https://graph.microsoft.com/v1.0/users/$mailbox/mailFolders/deletedItems/messages?`$top=50&`$select=id,subject,receivedDateTime,sender,importance,hasAttachments&`$orderby=receivedDateTime desc"
$deletedEmails = (Invoke-MgGraphRequest -Uri $baseUri).value

# Display results in table format
if ($deletedEmails.Count -gt 0) {
    Write-Host "`nDisplaying $($deletedEmails.Count) recently deleted emails:" -ForegroundColor Yellow
    $deletedEmails | Select-Object @{N="Date";E={[DateTime]::Parse($_.receivedDateTime).ToString("yyyy-MM-dd HH:mm")}},
                                 @{N="From";E={$_.sender.emailAddress.address}},
                                 @{N="Subject";E={$_.subject}},
                                 @{N="Attachments";E={$_.hasAttachments}} | 
                Format-Table -AutoSize
    
    Write-Host "`nRecovery instructions:" -ForegroundColor Green
    Write-Host "1. User can recover these from Deleted Items folder in Outlook" -ForegroundColor Green
    Write-Host "2. Select items and use Move > Other Folder to restore them" -ForegroundColor Green
} else {
    Write-Host "`nNo deleted emails found for this mailbox." -ForegroundColor Green
}

Write-Host "`nScan complete. Optional: To filter by keyword, add this to URI:" -ForegroundColor Cyan
Write-Host "&`$filter=contains(subject,'keyword') or contains(bodyPreview,'keyword')" -ForegroundColor Gray