# Recover Lost Intelligence by Identifying Critical Emails Deletion

function  Get-MailboxAccess {
    try {
        Write-Host "`n[SCANNING] Scanning for Suspicious Mailbox Access this may take some time..." -ForegroundColor Yellow
        # Fetch MailItemsAccessed events
        $logEntries = Search-UnifiedAuditLog -StartDate $Global:StartDate  -EndDate $Global:EndDate -Operations MailItemsAccessed -ResultSize 5000
        # Process data and extract relevant details
        $report = $logEntries | ForEach-Object {
            $record = $_.AuditData | ConvertFrom-Json
            [PSCustomObject]@{
                MailboxOwner   = $record.MailboxOwnerUPN
                AccessedBy     = $record.UserId
                AccessTime     = $record.CreationTime
                ClientApp      = $record.ClientAppId
                AccessLocation = $record.ClientIPAddress
                AccessCount    = 1
                RiskLevel      = if ($record.ClientIPAddress -match '185\.220|194\.88') { 'High' } elseif ($record.ClientIPAddress -match '102\.54') { 'Medium' } else { 'Low' }
            }
        } | Group-Object -Property MailboxOwner, AccessedBy, ClientApp, AccessLocation | ForEach-Object {
            $entry = $_.Group[0]
            $entry.AccessCount = $_.Count
            $entry
        }
        # Export results to CSV
        $report | Export-Csv -Path "SuspiciousMailAccessReport.csv" -NoTypeInformation

        Write-Host "Report generated: SuspiciousMailAccessReport.csv" -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR] Suspicious Mailbox Access : $_" -ForegroundColor Red
    }
}
