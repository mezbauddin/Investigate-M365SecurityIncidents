# Detect Suspicious Mailbox Access

function Get-MailboxAccess {
    try {
        Write-Host "`n[SCANNING] Scanning for Suspicious Mailbox Access..." -ForegroundColor Yellow

        # Fetch MailItemsAccessed events in current window
        $logEntries = Search-UnifiedAuditLog -StartDate $Global:StartDate -EndDate $Global:EndDate -Operations MailItemsAccessed -ResultSize 5000

        # Process data and extract relevant details
        $report = $logEntries | ForEach-Object {
            try {
                $record = $_.AuditData | ConvertFrom-Json -ErrorAction Stop

                $actorType = if ($record.LogonType -eq 0) { 'Owner' }
                            elseif ($record.LogonType -eq 2) { 'Delegate' }
                            elseif ($record.LogonType -eq 3) { 'Admin' }
                            elseif ($record.LogonType -eq 4) { 'Service' }
                            else { 'Unknown' }

                $app = if ($record.ClientAppId) { $record.ClientAppId } elseif ($record.ApplicationId) { $record.ApplicationId } else { 'Unknown' }

                [PSCustomObject]@{
                    MailboxOwner   = $record.MailboxOwnerUPN
                    AccessedBy     = $record.UserId
                    AccessTime     = $record.CreationTime
                    ClientApp      = $app
                    AccessLocation = $record.ClientIPAddress
                    ActorType      = $actorType
                    AccessType     = $record.AccessType
                    AccessCount    = 1
                    RiskLevel      = if ($record.ClientIPAddress -match '185\\.220|194\\.88') { 'High' }
                                    elseif ($record.ClientIPAddress -match '102\\.54') { 'Medium' } else { 'Low' }
                }
            } catch {
                Write-Host "[WARNING] Failed to parse record: $_" -ForegroundColor DarkYellow
            }
        } | Where-Object { $_ } | Group-Object -Property MailboxOwner, AccessedBy, ClientApp, AccessLocation | ForEach-Object {
            $entry = $_.Group[0]
            $entry.AccessCount = $_.Count
            $entry
        }

        # Export results to CSV
        $report | Export-Csv -Path "SuspiciousMailAccessReport.csv" -NoTypeInformation
        Write-Host "Report generated: SuspiciousMailAccessReport.csv" -ForegroundColor Green

    } catch {
        Write-Host "[ERROR] Suspicious Mailbox Access: $_" -ForegroundColor Red
    }
}