# Detect Suspicious Mailbox Exports

# Check if Exchange Online Management module is installed. If not, install it for the current user without prompting
if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
}

Import-Module ExchangeOnlineManagement

Connect-ExchangeOnline -ShowBanner:$false

Write-Host "Scanning for mailbox export activities in the last 7 days..." -ForegroundColor Cyan
 
# Set time window and parameters
$StartDate = (Get-Date).AddDays(-7).ToUniversalTime()
$EndDate = (Get-Date).ToUniversalTime()
$exportActivities = @("New-MailboxExportRequest", "New-ComplianceSearchAction")
$SessionId = [guid]::NewGuid().ToString()
$ResultSize = 5000
$allExports = @()
 
try {
    Write-Host "Retrieving audit logs..." -ForegroundColor Yellow
    # Initial search parameters
    $searchParams = @{
        StartDate      = $StartDate
        EndDate        = $EndDate
        Operations     = $exportActivities
        ResultSize     = $ResultSize
        SessionId      = $SessionId
        SessionCommand = "ReturnLargeSet"
    }
    # First batch with ReturnLargeSet
    $batch = Search-UnifiedAuditLog @searchParams
    # Process results with pagination
    do {
        if ($batch -and $batch.Count -gt 0) {
            Write-Host "Processing batch of $($batch.Count) records..." -ForegroundColor Yellow
            # Filter for export operations and add to collection
            foreach ($record in $batch) {
                if ($record.AuditData) {
                    try {
                        $auditData = $record.AuditData | ConvertFrom-Json
                        if ($record.Operation -eq "New-MailboxExportRequest" -or 
                            ($record.Operation -eq "New-ComplianceSearchAction" -and 
                            $auditData.Parameters -match 'Export' -and 
                            $auditData.Parameters -match 'Format')) {
                            $record | Add-Member -MemberType NoteProperty -Name "ParsedAuditData" -Value $auditData -Force -PassThru
                            $allExports += $record
                        }
                    } catch {
                        Write-Host "Warning: Could not parse AuditData for record ID: $($record.Id)" -ForegroundColor Yellow
                    }
                }
            }
            # Get next page if we have a full batch
            if ($batch.Count -eq $ResultSize) {
                $searchParams['SessionCommand'] = "ReturnNextPage"
                $batch = Search-UnifiedAuditLog @searchParams
            } else {
                $batch = $null
            }
        }
    } while ($batch -and $batch.Count -gt 0)
    # Display results
    if ($allExports.Count -gt 0) {
        Write-Host "`nDETECTED $($allExports.Count) EXPORT OPERATIONS:" -ForegroundColor Red
        $allExports | Select-Object @{N="Date";E={ $_.CreationDate.ToString("yyyy-MM-dd HH:mm") }},
                               @{N="Actor";E={ if ($_.UserIds) { $_.UserIds[0] } else { "System" } }},
                               @{N="Action";E={ $_.Operation }},
                               @{N="Target";E={ $_.ObjectId }} |
                               Sort-Object Date -Descending |
                               Format-Table -AutoSize
        Write-Host "` nRecommended security actions:`n1. Verify that each export operation was authorized and legitimate.`n2. For suspicious exports, determine what data was exported and by whom.`n3. Review or implement approval processes for mailbox exports." -ForegroundColor Yellow
    } else {
        Write-Host "`nNo mailbox export activities detected in the specified time period." -ForegroundColor Green
    }
} catch [System.Management.Automation.CommandNotFoundException] {
    Write-Host "Error: Search-UnifiedAuditLog cmdlet not found. Connect to Exchange Online first." -ForegroundColor Red
} catch {
    Write-Host "Error: $_" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
}
