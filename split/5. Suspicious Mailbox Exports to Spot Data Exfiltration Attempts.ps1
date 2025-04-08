function Get-MailboxExportEvents {
    Write-Host "`n[SCANNING] Checking for suspicious mailbox exports..." -ForegroundColor Yellow
    # Optional UPN filter prompt (leave blank for all)
    $filterUPN = Read-Host "Enter UPN to filter export events (leave blank for all)"
    try {
        $searchParams = @{
            StartDate      = $Global:StartDate
            EndDate        = $Global:EndDate
            Operations     = @("New-MailboxExportRequest", "New-ComplianceSearchAction")
            ResultSize     = 5000
            SessionId      = [guid]::NewGuid().ToString()
            SessionCommand = "ReturnLargeSet"
            ErrorAction    = "Stop"
        }
        $allExports = @()
        $batch = Search-UnifiedAuditLog @searchParams
        do {
            if ($batch -and $batch.Count -gt 0) {
                Write-Host "Processing batch of $($batch.Count) records..." -ForegroundColor Yellow
                foreach ($record in $batch) {
                    if ($record.AuditData) {
                        try {
                            $auditData = $record.AuditData | ConvertFrom-Json -ErrorAction Stop
                            if ($record.Operation -eq "New-MailboxExportRequest" -or 
                                ($record.Operation -eq "New-ComplianceSearchAction" -and 
                                $auditData.Parameters -match 'Export' -and 
                                $auditData.Parameters -match 'Format')) {
                                if (-not [string]::IsNullOrWhiteSpace($filterUPN)) {
                                    if ($record.initiatedBy.user.userPrincipalName -eq $filterUPN) {
                                        $record | Add-Member -MemberType NoteProperty -Name "ParsedAuditData" -Value $auditData -Force -PassThru -ErrorAction Stop
                                        $allExports += $record
                                    }
                                }
                                else {
                                    $record | Add-Member -MemberType NoteProperty -Name "ParsedAuditData" -Value $auditData -Force -PassThru -ErrorAction Stop
                                    $allExports += $record
                                }
                            }
                        }
                        catch {
                            Write-Host "Warning: Could not parse AuditData for record ID: $($record.Id)" -ForegroundColor Yellow
                        }
                    }
                }
                if ($batch.Count -eq $searchParams.ResultSize) {
                    $searchParams['SessionCommand'] = "ReturnNextPage"
                    $batch = Search-UnifiedAuditLog @searchParams
                }
                else {
                    $batch = $null
                }
            }
        } while ($batch -and $batch.Count -gt 0)
        
        if ($allExports.Count -gt 0) {
            Write-Host "`nDETECTED $($allExports.Count) EXPORT OPERATIONS:" -ForegroundColor Red
            $allExports |
            Select-Object @{N = "Date"; E = { $_.CreationDate.ToString("yyyy-MM-dd HH:mm") } },
            @{N = "Actor"; E = { if ($_.UserIds) { $_.UserIds[0] } else { "System" } } },
            @{N = "Action"; E = { $_.Operation } },
            @{N = "Target"; E = { $_.ObjectId } } |
            Sort-Object Date -Descending |
            Format-Table -AutoSize
            Write-Host "`nRecommended security actions:`n1. Verify that each export operation was authorized and legitimate.`n2. For suspicious exports, determine what data was exported and by whom.`n3. Review or implement approval processes for mailbox exports." -ForegroundColor Yellow
        }
        else {
            Write-Host "`nNo mailbox export activities detected in the specified time period." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "[ERROR] Error checking mailbox export events: $_" -ForegroundColor Red
    }
}
