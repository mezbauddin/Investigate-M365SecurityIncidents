# Spot Privilege Escalations in Mailbox Permissions


function Get-MailboxPermissionChanges {
    Write-Host "`n[SCANNING] Checking for mailbox permission changes..." -ForegroundColor Yellow
    try {
        $UriBase = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits"
        $Filter = "?`$filter=activityDisplayName eq 'Update mailbox permissions' and activityDateTime ge $($Global:StartDate) and activityDateTime le $($Global:EndDate)&`$orderby=activityDateTime desc&`$top=1000"
        $Headers = @{ "ConsistencyLevel" = "eventual" }

        $allResults = @()
        $nextLink = "$UriBase$Filter"

        do {
            $response = Invoke-MgGraphRequest -Uri $nextLink -Headers $Headers -ErrorAction Stop
            $allResults += $response.value
            $nextLink = $response.'@odata.nextLink'
        } while ($nextLink)

        if ($allResults.Count -gt 0) {
            $uniqueResults = $allResults | Sort-Object targetResources -Unique

            $formatted = $uniqueResults | Sort-Object activityDateTime | ForEach-Object {
                $targetResource = $_.targetResources[0]
                $target = if ($targetResource.userPrincipalName) {
                    $targetResource.userPrincipalName
                } elseif ($targetResource.displayName) {
                    $targetResource.displayName
                } else {
                    "Unknown"
                }

                [PSCustomObject]@{
                    Date   = $_.activityDateTime
                    Actor  = $_.initiatedBy.user.userPrincipalName
                    Action = $_.activityDisplayName
                    Target = $target
                }
            }

            Write-Host "`n[INFO] Found $($formatted.Count) mailbox permission change events in the selected time frame:`n" -ForegroundColor Cyan
            $formatted | Format-Table -AutoSize

            $csvPath = "MailboxPermissionChanges_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            $formatted | Export-Csv -Path $csvPath -NoTypeInformation
            Write-Host "`n[EXPORT] Audit log exported to: $csvPath" -ForegroundColor Green
        }
        else {
            Write-Host "[INFO] No mailbox permission changes detected in the specified time period." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "[ERROR] Error checking mailbox permission changes: $_" -ForegroundColor Red
    }
}
