# Investigo.ps1
# Author: Mezba Uddin | MVP | https://mrmicrosoft.com
# Description:
#   This interactive script performs security investigations on Exchange Online by:
#   - Connecting to Microsoft Graph API and Exchange Online.
#   - Dynamically retrieving the tenant's accepted internal domains.
#   - Scanning for malicious inbox rules that forward emails to external domains.
#   - Checking for unusual outbound email volume.
#   - Monitoring mailbox permission changes.
#   - Detecting deletion of critical emails.
#   - Blocking compromised user accounts.
#   - Detecting suspicious mailbox export events.
#
#   The script uses dynamic retrieval of internal domains to avoid hard-coded values,
#   ensuring that any changes in tenant domains are automatically accounted for.
#
#   Run the script and use the menu to select the desired security investigation action.

# --[Pre-flight: Check and Install Required Modules]--
function Install-RequiredModules {
    # Check if Exchange Online Management module is installed
    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        Write-Host "Installing Exchange Online Management module..." -ForegroundColor Yellow
        Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
    }
    
    # Check if Microsoft Graph module is installed
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
        Write-Host "Installing Microsoft Graph module..." -ForegroundColor Yellow
        Install-Module Microsoft.Graph -Scope CurrentUser -Force
    }
}

# --[Connect to Services]--
function Connect-ToServices {
    # Import necessary modules
    Import-Module ExchangeOnlineManagement
    Import-Module Microsoft.Graph
    
    # Connect to Exchange Online
    Write-Host "Connecting to Exchange Online..." -ForegroundColor Cyan
    Connect-ExchangeOnline -ShowBanner:$false
    
    # Connect to Microsoft Graph
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    Connect-MgGraph -Scopes "User.ReadWrite.All", "Directory.ReadWrite.All", "Reports.Read.All"
}

# --[Get Internal Domains]--
function Get-InternalDomains {
    # Get all accepted domains in the tenant
    $global:domains = Get-AcceptedDomain | Select-Object -ExpandProperty DomainName
    Write-Host "Retrieved $(($global:domains | Measure-Object).Count) internal domains for security analysis" -ForegroundColor Green
}

# --[Date Selection]--
function Get-DateSelectionFromUser {
    # Prompt user for the period (7, 30, 90 days - max 90 days)
    $validPeriods = @("7", "30", "90")
    do {
        $selectedPeriod = Read-Host "Enter the reporting period in days (7, 30, 90)"
    } while ($selectedPeriod -notin $validPeriods)
    
    return [int]$selectedPeriod
}

# --[Feature 1: Detect Malicious Inbox Rules]--
function Detect-MaliciousInboxRules {
    Write-Host "`n=== DETECTING MALICIOUS INBOX RULES ===" -ForegroundColor Cyan
    
    # Initialize counters
    $totalRulesChecked = 0
    $suspiciousRulesFound = 0
    
    # Get all mailboxes
    [array]$mailboxes = Get-ExoMailbox -ResultSize Unlimited | Select-Object -ExpandProperty PrimarySmtpAddress
    Write-Host "Scanning $(($mailboxes | Measure-Object).Count) mailboxes for suspicious forwarding rules..." -ForegroundColor Cyan
    
    foreach ($mbx in $mailboxes) {
        [array]$rules = Get-InboxRule -Mailbox $mbx
        $totalRulesChecked += ($rules | Measure-Object).Count
        
        $maliciousRules = $rules | Where-Object {
            ($_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo) -and
            @($_.ForwardTo, $_.ForwardAsAttachmentTo, $_.RedirectTo | Where-Object { $_ -ne $null }).Count -gt 0 -and
            @($_.ForwardTo, $_.ForwardAsAttachmentTo, $_.RedirectTo | Where-Object {
                $address = $_ -replace ".*SMTP:|\]|>", "" -replace "<", ""
                if ($address -match "@") {
                    $domain = $address.Split("@")[1]
                    $domain -and ($global:domains -notcontains $domain)
                } else {
                    $false
                }
            }).Count -gt 0
        }
        
        if ($maliciousRules.Count -gt 0) {
            $suspiciousRulesFound += $maliciousRules.Count
            Write-Host "ALERT: Suspicious forwarding rules found in $mbx" -ForegroundColor Red
            $maliciousRules | Format-Table Name, ForwardTo, ForwardAsAttachmentTo, RedirectTo -AutoSize
        }
    }
    
    Write-Host "`nScan Complete: Checked $totalRulesChecked rules across $($mailboxes.Count) mailboxes" -ForegroundColor Cyan
    if ($suspiciousRulesFound -eq 0) {
        Write-Host "Result: No suspicious forwarding rules detected. Your environment looks clean!" -ForegroundColor Green
    } else {
        Write-Host "Result: Found $suspiciousRulesFound suspicious forwarding rules that require investigation" -ForegroundColor Red
    }
}

# --[Feature 2: Identify Anomalous Outbound Email Volumes]--
function Find-AnomalousEmailVolume {
    Write-Host "`n=== IDENTIFYING ANOMALOUS OUTBOUND EMAIL VOLUMES ===" -ForegroundColor Cyan
    
    # Get date selection from user
    $selectedPeriod = Get-DateSelectionFromUser
    
    # Construct the API URL based on the selected period
    $uri = "https://graph.microsoft.com/v1.0/reports/getEmailActivityUserDetail(period='D$selectedPeriod')"
    
    Write-Host "Retrieving email activity report for the past $selectedPeriod days..." -ForegroundColor Cyan
    
    # Define output file path
    $outputPath = "$env:TEMP\email_activity_${selectedPeriod}days.csv"
    
    # Invoke the API request and save data to a CSV file
    Invoke-MgGraphRequest -Method GET -Uri $uri -OutputFilePath $outputPath
    
    # Threshold for high email volume (Adjust if needed)
    $threshold = 100
    
    Write-Host "Analyzing data for users sending more than $threshold emails in the past $selectedPeriod days..." -ForegroundColor Cyan
    
    # Import and filter email data
    $emailData = Import-Csv $outputPath
    [array]$HighVolumeSenders = $emailData | Where-Object {
        [int]::TryParse($_.'Send Count', [ref]$null) -and [int]$_.'Send Count' -gt $threshold
    } | Sort-Object { [int]$_.'Send Count' } -Descending
    
    # Display results
    if ($HighVolumeSenders.Count -gt 0) {
        Write-Host "`nFound $($HighVolumeSenders.Count) users sending high volumes of email (>$threshold)" -ForegroundColor Yellow
        $HighVolumeSenders | Format-Table 'User Principal Name', @{Name="Sent";Expression={$_.'Send Count'}}, 'Last Activity Date' -AutoSize
    } else {
        Write-Host "`nNo users found sending more than $threshold emails in the past $selectedPeriod days" -ForegroundColor Green
    }
    
    # Remove temporary file
    Remove-Item $outputPath -Force -ErrorAction SilentlyContinue
    
    Write-Host "Analysis complete" -ForegroundColor Cyan
}

# --[Feature 3: Monitor Mailbox Permission Changes]--
function Monitor-MailboxPermissions {
    Write-Host "`n=== MONITORING MAILBOX PERMISSION CHANGES ===" -ForegroundColor Cyan
    
    # Get date selection from user
    $selectedPeriod = Get-DateSelectionFromUser
    
    Write-Host "`nChecking for mailbox permission changes in the last $selectedPeriod days... Please wait." -ForegroundColor Cyan
    
    # Define time range
    $StartDate = (Get-Date).AddDays(-$selectedPeriod)
    $EndDate = Get-Date
    
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
}

# --[Feature 4: Check for Deleted Critical Emails]--
function Check-DeletedCriticalEmails {
    Write-Host "`n=== CHECKING FOR DELETED CRITICAL EMAILS ===" -ForegroundColor Cyan
    
    # Get date selection from user
    $selectedPeriod = Get-DateSelectionFromUser
    
    # Set time range
    $startDate = (Get-Date).AddDays(-$selectedPeriod)
    $endDate = Get-Date
    
    # Fetch MailItemsAccessed events
    Write-Host "Retrieving mail access audit logs for the past $selectedPeriod days..." -ForegroundColor Cyan
    $logEntries = Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate -Operations MailItemsAccessed -ResultSize 5000
    
    Write-Host "Processing $($logEntries.Count) log entries..." -ForegroundColor Yellow
    
    # Process data and extract relevant details
    $report = $logEntries | ForEach-Object {
        $record = $_.AuditData | ConvertFrom-Json
        [PSCustomObject]@{
            MailboxOwner = $record.MailboxOwnerUPN
            AccessedBy = $record.UserId
            AccessTime = $record.CreationTime
            ClientApp = $record.ClientAppId
            AccessLocation = $record.ClientIPAddress
            AccessCount = 1
            RiskLevel = if ($record.ClientIPAddress -match '185\.220|194\.88') { 'High' } elseif ($record.ClientIPAddress -match '102\.54') { 'Medium' } else { 'Low' }
        }
    } | Group-Object -Property MailboxOwner, AccessedBy, ClientApp, AccessLocation | ForEach-Object {
        $entry = $_.Group[0]
        $entry.AccessCount = $_.Count
        $entry
    }
    
    # Export results to CSV
    $reportPath = "$env:USERPROFILE\Desktop\SuspiciousMailAccessReport.csv"
    $report | Export-Csv -Path $reportPath -NoTypeInformation
    
    Write-Host "Results: Found $($report.Count) mail access events" -ForegroundColor Yellow
    $report | Format-Table -AutoSize
    Write-Host "Report exported to: $reportPath" -ForegroundColor Green
}

# --[Feature 5: Detect Suspicious Mailbox Exports]--
function Detect-SuspiciousMailboxExports {
    Write-Host "`n=== DETECTING SUSPICIOUS MAILBOX EXPORTS ===" -ForegroundColor Cyan
    
    # Get date selection from user
    $selectedPeriod = Get-DateSelectionFromUser
    
    Write-Host "Scanning for mailbox export activities in the last $selectedPeriod days..." -ForegroundColor Cyan
    
    # Set time window and parameters
    $StartDate = (Get-Date).AddDays(-$selectedPeriod).ToUniversalTime()
    $EndDate = (Get-Date).ToUniversalTime()
    $exportActivities = @("New-MailboxExportRequest", "New-ComplianceSearchAction")
    $SessionId = [guid]::NewGuid().ToString()
    $ResultSize = 5000
    $allExports = @()
    
    try {
        Write-Host "Retrieving audit logs..." -ForegroundColor Yellow
        
        # Initial search parameters
        $searchParams = @{
            StartDate = $StartDate
            EndDate = $EndDate
            Operations = $exportActivities
            ResultSize = $ResultSize
            SessionId = $SessionId
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
                            # Match either New-MailboxExportRequest or New-ComplianceSearchAction with 'Export' & 'Format' in Parameters
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
            $allExports |
                Select-Object @{N="Date";E={ $_.CreationDate.ToString("yyyy-MM-dd HH:mm") }},
                              @{N="Actor";E={ if ($_.UserIds) { $_.UserIds[0] } else { "System" } }},
                              @{N="Action";E={ $_.Operation }},
                              @{N="Target";E={ $_.ObjectId }} |
                Sort-Object Date -Descending |
                Format-Table -AutoSize
            
            Write-Host "`nRecommended security actions:`n1. Verify that each export operation was authorized and legitimate.`n2. For suspicious exports, determine what data was exported and by whom.`n3. Review or implement approval processes for mailbox exports." -ForegroundColor Yellow
        } else {
            Write-Host "`nNo mailbox export activities detected in the specified time period." -ForegroundColor Green
        }
    } catch [System.Management.Automation.CommandNotFoundException] {
        Write-Host "Error: Search-UnifiedAuditLog cmdlet not found. Connect to Exchange Online first." -ForegroundColor Red
    } catch {
        Write-Host "Error: $_" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
    }
}

# --[Feature 6: Block Compromised User]--
function Block-CompromisedUser {
    Write-Host "`n=== BLOCKING COMPROMISED USER ===" -ForegroundColor Cyan
    
    # Ask for the compromised user's email
    $userUPN = Read-Host "Enter the compromised user's email address"
    Write-Host "Taking immediate security actions for user: $userUPN" -ForegroundColor Red
    
    # Option 1: Block user account
    Write-Host "1. Blocking user account..." -ForegroundColor Yellow
    Update-MgUser -UserId $userUPN -AccountEnabled:$false
    Write-Host "   Account successfully disabled" -ForegroundColor Green
    
    # Option 2: Reset user password and force change at next login
    Write-Host "2. Resetting password..." -ForegroundColor Yellow
    $newPassword = -join ((33..126) | Get-Random -Count 16 | ForEach-Object { [char]$_ })
    Update-MgUser -UserId $userUPN -PasswordProfile @{
        Password = $newPassword
        ForceChangePasswordNextSignIn = $true
    }
    Write-Host "   Password reset successful. New temporary password: $newPassword" -ForegroundColor Green
    Write-Host "   IMPORTANT: Document this password securely!" -ForegroundColor Red
    
    # Option 3: Revoke all active sessions
    Write-Host "3. Revoking all active sessions..." -ForegroundColor Yellow
    Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/users/$userUPN/revokeSignInSessions"
    Write-Host "   All sessions terminated successfully" -ForegroundColor Green
    
    # Additional checks
    Write-Host "`nRunning security checks and retrieving recent sign-in activity..." -ForegroundColor Cyan
    Get-MgAuditLogSignIn -Filter "userPrincipalName eq '$userUPN'" -Top 5 |
        Select-Object CreatedDateTime, AppDisplayName, IpAddress, @{N="Status";E={$_.Status.ErrorCode}} |
        Format-Table -AutoSize
    
    Write-Host "`nRecommended next steps:" -ForegroundColor Yellow
    Write-Host "1. Check for suspicious inbox rules: Get-InboxRule -Mailbox $userUPN" -ForegroundColor Cyan
    Write-Host "2. Check for mail forwarding: Get-Mailbox $userUPN | Select-Object ForwardingAddress,ForwardingSmtpAddress" -ForegroundColor Cyan
    Write-Host "3. Document all actions taken in this security incident" -ForegroundColor Cyan
}

# --[Menu]--
function Show-Menu {
    Write-Host "`n==== Exchange Security Investigation Menu ====" -ForegroundColor Cyan
    Write-Host "1. Detect malicious inbox rules"
    Write-Host "2. Find users sending unusual volumes of emails"
    Write-Host "3. Monitor mailbox permission changes"
    Write-Host "4. Check if critical emails were deleted"
    Write-Host "5. Detect suspicious mailbox exports"
    Write-Host "6. Block compromised user"
    Write-Host "7. Exit"
}

# --[Main Script Execution]--
function Main {
    # Check and install required modules
    Install-RequiredModules
    
    # Connect to services
    Connect-ToServices
    
    # Get internal domains
    Get-InternalDomains
    
    # Main menu loop
    $exit = $false
    while (-not $exit) {
        Show-Menu
        $choice = Read-Host "`nEnter selection (1-7)"
        
        switch ($choice) {
            "1" { Detect-MaliciousInboxRules }
            "2" { Find-AnomalousEmailVolume }
            "3" { Monitor-MailboxPermissions }
            "4" { Check-DeletedCriticalEmails }
            "5" { Detect-SuspiciousMailboxExports }
            "6" { Block-CompromisedUser }
            "7" { $exit = $true; Write-Host "Exiting Investigo..." -ForegroundColor Cyan }
            default { Write-Host "Invalid selection. Please try again." -ForegroundColor Yellow }
        }
    }
}

# Start the script
Main
