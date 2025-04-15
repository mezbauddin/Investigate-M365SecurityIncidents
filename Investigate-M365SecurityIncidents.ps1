# Investigate-ExchangeSecurityIncidents.ps1
# Author: Mezba Uddin | MVP | https://mrmicrosoft.com
# Description:
#   This interactive script performs security investigations on Exchange Online by:
#   - Connecting to Microsoft Graph API and Exchange Online.
#   - Dynamically retrieving the tenant’s accepted internal domains.
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

# --[Pre-flight: Connect to Graph and Exchange Online]--
function Connect-ToServices {
    Write-Host "Connecting to Microsoft Graph API..." -ForegroundColor Cyan
    try {
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    }
    catch {
        Write-Host "[WARNING] Microsoft Graph Authentication module not found. Installing..." -ForegroundColor Yellow
        Install-Module -Name Microsoft.Graph.Authentication -Force -AllowClobber
        Import-Module Microsoft.Graph.Authentication
    }
    try {
        Connect-MgGraph -Scopes "AuditLog.Read.All", "Mail.Read", "MailboxSettings.Read", "User.ReadWrite.All", "Mail.ReadBasic", "UserAuthenticationMethod.ReadWrite.All" -NoWelcome -ErrorAction Stop
        Write-Host "[SUCCESS] Connected to Microsoft Graph!" -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR] Failed to connect to Microsoft Graph: $_" -ForegroundColor Red
        
    }
}
    
# Connect to Exchange Online
Write-Host "Connecting to Exchange Online..." -ForegroundColor Cyan
try {
    Import-Module ExchangeOnlineManagement -ErrorAction Stop
}
catch {
    Write-Host "[WARNING] Exchange Online Management module not found. Installing..." -ForegroundColor Yellow
    Install-Module -Name ExchangeOnlineManagement -Force -AllowClobber
    Import-Module ExchangeOnlineManagement
}
try {
    # Connect to Exchange Online with recommended parameters
    Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
    Write-Host "[SUCCESS] Connected to Exchange Online!" -ForegroundColor Green
}
catch {
    Write-Host "[ERROR] Failed to connect to Exchange Online: $_" -ForegroundColor Red
}


# --[Retrieve internal domains from tenant]--
function Get-InternalDomains {
    Write-Host "Retrieving internal accepted domains..." -ForegroundColor Cyan
    try {
        $domains = Get-AcceptedDomain -ErrorAction Stop
        $internalDomains = @()
        foreach ($domain in $domains) {
            $internalDomains += $domain.DomainName
        }
        $Global:InternalDomains = $internalDomains
        Write-Host "[SUCCESS] Retrieved internal domains: $($Global:InternalDomains -join ', ')" -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR] Failed to retrieve internal domains: $_" -ForegroundColor Red
    }
}

# --[Set investigation window]--
function Set-InvestigationWindow {
    param ([int]$Days = 7)
    $Global:StartDate = (Get-Date).AddDays(-$Days).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $Global:EndDate = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $Global:days = $Days
    Write-Host "[INFO] Investigating incidents from $Global:StartDate to $Global:EndDate..."
}


# --[1. Detect malicious inbox rules forwarding externally]--
function Get-MaliciousInboxRules {
    Write-Host "`n[SCANNING] Detecting inbox rules with external forwarding..." -ForegroundColor Yellow
    $foundMaliciousRules = $false
    try {
        Get-InternalDomains
        $mailboxes = Get-ExoMailbox -Filter "RecipientTypeDetails -eq 'UserMailbox' -or RecipientTypeDetails -eq 'SharedMailbox'" -ResultSize Unlimited -ErrorAction Stop
        foreach ($mailbox in $mailboxes) {
            try {
                $rules = Get-InboxRule -Mailbox $mailbox.UserPrincipalName -ErrorAction Stop
                foreach ($rule in $rules) {
                    if ($rule.ForwardTo -or $rule.ForwardAsAttachmentTo -or $rule.RedirectTo) {
                        $recipients = @()
                        if ($rule.ForwardTo) { $recipients += $rule.ForwardTo }
                        if ($rule.ForwardAsAttachmentTo) { $recipients += $rule.ForwardAsAttachmentTo }
                        if ($rule.RedirectTo) { $recipients += $rule.RedirectTo }
                        $externalRecipients = $recipients | Where-Object {
                            if ($_ -match "SMTP:") {
                                $email = $_ -replace "^SMTP:" -replace "^smtp:"
                                $domain = $email.Split("@")[1]
                                return -not ($Global:InternalDomains -contains $domain)
                            }
                            else { return $false }
                        }
                        if ($externalRecipients) {
                            Write-Host "[WARNING] [$($mailbox.UserPrincipalName)] - Malicious rule: $($rule.Name)" -ForegroundColor Red
                            Write-Host "          Forwarding to external recipients: $($externalRecipients -join ', ')" -ForegroundColor Red
                            $foundMaliciousRules = $true
                        }
                    }
                }
                Write-Host "[INFO] Checked rules for $($mailbox.UserPrincipalName)" -ForegroundColor Green
            }
            catch {
                Write-Host "[ERROR] Could not check rules for $($mailbox.UserPrincipalName): $_" -ForegroundColor DarkYellow
                continue
            }
        }
    }
    catch {
        Write-Host "[ERROR] Failed to retrieve mailboxes: $_" -ForegroundColor Red
    }
    if (-not $foundMaliciousRules) {
        Write-Host "[INFO] No malicious forwarding rules detected." -ForegroundColor Green
    }
}

# --[2. Detect users sending large volumes of mail]--
function Get-UnusualEmailVolume {
    Write-Host "`n[SCANNING] Checking for unusual outbound email volume..." -ForegroundColor Yellow
    try {
        $Uri = "https://graph.microsoft.com/v1.0/reports/getEmailActivityUserDetail(period='D$Global:days')"
        Write-Host $Uri "here"
        $outputPath = "$env:TEMP\email_activity_$(Get-Date -Format 'yyyyMMddHHmmss').csv"
        Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputFilePath $outputPath -ErrorAction Stop
        if (Test-Path $outputPath) {
            $parsed = Import-Csv $outputPath
            $highVolumeSenders = $parsed | Where-Object { 
                [int]::TryParse($_.SendCount, [ref]$null) -and [int]$_.SendCount -gt 100 
            }
            if ($highVolumeSenders) {
                foreach ($sender in $highVolumeSenders) {
                    Write-Host "[WARNING] $($sender.UserPrincipalName) sent $($sender.SendCount) emails in last ($Global:days) days." -ForegroundColor Red
                }
            }
            else {
                Write-Host "[INFO] No users with unusual email volume detected." -ForegroundColor Green
            }
            Remove-Item $outputPath -Force -ErrorAction SilentlyContinue
        }
        else {
            Write-Host "[ERROR] Failed to retrieve email activity report." -ForegroundColor Red
        }
    }
    catch {
        Write-Host "[ERROR] Error retrieving email volume data: $_" -ForegroundColor Red
    }
}

# --[3. Monitor mailbox permission changes]--
function Get-MailboxPermissionChanges {
    $ops = @(
        "Add-MailboxPermission", "Remove-MailboxPermission", "Set-MailboxPermission",
        "Add-MailboxFolderPermission", "Remove-MailboxFolderPermission", "Set-MailboxFolderPermission"
    )
    Write-Host "`nSearching mailbox permission changes from $Global:StartDate to $Global:EndDate..." -ForegroundColor Cyan
    $sessionId = [guid]::NewGuid().ToString()
    $cmd = "Initialize"
    $results = @()
    do {
        $batch = Search-UnifiedAuditLog -StartDate $Global:StartDate -EndDate $Global:EndDate -Operations $ops `
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
}


# --[Feature 4: Check for Suspicious Mailbox Access--
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


# --[5. Detect large mailbox exports]--
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




# --[6. Automatically block compromised users]--
function Block-CompromisedUser {
    param (
        [string]$userUPN
    )
    if ([string]::IsNullOrWhiteSpace($userUPN)) {
        Write-Host "[ERROR] No user specified. Skipping block operation." -ForegroundColor Red
        return
    }
    Write-Host "`n[SECURITY] Blocking user: $userUPN" -ForegroundColor Yellow
    try {
        Write-Host "Taking immediate security actions for user: $userUPN" -ForegroundColor Red

        # Option 1: Block user account
        Write-Host "1. Blocking user account..." -ForegroundColor Yellow
        Update-MgUser -UserId $userUPN -AccountEnabled:$false
        Write-Host "   Account successfully disabled" -ForegroundColor Green

        # Option 2: Reset user password and force change at next login
        Write-Host "2. Resetting password..." -ForegroundColor Yellow
        $newPassword = -join ((33..126) | Get-Random -Count 16 | ForEach-Object { [char]$_ })
        Update-MgUser -UserId $userUPN -PasswordProfile @{
            Password                      = $newPassword
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
        Select-Object CreatedDateTime, AppDisplayName, IpAddress, @{N = "Status"; E = { $_.Status.ErrorCode } } | 
        Format-Table -AutoSize

        Write-Host "`nRecommended next steps:" -ForegroundColor Yellow
        Write-Host "1. Check for suspicious inbox rules: Get-InboxRule -Mailbox $userUPN" -ForegroundColor Cyan
        Write-Host "2. Check for mail forwarding: Get-Mailbox $userUPN | Select-Object ForwardingAddress,ForwardingSmtpAddress" -ForegroundColor Cyan
        Write-Host "3. Document all actions taken in this security incident" -ForegroundColor Cyan
    }
    catch {
        Write-Host "[ERROR] Failed to block user: $_" -ForegroundColor Red
    }
}

# --[Menu]--
function Show-Menu {
    # Exchange Security Investigation Tool
    Write-Host "`n===================================" -ForegroundColor Cyan
    Write-Host "Exchange Security Investigation Tool" -ForegroundColor Cyan
    Write-Host "===================================" -ForegroundColor Cyan

    Write-Host "`n1. Detect malicious inbox rules" -ForegroundColor Yellow
    Write-Host "2. Find users sending unusual volumes of emails" -ForegroundColor Yellow
    Write-Host "3. Monitor mailbox permission changes" -ForegroundColor Yellow
    Write-Host "4. Detect Suspicious Mailbox Access" -ForegroundColor Yellow
    Write-Host "5. Detect suspicious mailbox exports" -ForegroundColor Yellow
    Write-Host "6. Block compromised user" -ForegroundColor Yellow
    Write-Host "7. Execute All" -ForegroundColor Yellow
    Write-Host "8. Exit" -ForegroundColor Yellow
}

# --[Main Script Execution]--
Connect-ToServices


# Prompt for investigation window in days (default 7)
$validPeriods = @("7", "15", "30")
$daysInput = Read-Host "Enter the reporting period in days (7, 15, 30) This will be used as period in all Modules if needed"
if ([string]::IsNullOrWhiteSpace($daysInput)) {
    $daysInput = 7
}
else {
    if ($validPeriods -notcontains $daysInput) {
        Write-Host "[WARNING] Invalid period. Using default 7 days." -ForegroundColor Yellow
        $daysInput = 7
    }
    else {
        $daysInput = [int]$daysInput
    }
}
Set-InvestigationWindow -Days $daysInput



$Modules = @{
    1 = { Get-MaliciousInboxRules }
    2 = { Get-UnusualEmailVolume }
    3 = { Get-MailboxPermissionChanges }
    4 = { Get-MailboxAccess }
    5 = { Get-MailboxExportEvents }
    6 = {
        $userToBlock = Read-Host "Enter UPN of user to block"
        Block-CompromisedUser -userUPN $userToBlock
    }
    7 = {
        foreach ($key in 1..5) { & $Modules[$key] }
        $userToBlock = Read-Host "Enter UPN of user to block"
        Block-CompromisedUser -userUPN $userToBlock
    }
    8 = {
        try {
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction Stop
            Disconnect-MgGraph -ErrorAction Stop
            Write-Host "[SUCCESS] Successfully disconnected from all services." -ForegroundColor Green
        }
        catch {
            Write-Host "[WARNING] Error during disconnect: $_" -ForegroundColor Yellow
        }
        Write-Host "Exiting. Stay secure!" -ForegroundColor Green 
        exit
    }
}

do {
    Show-Menu
    $choice = [int](Read-Host "Select an option (1-8)")
    
    if ($Modules.ContainsKey($choice)) {
        & $Modules[$choice]
    }
    else {
        Write-Host "[ERROR] Invalid choice. Try again." -ForegroundColor Red
    }

} while ($choice -ne 8)

