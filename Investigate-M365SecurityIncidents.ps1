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
    Connect-MgGraph -Scopes "AuditLog.Read.All", "Mail.Read", "MailboxSettings.Read", "User.ReadWrite.All", "Mail.ReadBasic"
    Write-Host "[SUCCESS] Connected to Microsoft Graph!" -ForegroundColor Green
    
    # Connect to Exchange Online
    Write-Host "Connecting to Exchange Online..." -ForegroundColor Cyan
    try {
        # Check if EXO V2 module is available
        if (!(Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
            Write-Host "[WARNING] Exchange Online Management module not found. Installing..." -ForegroundColor Yellow
            Install-Module -Name ExchangeOnlineManagement -Force -AllowClobber
        }
        
        # Import the module
        Import-Module ExchangeOnlineManagement
        
        # Connect to Exchange Online
        Connect-ExchangeOnline
        Write-Host "[SUCCESS] Connected to Exchange Online!" -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR] Failed to connect to Exchange Online: $_" -ForegroundColor Red
    }
}

# --[Retrieve internal domains from tenant]--
function Get-InternalDomains {
    Write-Host "Retrieving internal accepted domains..." -ForegroundColor Cyan
    try {
        $domains = Get-AcceptedDomain
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
    Write-Host "[INFO] Investigating incidents from $StartDate to $EndDate..."
}

# --[1. Detect malicious inbox rules forwarding externally]--
function Detect-MaliciousInboxRules {
    Write-Host "`n[SCANNING] Detecting inbox rules with external forwarding..." -ForegroundColor Yellow
    $foundMaliciousRules = $false
    
    try {
        # Get all mailboxes
        $mailboxes = Get-Mailbox -ResultSize Unlimited
        
        foreach ($mailbox in $mailboxes) {
            try {
                # Get inbox rules for the mailbox
                $rules = Get-InboxRule -Mailbox $mailbox.UserPrincipalName
                
                foreach ($rule in $rules) {
                    # Check for external forwarding
                    if ($rule.ForwardTo -or $rule.ForwardAsAttachmentTo -or $rule.RedirectTo) {
                        $recipients = @()
                        if ($rule.ForwardTo) { $recipients += $rule.ForwardTo }
                        if ($rule.ForwardAsAttachmentTo) { $recipients += $rule.ForwardAsAttachmentTo }
                        if ($rule.RedirectTo) { $recipients += $rule.RedirectTo }
                        
                        # Determine external recipients based on internal domains list
                        $externalRecipients = $recipients | Where-Object {
                            if ($_ -match "SMTP:") {
                                $email = $_ -replace "^SMTP:" -replace "^smtp:"
                                $domain = $email.Split("@")[1]
                                # If the domain is NOT in our retrieved internal domains, flag it as external
                                return -not ($Global:InternalDomains -contains $domain)
                            }
                            else {
                                return $false
                            }
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
function Detect-UnusualEmailVolume {
    Write-Host "`n[SCANNING] Checking for unusual outbound email volume..." -ForegroundColor Yellow
    
    try {
        $Uri = "https://graph.microsoft.com/v1.0/reports/getEmailActivityUserDetail(period='D7')"
        $outputPath = "$env:TEMP\email_activity_$(Get-Date -Format 'yyyyMMddHHmmss').csv"
        
        # Use OutputFilePath parameter to handle CSV response
        Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputFilePath $outputPath
        
        if (Test-Path $outputPath) {
            $parsed = Import-Csv $outputPath
            $highVolumeSenders = $parsed | Where-Object { 
                [int]::TryParse($_.SendCount, [ref]$null) -and [int]$_.SendCount -gt 100 
            }
            
            if ($highVolumeSenders) {
                foreach ($sender in $highVolumeSenders) {
                    Write-Host "[WARNING] $($sender.UserPrincipalName) sent $($sender.SendCount) emails in last 7 days." -ForegroundColor Red
                }
            } else {
                Write-Host "[INFO] No users with unusual email volume detected." -ForegroundColor Green
            }
            
            # Clean up temp file
            Remove-Item $outputPath -Force -ErrorAction SilentlyContinue
        } else {
            Write-Host "[ERROR] Failed to retrieve email activity report." -ForegroundColor Red
        }
    } catch {
        Write-Host "[ERROR] Error retrieving email volume data: $_" -ForegroundColor Red
    }
}

# --[3. Monitor mailbox permission changes]--
function Detect-MailboxPermissionChanges {
    Write-Host "`n[SCANNING] Checking for mailbox permission changes..." -ForegroundColor Yellow
    
    try {
        $Uri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=activityDisplayName eq 'Update mailbox permissions' and activityDateTime ge $StartDate and activityDateTime le $EndDate"
        $results = Invoke-MgGraphRequest -Uri $Uri
        
        if ($results.value.Count -gt 0) {
            foreach ($record in $results.value) {
                Write-Host "[WARNING] $($record.activityDateTime) - $($record.initiatedBy.user.userPrincipalName) updated mailbox permissions." -ForegroundColor Red
            }
        } else {
            Write-Host "[INFO] No mailbox permission changes detected in the specified time period." -ForegroundColor Green
        }
    } catch {
        Write-Host "[ERROR] Error checking mailbox permission changes: $_" -ForegroundColor Red
    }
}

# --[4. Detect deleted critical emails]--
function Detect-CriticalEmailDeletion {
    Write-Host "`n[SCANNING] Detecting critical email deletions..." -ForegroundColor Yellow
    
    # Prompt for the mailbox to check
    $mailbox = Read-Host "Enter the email address to check for deleted items (e.g., ceo@company.com)"
    
    if ([string]::IsNullOrWhiteSpace($mailbox)) {
        Write-Host "[ERROR] No email address provided. Skipping check." -ForegroundColor Red
        return
    }
    
    try {
        $Uri = "https://graph.microsoft.com/v1.0/users/$mailbox/mailFolders/deletedItems/messages"
        $deleted = Invoke-MgGraphRequest -Uri $Uri
        
        if ($deleted.value.Count -gt 0) {
            foreach ($msg in $deleted.value) {
                Write-Host "[WARNING] Deleted: $($msg.subject) | $($msg.receivedDateTime)" -ForegroundColor Red
            }
        } else {
            Write-Host "[INFO] No deleted emails found in the specified mailbox." -ForegroundColor Green
        }
    } catch {
        Write-Host "[ERROR] Error checking deleted emails: $_" -ForegroundColor Red
    }
}

# --[5. Automatically block compromised users]--
function Block-CompromisedUser {
    param (
        [string]$UserPrincipalName
    )
    
    if ([string]::IsNullOrWhiteSpace($UserPrincipalName)) {
        Write-Host "[ERROR] No user specified. Skipping block operation." -ForegroundColor Red
        return
    }
    
    Write-Host "`n[SECURITY] Blocking user: $UserPrincipalName" -ForegroundColor Yellow
    
    try {
        Update-MgUser -UserId $UserPrincipalName -AccountEnabled:$false
        Write-Host "[SUCCESS] User blocked successfully." -ForegroundColor Green
    } catch {
        Write-Host "[ERROR] Failed to block user: $_" -ForegroundColor Red
    }
}

# --[6. Detect large mailbox exports]--
function Detect-MailboxExportEvents {
    Write-Host "`n[SCANNING] Checking for suspicious mailbox exports..." -ForegroundColor Yellow
    
    try {
        $Uri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=activityDisplayName eq 'Export mailbox' and activityDateTime ge $StartDate and activityDateTime le $EndDate"
        $results = Invoke-MgGraphRequest -Uri $Uri
        
        if ($results.value.Count -gt 0) {
            foreach ($log in $results.value) {
                Write-Host "[WARNING] Export: $($log.initiatedBy.user.userPrincipalName) exported mailbox at $($log.activityDateTime)" -ForegroundColor Red
            }
        } else {
            Write-Host "[INFO] No mailbox export events detected in the specified time period." -ForegroundColor Green
        }
    } catch {
        Write-Host "[ERROR] Error checking mailbox export events: $_" -ForegroundColor Red
    }
}

# --[Menu]--
function Show-Menu {
    Write-Host "`n==== Exchange Security Investigation Menu ====" -ForegroundColor Cyan
    Write-Host "1. Detect malicious inbox rules"
    Write-Host "2. Find users sending unusual volumes of emails"
    Write-Host "3. Monitor mailbox permission changes"
    Write-Host "4. Check if critical emails were deleted"
    Write-Host "5. Block compromised user"
    Write-Host "6. Detect suspicious mailbox exports"
    Write-Host "7. Exit"
}

# --[Main Script Execution]--
Connect-ToServices
# Retrieve internal domains dynamically from the tenant
Get-InternalDomains
Set-InvestigationWindow -Days 7

do {
    Show-Menu
    $choice = Read-Host "Select an option (1-7)"
    switch ($choice) {
        1 { Detect-MaliciousInboxRules }
        2 { Detect-UnusualEmailVolume }
        3 { Detect-MailboxPermissionChanges }
        4 { Detect-CriticalEmailDeletion }
        5 {
            $userToBlock = Read-Host "Enter UPN of user to block"
            Block-CompromisedUser -UserPrincipalName $userToBlock
        }
        6 { Detect-MailboxExportEvents }
        7 { 
            # Disconnect from services
            try {
                Disconnect-ExchangeOnline -Confirm:$false
                Disconnect-MgGraph
                Write-Host "[SUCCESS] Successfully disconnected from all services." -ForegroundColor Green
            } catch {
                Write-Host "[WARNING] Error during disconnect: $_" -ForegroundColor Yellow
            }
            Write-Host "Exiting. Stay secure!" -ForegroundColor Green 
        }
        default { Write-Host "[ERROR] Invalid choice. Try again." -ForegroundColor Red }
    }
} while ($choice -ne 7)
