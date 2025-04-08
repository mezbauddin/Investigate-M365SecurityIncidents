# Detect Malicious Inbox Rules


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
