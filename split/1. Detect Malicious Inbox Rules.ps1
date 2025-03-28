# Detect Malicious Inbox Rules

# Ensure required modules are installed and imported
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) { 
    Install-Module Microsoft.Graph -Scope CurrentUser -Force 
}
Import-Module Microsoft.Graph

if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) { 
    Install-Module ExchangeOnlineManagement -Force -AllowClobber 
}
Import-Module ExchangeOnlineManagement

# Connect to Microsoft Graph and Exchange Online
Connect-MgGraph -Scopes "Mail.Read", "MailboxSettings.Read"
Connect-ExchangeOnline

# Set investigation window (last 7 days) and internal domains list
$StartDate = (Get-Date).AddDays(-7).ToString("yyyy-MM-ddTHH:mm:ssZ")
$EndDate = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
$InternalDomains = @("contoso.com", "company.local")  # Update with your domains

Write-Host " Detecting malicious inbox rules with external forwarding..." -ForegroundColor Yellow

# Get all mailboxes and scan inbox rules
$mailboxes = Get-Mailbox -ResultSize Unlimited
foreach ($mailbox in $mailboxes) {
    try {
        $rules = Get-InboxRule -Mailbox $mailbox.UserPrincipalName
        foreach ($rule in $rules) {
            if ($rule.ForwardTo -or $rule.ForwardAsAttachmentTo -or $rule.RedirectTo) {
                $recipients = @()
                if ($rule.ForwardTo) { $recipients += $rule.ForwardTo }
                if ($rule.ForwardAsAttachmentTo) { $recipients += $rule.ForwardAsAttachmentTo }
                if ($rule.RedirectTo) { $recipients += $rule.RedirectTo }

                # Check if recipient email domain is not in the internal domains list
                $externalRecipients = $recipients | Where-Object { 
                    if ($_ -match "SMTP:") { 
                        $email = $_ -replace "^SMTP:" -replace "^smtp:"
                        $domain = $email.Split("@")[1]
                        return -not ($InternalDomains -contains $domain)
                    } else { return $false }
                }
                
                if ($externalRecipients) {
                    Write-Host "[WARNING] $($mailbox.UserPrincipalName) - Rule '$($rule.Name)' forwards externally:" -ForegroundColor Red
                    Write-Host "          Recipients: $($externalRecipients -join ', ')" -ForegroundColor Red
                }
            }
        }
    } catch {
        Write-Host "[ERROR] Could not process mailbox $($mailbox.UserPrincipalName): $_" -ForegroundColor DarkYellow
    }
}

Write-Host "[INFO] Scan completed." -ForegroundColor Green