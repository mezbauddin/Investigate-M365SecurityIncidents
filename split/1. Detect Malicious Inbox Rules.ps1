# Detect Malicious Inbox Rules


# Check if Exchange Online Management module is installed. If not, install it for the current user without prompting
if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
}

Import-Module ExchangeOnlineManagement

Connect-ExchangeOnline -ShowBanner:$false


$totalRulesChecked = 0; $suspiciousRulesFound = 0
[array]$domains = Get-AcceptedDomain | Select-Object -ExpandProperty DomainName 
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
                $domain -and ($domains -notcontains $domain)
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
