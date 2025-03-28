# Detect Malicious Inbox Rules
Connect-MgGraph -Scopes "Mail.ReadWrite"
Connect-ExchangeOnline

# Track statistics
$totalMailboxes = 0
$totalRulesChecked = 0
$suspiciousRulesFound = 0

# Get your organization's domains to identify internal domains
$domains = Get-AcceptedDomain | Select-Object -ExpandProperty DomainName
$mailboxes = Get-Mailbox -ResultSize Unlimited | Select-Object -ExpandProperty PrimarySmtpAddress
Write-Host "Scanning $(($mailboxes | Measure-Object).Count) mailboxes for suspicious forwarding rules..." -ForegroundColor Cyan

foreach ($mbx in $mailboxes) {
    $totalMailboxes++
    $rules = Get-InboxRule -Mailbox $mbx
    $totalRulesChecked += ($rules | Measure-Object).Count
    
    $maliciousRules = $rules | Where-Object {
        ($_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo) -and
        @($_.ForwardTo, $_.ForwardAsAttachmentTo, $_.RedirectTo | Where-Object {$_}).Count -gt 0 -and
        @($_.ForwardTo, $_.ForwardAsAttachmentTo, $_.RedirectTo | Where-Object {$_} | 
            ForEach-Object {
                $address = $_ -replace ".*SMTP:|\]|>","" -replace "<",""
                $domain = $address.Split("@")[1]
                $domains -notcontains $domain 
            }
        ).Count -gt 0
    }
    
    if ($maliciousRules.Count -gt 0) {
        $suspiciousRulesFound += $maliciousRules.Count
        Write-Host "ALERT: Suspicious forwarding rules found in $mbx" -ForegroundColor Red
        $maliciousRules | Format-Table Name, ForwardTo, ForwardAsAttachmentTo, RedirectTo -AutoSize
    }
}

# Show summary
Write-Host "`nScan Complete: Checked $totalRulesChecked rules across $totalMailboxes mailboxes" -ForegroundColor Cyan
if ($suspiciousRulesFound -eq 0) {
    Write-Host "Result: No suspicious forwarding rules detected. Your environment looks clean!" -ForegroundColor Green
} else {
    Write-Host "Result: Found $suspiciousRulesFound suspicious forwarding rules that require investigation" -ForegroundColor Red
}