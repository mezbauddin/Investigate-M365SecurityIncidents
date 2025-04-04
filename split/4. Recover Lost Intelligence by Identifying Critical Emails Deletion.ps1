# Recover Lost Intelligence by Identifying Critical Emails Deletion

# Check if Exchange Online Management module is installed. If not, install it for the current user without prompting
if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
    }
    Import-Module ExchangeOnlineManagement
    Connect-ExchangeOnline -ShowBanner:$false
    # Prompt user for the period (7, 30, 90, 180 days)
    $validPeriods = @(&quot;7&quot;, &quot;30&quot;, &quot;90&quot;, &quot;180&quot;)
    do {
    $selectedPeriod = Read-Host &quot;Enter the reporting period in days (7, 30, 90, 180)&quot;
    } while ($selectedPeriod -notin $validPeriods)
    # Convert period to integer
    
    $selectedPeriod = [int]$selectedPeriod
    # Set time range
    $startDate = (Get-Date).AddDays(-$selectedPeriod)
    $endDate = Get-Date
    # Fetch MailItemsAccessed events
    $logEntries = Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate -Operations MailItemsAccessed -
    ResultSize 5000
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
    RiskLevel = if ($record.ClientIPAddress -match &#39;185\.220|194\.88&#39;) { &#39;High&#39; } elseif ($record.ClientIPAddress -
    match &#39;102\.54&#39;) { &#39;Medium&#39; } else { &#39;Low&#39; }
    }
    } | Group-Object -Property MailboxOwner, AccessedBy, ClientApp, AccessLocation | ForEach-Object {
    $entry = $_.Group[0]
    $entry.AccessCount = $_.Count
    $entry
    }
    # Export results to CSV
    $report | Export-Csv -Path &quot;SuspiciousMailAccessReport.csv&quot; -NoTypeInformation
    Write-Host &quot;Report generated: SuspiciousMailAccessReport.csv&quot; -ForegroundColor Green