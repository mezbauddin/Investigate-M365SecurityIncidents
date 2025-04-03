# Recover Lost Intelligence by Identifying Critical Emails Deletion

# Prompt user for the period (7, 30, 90, 180 days)
$validPeriods = @("7", "30", "90", "180")
do {
    $selectedPeriod = Read-Host "Enter the reporting period in days (7, 30, 90, 180)"
} while ($selectedPeriod -notin $validPeriods)
# Convert period to integer
$selectedPeriod = [int]$selectedPeriod
# Set time range
$startDate = (Get-Date).AddDays(-$selectedPeriod)
$endDate = Get-Date
# Fetch MailItemsAccessed events
$logEntries = Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate -Operations MailItemsAccessed -ResultSize 5000
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
$report | Export-Csv -Path "SuspiciousMailAccessReport.csv" -NoTypeInformation

Write-Host "Report generated: SuspiciousMailAccessReport.csv" -ForegroundColor Green
