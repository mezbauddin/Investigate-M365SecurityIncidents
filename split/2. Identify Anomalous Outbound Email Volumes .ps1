# Identify Anomalous Outbound Email Volumes
# Connect to Microsoft Graph API
Connect-MgGraph -Scopes "Reports.Read.All"

Write-Host "Retrieving email activity report for the past 7 days..." -ForegroundColor Cyan

# Get email activity report for past 7 days
$outputPath = "$env:TEMP\email_activity.csv"
Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/reports/getEmailActivityUserDetail(period='D7')" -OutputFilePath $outputPath

# Import and analyze the data (adjust threshold as needed)
$threshold = 100  # Adjust this number based on your organization's normal patterns
Write-Host "Analyzing data for users sending more than $threshold emails in the past week..." -ForegroundColor Cyan

$emailData = Import-Csv $outputPath
$highVolumeSenders = $emailData | Where-Object { 
    [int]::TryParse($_.SendCount, [ref]$null) -and [int]$_.SendCount -gt $threshold 
} | Sort-Object { [int]$_.SendCount } -Descending

# Display results
if ($highVolumeSenders.Count -gt 0) {
    Write-Host "`nFound $($highVolumeSenders.Count) users sending high volumes of email (>$threshold)" -ForegroundColor Yellow
    $highVolumeSenders | Format-Table UserPrincipalName, @{Name="Sent";Expression={$_.SendCount}}, LastActivityDate -AutoSize
} else {
    Write-Host "`nNo users found sending more than $threshold emails in the past week" -ForegroundColor Green
}

# Clean up
Remove-Item $outputPath -Force -ErrorAction SilentlyContinue
Write-Host "Analysis complete" -ForegroundColor Cyan

# Optional: Export results to CSV for further analysis
# $highVolumeSenders | Export-Csv "$env:USERPROFILE\Desktop\HighVolumeSenders.csv" -NoTypeInformation