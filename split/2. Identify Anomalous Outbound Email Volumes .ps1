# Identify Anomalous Outbound Email Volumes

#Prompt user for the period (7, 30, 90, 180 days)
$validPeriods = @("7", "30", "90", "180")
do {
    $selectedPeriod = Read-Host "Enter the reporting period in days (7, 30, 90, 180)"
} while ($selectedPeriod -notin $validPeriods)

#Construct the API URL based on the selected period
$uri = "https://graph.microsoft.com/v1.0/reports/getEmailActivityUserDetail(period='D$selectedPeriod')"

#Authenticate with Microsoft Graph (Ensure you're connected)
Connect-MgGraph -Scopes "Reports.Read.All"

Write-Host "Retrieving email activity report for the past $selectedPeriod days..." -ForegroundColor Cyan

#Define output file path
$outputPath = "$env:TEMP\email_activity_${selectedPeriod}days.csv"

#Invoke the API request and save data to a CSV file
Invoke-MgGraphRequest -Method GET -Uri $uri -OutputFilePath $outputPath

#Threshold for high email volume (Adjust if needed)
$threshold = 100

Write-Host "Analyzing data for users sending more than $threshold emails in the past $selectedPeriod days..." -ForegroundColor Cyan

#Import and filter email data
$emailData = Import-Csv $outputPath 
[array]$HighVolumeSenders = $emailData | Where-Object { 
    [int]::TryParse($_.'Send Count', [ref]$null) -and [int]$_.'Send Count' -gt $threshold 
} | Sort-Object { [int]$_.'Send Count' } -Descending

#Display results
if ($HighVolumeSenders.Count -gt 0) { 
    Write-Host "`nFound $($HighVolumeSenders.Count) users sending high volumes of email (>$threshold)" -ForegroundColor Yellow
    $HighVolumeSenders | Format-Table 'User Principal Name', @{Name="Sent";Expression={$_.'Send Count'}}, 'Last Activity Date' -AutoSize 
} else { 
    Write-Host "`nNo users found sending more than $threshold emails in the past $selectedPeriod days" -ForegroundColor Green 
}

#Remove temporary file
Remove-Item $outputPath -Force -ErrorAction SilentlyContinue 

Write-Host "Analysis complete" -ForegroundColor Cyan

# Optional: Export results to a CSV file on Desktop
#$HighVolumeSenders | Export-Csv "$env:USERPROFILE\Desktop\HighVolumeSenders_${selectedPeriod}days.csv" -NoTypeInformation
