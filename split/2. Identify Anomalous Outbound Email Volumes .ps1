-- Identify Anomalous Outbound Email Volumes -- 

Ensure required module is installed and imported 

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) { Install-Module Microsoft.Graph -Scope CurrentUser -Force } Import-Module Microsoft.Graph 

Connect to Microsoft Graph 

Connect-MgGraph -Scopes "Report.Read.All" 

Set investigation window (not used directly in this snippet but report is for period D7) 

Write-Host "📊 Checking for unusual outbound email volume..." -ForegroundColor Yellow 

Retrieve email activity report for the last 7 days 

$Uri = "https://graph.microsoft.com/v1.0/reports/getEmailActivityUserDetail(period='D7')" $outputPath = "$env:TEMP\email_activity_$(Get-Date -Format 'yyyyMMddHHmmss').csv" 

Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputFilePath $outputPath 

if (Test-Path $outputPath) { $parsed = Import-Csv $outputPath $highVolumeSenders = $parsed | Where-Object { [int]::TryParse($.SendCount, [ref]$null) -and [int]$.SendCount -gt 100 } if ($highVolumeSenders) { foreach ($sender in $highVolumeSenders) { Write-Host "[WARNING] $($sender.UserPrincipalName) sent $($sender.SendCount) emails in the last 7 days." -ForegroundColor Red } } else { Write-Host "No unusual email volume detected." -ForegroundColor Green } Remove-Item $outputPath -Force -ErrorAction SilentlyContinue } else { Write-Host "[ERROR] Failed to retrieve the email activity report." -ForegroundColor Red } 