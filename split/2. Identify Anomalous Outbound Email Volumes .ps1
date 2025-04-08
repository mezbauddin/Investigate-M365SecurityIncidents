# Identify Anomalous Outbound Email Volumes

function Get-UnusualEmailVolume {
    Write-Host "`n[SCANNING] Checking for unusual outbound email volume..." -ForegroundColor Yellow
    try {
        $Uri = "https://graph.microsoft.com/v1.0/reports/getEmailActivityUserDetail(period='D$Global:days')"
        $outputPath = "$env:TEMP\email_activity_$(Get-Date -Format 'yyyyMMddHHmmss').csv"
        Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputFilePath $outputPath -ErrorAction Stop
        if (Test-Path $outputPath) {
            $parsed = Import-Csv $outputPath
            $highVolumeSenders = $parsed | Where-Object { 
                [int]::TryParse($_.SendCount, [ref]$null) -and [int]$_.SendCount -gt 100 
            }
            if ($highVolumeSenders) {
                foreach ($sender in $highVolumeSenders) {
                    Write-Host "[WARNING] $($sender.UserPrincipalName) sent $($sender.SendCount) emails in last ($Global:days) days." -ForegroundColor Red
                }
            }
            else {
                Write-Host "[INFO] No users with unusual email volume detected." -ForegroundColor Green
            }
            Remove-Item $outputPath -Force -ErrorAction SilentlyContinue
        }
        else {
            Write-Host "[ERROR] Failed to retrieve email activity report." -ForegroundColor Red
        }
    }
    catch {
        Write-Host "[ERROR] Error retrieving email volume data: $_" -ForegroundColor Red
    }
}
