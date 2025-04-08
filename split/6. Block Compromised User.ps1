# Block a Compromised User

function Block-CompromisedUser {
    param (
        [string]$userUPN
    )
    if ([string]::IsNullOrWhiteSpace($userUPN)) {
        Write-Host "[ERROR] No user specified. Skipping block operation." -ForegroundColor Red
        return
    }
    Write-Host "`n[SECURITY] Blocking user: $userUPN" -ForegroundColor Yellow
    try {
        Write-Host "Taking immediate security actions for user: $userUPN" -ForegroundColor Red

        # Option 1: Block user account
        Write-Host "1. Blocking user account..." -ForegroundColor Yellow
        Update-MgUser -UserId $userUPN -AccountEnabled:$false
        Write-Host "   Account successfully disabled" -ForegroundColor Green

        # Option 2: Reset user password and force change at next login
        Write-Host "2. Resetting password..." -ForegroundColor Yellow
        $newPassword = -join ((33..126) | Get-Random -Count 16 | ForEach-Object { [char]$_ })
        Update-MgUser -UserId $userUPN -PasswordProfile @{
            Password                      = $newPassword
            ForceChangePasswordNextSignIn = $true
        }
        Write-Host "   Password reset successful. New temporary password: $newPassword" -ForegroundColor Green
        Write-Host "   IMPORTANT: Document this password securely!" -ForegroundColor Red

        # Option 3: Revoke all active sessions
        Write-Host "3. Revoking all active sessions..." -ForegroundColor Yellow
        Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/users/$userUPN/revokeSignInSessions"
        Write-Host "   All sessions terminated successfully" -ForegroundColor Green

        # Additional checks
        Write-Host "`nRunning security checks and retrieving recent sign-in activity..." -ForegroundColor Cyan
        Get-MgAuditLogSignIn -Filter "userPrincipalName eq '$userUPN'" -Top 5 | 
        Select-Object CreatedDateTime, AppDisplayName, IpAddress, @{N = "Status"; E = { $_.Status.ErrorCode } } | 
        Format-Table -AutoSize

        Write-Host "`nRecommended next steps:" -ForegroundColor Yellow
        Write-Host "1. Check for suspicious inbox rules: Get-InboxRule -Mailbox $userUPN" -ForegroundColor Cyan
        Write-Host "2. Check for mail forwarding: Get-Mailbox $userUPN | Select-Object ForwardingAddress,ForwardingSmtpAddress" -ForegroundColor Cyan
        Write-Host "3. Document all actions taken in this security incident" -ForegroundColor Cyan
    }
    catch {
        Write-Host "[ERROR] Failed to block user: $_" -ForegroundColor Red
    }
}
