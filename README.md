# Microsoft 365 Security Incident Investigation Tool

A PowerShell script to help security administrators investigate and respond to potential security incidents in Microsoft 365 environments.

## Author
Mezba Uddin | MVP | https://mezbauddin.com

## Features

1. **Malicious Inbox Rules Detection**
   - Scans all mailboxes for rules forwarding to external addresses
   - Identifies potential data exfiltration attempts
   - Automatically identifies internal vs external domains

2. **Unusual Email Volume Detection**
   - Identifies users sending high volumes of emails
   - Helps detect potential spam or compromised accounts
   - Configurable detection thresholds and time periods (7, 30, 90 days)

3. **Mailbox Permission Changes Monitoring**
   - Tracks changes to mailbox permissions
   - Alerts on unauthorized access attempts
   - Uses unified audit logs for comprehensive detection

4. **Critical Email Deletion Detection**
   - Monitors deleted items in specified mailboxes
   - Helps investigate potential data loss
   - Provides details on deleted messages for recovery

5. **Mailbox Export Monitoring**
   - Detects mailbox export operations
   - Helps prevent unauthorized data extraction
   - Supports filtering by specific users
   - Provides detailed audit information with pagination

# Investigate-M365SecurityIncidents

A comprehensive PowerShell toolkit for investigating and responding to Microsoft 365 (Exchange Online) security incidents. This project provides both an interactive main script and modular component scripts for targeted investigations.

## Author
Mezba Uddin | MVP | https://mrmicrosoft.com

---

## Project Structure

- **Investigate-M365SecurityIncidents.ps1**  
  Main interactive script with a menu-driven interface. Connects to Microsoft Graph and Exchange Online, lets you select investigation modules, and automates incident response tasks.

- **split/**  
  Contains modular scripts for individual investigation tasks. Each script can be run standalone for automation or integration with other tools.

    - `1. Detect Malicious Inbox Rules.ps1`  
      Scans all mailboxes for inbox rules that forward or redirect messages to external domains, helping to spot potential data exfiltration via malicious rules.

    - `2. Identify Anomalous Outbound Email Volumes .ps1`  
      Identifies users sending unusually high volumes of email, flagging compromised accounts or spam campaigns.

    - `3. Spot Privilege Escalations in Mailbox Permissions.ps1`  
      Detects changes in mailbox permissions (delegation, access grants), highlighting possible privilege escalation attempts.

    - `4. Detect Suspicious Mailbox Access.ps1`  
      Analyzes mailbox access events (MailItemsAccessed) to detect suspicious logins, access by delegates/admins, and anomalous client IPs.

    - `5. Suspicious Mailbox Exports to Spot Data Exfiltration Attempts.ps1`  
      Monitors and reports on mailbox export operations (e.g., PST exports, compliance searches), helping prevent or investigate data exfiltration.

    - `6. Block Compromised User.ps1`  
      Automates blocking a compromised user: disables the account, resets password, revokes sessions, and provides guidance for further incident response.

---

## Prerequisites

- Microsoft 365 Admin account with:
  - Exchange Administrator role
  - Global Reader or Global Administrator role
- PowerShell 5.1 or later (Windows) or PowerShell Core (cross-platform)
- Internet access from the host running the scripts

**Modules (auto-installed if missing):**
- ExchangeOnlineManagement
- Microsoft.Graph.Authentication
- Microsoft.Graph (for advanced Graph queries)

**Required Microsoft Graph permissions:**
- AuditLog.Read.All
- Mail.Read
- MailboxSettings.Read
- User.ReadWrite.All
- Mail.ReadBasic

---

## Installation

1. Clone or download this repository.
2. Open PowerShell as an administrator.
3. Navigate to the project directory.
4. Modules required will be installed automatically on first run if not already present.

---

## Usage

### Main Interactive Script

```powershell
# Run the main menu-driven investigation tool
./Investigate-M365SecurityIncidents.ps1
```

- Authenticate with your Microsoft 365 admin credentials when prompted.
- Select the investigation time period (7, 15, or 30 days).
- Use the menu to:
  1. Detect malicious inbox rules
  2. Find users sending unusual volumes of emails
  3. Monitor mailbox permission changes
  4. Detect suspicious mailbox access
  5. Detect suspicious mailbox exports
  6. Block a compromised user
  7. Execute all investigations
  8. Exit and disconnect

### Running Individual Modules

Each script in the `split/` folder can be run independently for automation or focused checks:

```powershell
# Example: Detect malicious inbox rules
./split/1.\ Detect\ Malicious\ Inbox\ Rules.ps1
```

---

## Script Details

- **1. Detect Malicious Inbox Rules.ps1**  
  Scans all mailboxes for rules forwarding or redirecting messages to external domains. Automatically determines internal domains for accuracy.

- **2. Identify Anomalous Outbound Email Volumes .ps1**  
  Uses Microsoft Graph reporting to find users with unusually high outbound email counts in the selected period.

- **3. Spot Privilege Escalations in Mailbox Permissions.ps1**  
  Queries audit logs for mailbox permission changes, listing who granted/revoked access and when.

- **4. Detect Suspicious Mailbox Access.ps1**  
  Analyzes mailbox access logs for non-owner access, suspicious IPs, and risky client applications.

- **5. Suspicious Mailbox Exports to Spot Data Exfiltration Attempts.ps1**  
  Monitors mailbox export operations, with optional filtering by user. Flags large or unexpected exports.

- **6. Block Compromised User.ps1**  
  Blocks a user by disabling the account, resetting password, revoking sessions, and provides recommended follow-up actions.

---

## Enhanced Features

- **Automatic Module Installation:** Installs required modules if missing.
- **Configurable Time Periods:** Supports 7, 15, or 30-day windows for investigations.
- **Error Handling:** Improved error feedback and reporting.
- **Consistent UX:** Color-coded, clear output for all actions.
- **CSV Export:** Investigation results are exported for further analysis.
- **Standalone/Integrated Use:** Use the main script for guided workflows or run individual scripts for automation.

---

## Security Notes

- These scripts require elevated privileges. Always:
  - Run from a secure, trusted workstation
  - Use accounts with only the necessary permissions
  - Review all actions before executing
  - Follow your organization’s security and change management policies
- Some scripts export results to CSV for auditing and compliance.

---

## Troubleshooting

- If modules fail to install automatically, try installing them manually:
  ```powershell
  Install-Module ExchangeOnlineManagement -Scope CurrentUser
  Install-Module Microsoft.Graph -Scope CurrentUser
  Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
  ```
- Ensure your admin account has the required roles and Graph permissions.
- If you encounter throttling or API limits, wait and retry.

---

## Contributing

Contributions, issues, and feature requests are welcome! Fork the repository and submit a pull request.

## License

MIT License. See LICENSE file for details.
