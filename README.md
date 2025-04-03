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

6. **Compromised User Management**
   - Ability to quickly block compromised user accounts
   - Prevents further unauthorized access
   - Provides security recommendations for cleanup

## Prerequisites

- Microsoft 365 Admin Account with appropriate permissions
- PowerShell 5.1 or later
- Exchange Online Management Module (automatically installed if missing)
- Microsoft Graph PowerShell SDK (automatically installed if missing)

## Required Permissions

- Exchange Administrator role
- Global Reader or Global Administrator role
- Following Microsoft Graph permissions:
  - AuditLog.Read.All
  - Mail.Read
  - MailboxSettings.Read
  - User.ReadWrite.All
  - Mail.ReadBasic

## Installation

1. Clone or download this repository
2. Required modules will be automatically installed on first run
3. Run the main script or individual component scripts as needed

```powershell
# Run the main menu-driven tool
.\Investigate-M365SecurityIncidents.ps1

# Or run individual component scripts in the 'split' folder
.\split\1.\ Detect\ Malicious\ Inbox\ Rules.ps1
```

## Usage

1. Run the script
2. Authenticate with your Microsoft 365 admin credentials
3. Select the investigation time period (7, 30, or 90 days)
4. Select options from the menu to perform different security checks
5. Review the results and take necessary actions

## Enhanced Features

- **Automatic Module Installation**: Scripts check for required modules and install them if missing
- **Configurable Time Periods**: Most scripts support 7, 30, or 90-day investigation windows
- **Improved Error Handling**: Better error detection and user feedback
- **Consistent UX**: Standardized color coding and output formatting
- **Pagination Support**: Properly handles large result sets without truncation

## Security Note

This script requires elevated privileges in your Microsoft 365 environment. Always:
- Run this script from a secure administrative workstation
- Use accounts with appropriate permissions
- Review all actions before executing them
- Follow your organization's security policies

## Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.

## License

This project is licensed under the MIT License - see the LICENSE file for details
