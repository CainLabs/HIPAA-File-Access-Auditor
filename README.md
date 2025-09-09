HIPAA File Access Auditor
The Problem
The HIPAA Security Rule requires healthcare organizations to implement procedures to "regularly review records of information system activity, such as audit logs, access reports, and security incident tracking reports" (§ 164.312(b)). For organizations using standard Windows file servers to store Protected Health Information (PHI), this creates a significant challenge. 📂

A busy file server can generate millions of event logs daily, making manual review impossible. Without a proper tool, unauthorized access to sensitive patient data by insiders or compromised accounts can go undetected for months, leading to severe data breaches, regulatory fines, and loss of patient trust. Commercial SIEM (Security Information and Event Management) platforms can solve this, but their cost and complexity are often prohibitive for small to mid-sized clinics and healthcare providers.

The Solution
This PowerShell script, HIPAA-File-Access-Auditor.ps1, provides a no-cost, lightweight, and automated solution to this critical compliance gap.

It runs directly on your file server and intelligently parses the Windows Security Log to identify high-risk access events based on a simple set of rules you define. The script automatically flags suspicious activity—such as a user accessing patient records after hours or an account from the marketing department accessing clinical research—and generates a concise, human-readable CSV report. 📝

This tool transforms the vague requirement to "review activity" into a manageable, daily operational security task, providing clear, actionable intelligence to your compliance team.

Key Features
🕵️‍♂️ Automated Anomaly Detection: Flags suspicious activity based on customizable business rules, turning raw log data into security intelligence.

🌙 After-Hours Access Alerts: Immediately identifies and reports any access to sensitive files that occurs outside of your organization's defined business hours.

👤 Unauthorized User Flagging: Cross-references Active Directory in real-time to identify access by users who are not members of pre-defined authorized groups (e.g., "ClinicalStaff").

⚡ Performance Optimized: Includes a built-in cache for Active Directory queries to ensure high performance and minimize network impact, even when analyzing thousands of events.

📊 Actionable CSV Reporting: Generates a clean CSV report detailing each potential incident, including the user, file path, timestamp, and the specific reason it was flagged for review.

Requirements
Operating System: Windows Server 2016 / Windows 10 or newer.

PowerShell: PowerShell 5.1 or newer.

Permissions: The script must be run by a user with permissions to read the Security Event Log and query Active Directory domain user objects.

Active Directory: The server must be domain-joined, and the Active Directory PowerShell Module must be installed and available. This is typically installed as part of the Remote Server Administration Tools (RSAT).

❗️CRITICAL - Audit Policy: The system's audit policy must be configured to log successful file system access. The script includes a pre-flight check to verify this, but it cannot enable the policy for you.

Setup & Configuration
For the script to function, you must enable two types of auditing in Windows.

Step 1: Enable the Global Audit Policy
This policy tells Windows to start tracking file system access events. The easiest way to apply this is through a Group Policy Object (GPO).

Open the Group Policy Management console.

Create or edit a GPO that applies to your file servers.

Navigate to:
Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> Audit Policies -> Object Access.

Find the Audit File System policy and enable it for Success events.

Step 2: Apply Auditing to Specific PHI Folders
This policy tells Windows which specific folders to monitor. You must apply this directly to every folder containing PHI.

Right-click the folder containing PHI and select Properties.

Go to the Security tab and click Advanced.

Go to the Auditing tab and click Add.

Click "Select a principal" and enter Everyone, then click OK.

Set the Type to Success.

Set "Applies to" to "This folder, subfolders, and files".

Click "Show advanced permissions" and select "Full control" to ensure all access types are logged.

Click OK to save the new auditing entry.

Usage
To run the script, open a PowerShell console, navigate to the script's directory, and execute it with the required parameters. It is recommended to use a dynamic filename for the report to create a unique audit file for each run.

Example Command:

PowerShell

.\HIPAA-File-Access-Auditor.ps1 -Path "D:\PatientRecords", "E:\Billing" -AuthorizedGroups "ClinicalStaff", "BillingDept" -ReportPath "C:\HIPAA-Audits\$(Get-Date -f yyyy-MM-dd)-Audit.csv"
This command will:

Monitor the D:\PatientRecords and E:\Billing directories.

Consider users in the "ClinicalStaff" and "BillingDept" AD groups as authorized.

Generate a report named with today's date (e.g., 2025-09-09-Audit.csv) in the C:\HIPAA-Audits folder.

Sample Report
The script will produce a .csv file containing any events that were flagged as anomalous. The ReasonForFlag column provides a clear explanation for why the event was included in the report.

Timestamp	UserName	FilePath	Process	ReasonForFlag
9/9/2025 2:14:11 AM	JSMITH	D:\PatientRecords\social\0123.pdf	explorer.exe	After-Hours Access
9/9/2025 10:05:22 AM	BJOHNSON	E:\Billing\archive\Q2.xlsx	powershell.exe	Unauthorized User
9/9/2025 11:30:01 PM	MRODRIGUEZ	D:\PatientRecords\labwork\5543.docx	WINWORD.EXE	After-Hours Access; Unauthorized User

Export to Sheets
Disclaimer
This tool is provided as-is to assist with security and compliance efforts. It is not a guarantee of HIPAA compliance. Always validate the script's findings and use it as one component of a comprehensive security and privacy program.