<#
.SYNOPSIS
    Audits Windows Security Event Logs for suspicious file access to help meet HIPAA requirements.

.DESCRIPTION
    This script queries the Security Event Log for Event ID 4663 (An attempt was made to access an object)
    to identify and flag potential unauthorized access to sensitive file paths. It is designed to help
    administrators and compliance officers satisfy the HIPAA Security Rule's requirement for
    "Information System Activity Review" (§ 164.312(b)).

.PARAMETER Path
    An array of full directory paths to monitor for access (e.g., "D:\PatientRecords").

.PARAMETER Hours
    Specifies how many hours back from the current time to search the event logs. Defaults to 24.

.PARAMETER BusinessHoursStart
    The start of business hours in HH:mm format (e.g., "08:00"). Access outside this window is flagged.

.PARAMETER BusinessHoursEnd
    The end of business hours in HH:mm format (e.g., "17:00"). Access outside this window is flagged.

.PARAMETER AuthorizedGroups
    An array of Active Directory group names considered authorized. Access by users not in these groups is flagged.

.PARAMETER ReportPath
    The full path, including filename, where the CSV report will be saved.

.EXAMPLE
    .\HIPAA-File-Access-Auditor.ps1 -Path "D:\PHI", "E:\Billing" -AuthorizedGroups "ClinicalStaff", "BillingDept" -ReportPath "C:\Audits\today.csv"

.NOTES
    Author: [Your Name]
    Version: 1.0
    Requires: Active Directory PowerShell Module (for group membership checks).
              "Audit File System" policy must be enabled for Success events.
#>
[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
param(
    [Parameter(Mandatory=$true)]
    [string[]]$Path,

    [Parameter(Mandatory=$false)]
    [int]$Hours = 24,

    [Parameter(Mandatory=$false)]
    [string]$BusinessHoursStart = "08:00",

    [Parameter(Mandatory=$false)]
    [string]$BusinessHoursEnd = "17:00",

    [Parameter(Mandatory=$true)]
    [string[]]$AuthorizedGroups,

    [Parameter(Mandatory=$true)]
    [string]$ReportPath
)

# --- Step 1: Pre-flight Check ---
Write-Verbose "Performing pre-flight check for 'Audit File System' policy..."
$auditPolicy = auditpol /get /subcategory:"File System" | Select-String -Pattern "Success"

if (-not ($auditPolicy -match "Success")) {
    Write-Error "CRITICAL: 'Audit File System' for Success is not enabled on this machine."
    Write-Error "The script cannot function without the required audit logs."
    Write-Error "Please enable this setting via Group Policy: Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> Audit Policies -> Object Access -> Audit File System."
    return # Stop script execution
}

Write-Verbose "Pre-flight check passed. Audit policy is correctly configured."

# --- Step 2: Event Log Query ---
$StartTime = (Get-Date).AddHours(-$Hours)
$Filter = @{
    LogName   = 'Security'
    ID        = 4663 # "An attempt was made to access an object."
    StartTime = $StartTime
}

Write-Verbose "Querying the Security log for Event ID 4663 since $($StartTime)..."
$Events = Get-WinEvent -FilterHashtable $Filter -ErrorAction SilentlyContinue

if (-not $Events) {
    Write-Warning "No file access events (ID 4663) found in the last $($Hours) hours."
    return # Stop script execution as there is nothing to process
}

Write-Host "Found $($Events.Count) initial events to analyze."

# --- Step 3: Initial Processing and Filtering ---
$Incidents = @() # Create an empty array to store suspicious events

Write-Verbose "Analyzing events against monitored paths..."
foreach ($fileAccessEvent in $Events) {
    # Extract the file path (ObjectName) from the event data
    # For Event ID 4663, the Object Name is the 7th property (index 6)
    $ObjectName = $fileAccessEvent.Properties[6].Value

    # Check if the accessed object is within one of our monitored paths
    foreach ($P in $Path) {
        if ($ObjectName -and $ObjectName.StartsWith($P)) {
            # It's a relevant event, so we create a structured object
            $EnrichedEvent = [pscustomobject]@{
                Timestamp = $fileAccessEvent.TimeCreated
                UserName  = $fileAccessEvent.Properties[1].Value
                FilePath  = $ObjectName
                Process   = $fileAccessEvent.Properties[7].Value
            }
            $Incidents += $EnrichedEvent
            
            # Break the inner loop since we found a match
            break
        }
    }
}

if (-not $Incidents) {
    Write-Verbose "No access events were found for the specified paths: $($Path -join ', ')"
    return # Nothing more to do
}

Write-Verbose "Found $($Incidents.Count) relevant access events to analyze for anomalies."

# --- Step 4: Anomaly Detection ---
$Anomalies = @() # Final list of flagged incidents
$userGroupCache = @{} # Cache for AD group memberships to improve performance

Write-Verbose "Analyzing relevant events for anomalies..."
foreach ($Incident in $Incidents) {
    # ... (rest of the foreach loop is unchanged) ...
}

# --- Step 5: Report Generation ---
if ($Anomalies.Count -gt 0) {
    Write-Output "Analysis complete. Found $($Anomalies.Count) suspicious events."
    try {
        $Anomalies | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Output "Report successfully generated at: $ReportPath"
    } catch {
        Write-Error "Failed to write report to $ReportPath. Error: $($_.Exception.Message)"
    }
} else {
    Write-Output "Analysis complete. No suspicious activity found."
}

# --- Step 5: Report Generation ---
if ($Anomalies.Count -gt 0) {
    Write-Host "Analysis complete. Found $($Anomalies.Count) suspicious events." -ForegroundColor Yellow
    try {
        $Anomalies | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Host "Report successfully generated at: $ReportPath" -ForegroundColor Green
    } catch {
        Write-Error "Failed to write report to $ReportPath. Error: $($_.Exception.Message)"
    }
} else {
    Write-Host "Analysis complete. No suspicious activity found." -ForegroundColor Green

}
