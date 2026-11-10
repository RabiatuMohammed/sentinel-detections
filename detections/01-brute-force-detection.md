# Detection Rule: Potential Brute Force Attack (Multiple Failed Sign-ins)

**Author:** Rabiatu Mohammed  
**Date:** November 2026  
**Status:** Validated / Ready for Deployment  
**Data Source:** Azure AD (Entra ID) Sign-in Logs (`SigninLogs`)

## 1. Objective
Detect potential password guessing or brute force attacks by identifying user accounts that experience multiple failed sign-in attempts within a 24-hour period.

## 2. MITRE ATT&CK Mapping
- **Tactic:** Credential Access (TA0006)
- **Technique:** Brute Force (T1110)
- **Sub-technique:** Password Guessing (T1110.001)

## 3. Detection Logic (KQL)
```kql
SigninLogs
| where ResultType != "0"  // Filter for failures (0 = Success)
| where TimeGenerated > ago(24h)
| summarize 
    FailedAttempts = count(),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated),
    ErrorCodes = make_set(ResultType)
    by UserPrincipalName, IPAddress, Location
| where FailedAttempts >= 2  // Threshold for alerting
| project 
    UserPrincipalName,
    IPAddress,
    Location,
    FailedAttempts,
    FirstAttempt,
    LastAttempt,
    ErrorCodes
| sort by FailedAttempts desc
