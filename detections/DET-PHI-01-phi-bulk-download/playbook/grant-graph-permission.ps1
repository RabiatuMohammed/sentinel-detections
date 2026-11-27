# Grants the playbook's managed identity the one Microsoft Graph permission it needs:
# User.RevokeSessions.All (application). ARM templates cannot assign Graph app roles, so this runs after deployment.
# Requires: Microsoft.Graph PowerShell module, and an admin who can consent to AppRoleAssignment.ReadWrite.All.
# Usage: ./grant-graph-permission.ps1 -PlaybookPrincipalId <PlaybookPrincipalId output from the template deployment>
param([Parameter(Mandatory = $true)][string]$PlaybookPrincipalId)

Connect-MgGraph -Scopes "Application.Read.All","AppRoleAssignment.ReadWrite.All" -UseDeviceCode

# Microsoft Graph's service principal (same appId in every tenant)
$graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$appRole = $graphSp.AppRoles | Where-Object { $_.Value -eq "User.RevokeSessions.All" -and $_.AllowedMemberTypes -contains "Application" }
if (-not $appRole) { throw "User.RevokeSessions.All application role not found on Microsoft Graph." }

New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $PlaybookPrincipalId -PrincipalId $PlaybookPrincipalId -ResourceId $graphSp.Id -AppRoleId $appRole.Id

Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $PlaybookPrincipalId | Select-Object PrincipalDisplayName, ResourceDisplayName, AppRoleId
Disconnect-MgGraph
