# Reference data every IOC hunt uses, whatever the incident.

# Directory roles worth an attacker's time (built-in role template IDs).
$script:NSPHuntPrivilegedRoles = @{
    '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
    'e8611ab8-c189-46e8-94e1-60213ab1f814' = 'Privileged Role Administrator'
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' = 'Privileged Authentication Administrator'
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = 'Application Administrator'
    '158c047a-c907-4556-b7ef-446551a6b5f7' = 'Cloud Application Administrator'
    '29232cdf-9323-42fd-ade2-1d097af3e4de' = 'Exchange Administrator'
    'f28a1f50-f6e7-4571-818b-6a12f2af6b6c' = 'SharePoint Administrator'
    '69091246-20e8-4a56-aa4d-066075b2a7a8' = 'Teams Administrator'
    'fe930be7-5e62-47db-91af-98c3a49a38b1' = 'User Administrator'
    '194ae4cb-b126-40b2-bd5b-6091b380977d' = 'Security Administrator'
    '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2' = 'Hybrid Identity Administrator'
    'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9' = 'Conditional Access Administrator'
    '3a2c62db-5318-420d-8d74-23affee5d9d5' = 'Intune Administrator'
}

# Application permissions that make an enabled IOC app worth a closer look.
$script:NSPHuntHighRiskAppPermissions = @(
    'Directory.ReadWrite.All', 'RoleManagement.ReadWrite.Directory', 'Application.ReadWrite.All',
    'AppRoleAssignment.ReadWrite.All', 'Mail.ReadWrite', 'Mail.Read', 'full_access_as_app',
    'Sites.FullControl.All', 'Files.ReadWrite.All', 'User.ReadWrite.All', 'Exchange.ManageAsApp'
)

$script:NSPHuntSeverityOrder = @{ Critical = 0; High = 1; Medium = 2; Warning = 3; Low = 4; Info = 5 }

# Read-only Graph scopes for a delegated hunt; -DisableIocApps adds Application.ReadWrite.All.
$script:NSPHuntScopes = @('Application.Read.All', 'Directory.Read.All', 'AuditLog.Read.All', 'RoleManagement.Read.Directory')
