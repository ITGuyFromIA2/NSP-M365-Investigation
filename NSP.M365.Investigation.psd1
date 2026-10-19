@{
    RootModule = 'NSP.M365.Investigation.psm1'
    ModuleVersion = '0.1.0'
    GUID = 'ff0eba01-0e0c-4c85-818f-c9f9922f1bce'
    Author = 'Network Systems Plus'
    CompanyName = 'Network Systems Plus'
    Copyright = '(c) 2026 Network Systems Plus. All rights reserved.'
    Description = 'Incident response for Microsoft 365 / Entra ID: hunts one tenant or a list for an incident''s indicators (vendor app service principals, roles, new credentials, directory audits, sign-ins from IOC IPs) and writes a severity-sorted report with raw evidence. Ships the October 2026 ConnectWise SkyKick indicator set. Windows PowerShell 5.1 compatible.'

    # 5.1 is the floor, and the module must import on a bare host: NSP.M365.Graph is loaded on
    # first use (Private\Import-NSPToolkitModule.ps1), never declared as RequiredModules.
    PowerShellVersion = '5.1'

    FunctionsToExport = @(
        'Get-NSPIocSet'
        'Invoke-NSPM365IocHunt'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()

    PrivateData = @{
        PSData = @{
            Tags = @('NSP', 'M365', 'Entra', 'MicrosoftGraph', 'IncidentResponse', 'IOC', 'ThreatHunting', 'SkyKick', 'ConnectWise')
            ProjectUri = 'https://github.com/ITGuyFromIA2/NSP-M365-Investigation'
            LicenseUri = 'https://github.com/ITGuyFromIA2/NSP-M365-Investigation/blob/main/LICENSE'
            ReleaseNotes = 'https://github.com/ITGuyFromIA2/NSP-M365-Investigation/blob/main/CHANGELOG.md'
        }
    }
}
