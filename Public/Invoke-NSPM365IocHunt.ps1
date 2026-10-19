function Invoke-NSPM365IocHunt {
    <#
    .SYNOPSIS
        Hunts one or more Microsoft 365 / Entra ID tenants for an incident's indicators and writes a severity-sorted Findings.csv with raw evidence.
    .DESCRIPTION
        Read-only unless -DisableIocApps. Per tenant, for the indicator set named by -IocSet
        (Get-NSPIocSet):

          1. The incident's service principals (by app ID, owner tenant, display name prefix):
             still enabled, directory roles held, application permissions granted.
          2. Every other service principal holding a privileged directory role (review list).
          3. ApplicationManagement and RoleManagement directory audits since -Since: an app giving
             a role to itself is Critical; IOC apps acting or granted roles, credentials added by
             applications, and IOC user agents are flagged.
          4. Secrets and certificates added since -Since on every app registration and service
             principal; High when an application (not a person) added it.
          5. Sign-ins (beta): IOC apps' service principal sign-ins, any sign-in from the IOC IPs,
             and whether a credential added in the window has signed in, and from where.
          6. Users created since -Since.

        Output: <OutputPath>\Findings.csv sorted by severity, and <OutputPath>\<tenant>\*.json raw
        audit and sign-in data, so the evidence outlives log retention (7 days without Entra ID
        P1, 30 with). Tenants without P1 cannot read sign-ins through Graph: the run flags them,
        and their Service principal sign-ins must be exported from the Entra portal by hand.

        Every tenant is checked against the tenant asked for (a domain is resolved to its tenant
        ID first); a mismatch is reported as a warning and nothing else is reported for it.

        -DisableIocApps disables (never deletes) the enabled service principals whose app ID is in
        the set; apps matched only by owner tenant or name are reported, not touched. It confirms
        per app (ConfirmImpact High); -WhatIf still writes the report.

        Sign-in goes through NSP.M365.Graph: delegated (Connect-NSPGraph), or app-only with
        -ClientId and -CertificateThumbprint (Connect-NSPGraphAppOnly).

        Not covered: mailbox and file access (Unified Audit Log), and Graph directory reads, which
        Microsoft does not log. A clean result does not prove nothing was read.
    .PARAMETER IocSet
        The indicator set: a name from Get-NSPIocSet (SkyKick), or the path to a .psd1 of the same shape.
    .PARAMETER TenantId
        One or more tenant IDs or domains, each connected to in turn.
    .PARAMETER TenantCsv
        CSV with a TenantId column and an optional Name column.
    .PARAMETER UseCurrentConnection
        The tenant of the current Graph session (connects when there is none). The default.
    .PARAMETER ClientId
        App-only: a multi-tenant app consented in each tenant with Application.Read.All,
        Directory.Read.All, AuditLog.Read.All, RoleManagement.Read.Directory (plus
        Application.ReadWrite.All for -DisableIocApps). Needs -CertificateThumbprint and a tenant.
    .PARAMETER Since
        Start of the hunt window (UTC unless it carries an offset). Defaults to the set's.
    .PARAMETER AdditionalIocIPs
        IPs published after the set was written.
    .PARAMETER AdditionalIocAppIds
        App IDs published after the set was written. These are disabled by -DisableIocApps too.
    .PARAMETER OutputPath
        Report folder. Defaults to .\<set>IOC_<timestamp>.
    .PARAMETER SkipSignIns
        Skip the sign-in log queries.
    .PARAMETER DisableIocApps
        Disable the set's enabled service principals, confirming each.
    .PARAMETER PassThru
        Also return the findings.
    .EXAMPLE
        Invoke-NSPM365IocHunt -IocSet SkyKick -UseCurrentConnection

        Your own tenant first.
    .EXAMPLE
        Invoke-NSPM365IocHunt -IocSet SkyKick -TenantCsv .\tenants.csv -ClientId $partnerAppId -CertificateThumbprint $thumbprint
    .EXAMPLE
        Invoke-NSPM365IocHunt -IocSet SkyKick -TenantId contoso.onmicrosoft.com -DisableIocApps -WhatIf
    .EXAMPLE
        Invoke-NSPM365IocHunt -IocSet SkyKick -TenantId $tenantId -AdditionalIocIPs '203.0.113.7'
    .NOTES
        Delegated (GDAP) access needs Global Reader plus Security Reader (or Reports Reader) to
        read, and Cloud Application Administrator for -DisableIocApps. A delegated sign-in to a
        client tenant needs the "Microsoft Graph Command Line Tools" app consented there; on
        AADSTS650051 or AADSTS65001 use -ClientId/-CertificateThumbprint with your partner app.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'Current')]
    param(
        [Parameter(Mandatory)]
        [ArgumentCompleter({ Get-ChildItem -Path (Join-Path (Get-Module NSP.M365.Investigation).ModuleBase 'IocSets') -Filter "$($args[2])*.psd1" | ForEach-Object BaseName })]
        [string]$IocSet,

        [Parameter(ParameterSetName = 'TenantList', Mandatory)]
        [string[]]$TenantId,

        [Parameter(ParameterSetName = 'TenantCsv', Mandatory)]
        [ValidateScript({ Test-Path -LiteralPath $_ })]
        [string]$TenantCsv,

        [Parameter(ParameterSetName = 'Current')]
        [switch]$UseCurrentConnection,

        [string]$ClientId,
        [string]$CertificateThumbprint,
        [switch]$UseDeviceCode,

        [datetime]$Since,
        [string[]]$AdditionalIocIPs = @(),
        [string[]]$AdditionalIocAppIds = @(),
        [string]$OutputPath,

        [switch]$SkipSignIns,
        [switch]$DisableIocApps,
        [switch]$PassThru
    )

    $ErrorActionPreference = 'Stop'
    if ([bool]$ClientId -ne [bool]$CertificateThumbprint) { throw 'App-only sign-in needs both -ClientId and -CertificateThumbprint.' }
    if ($ClientId -and $PSCmdlet.ParameterSetName -eq 'Current') { throw 'App-only sign-in needs a tenant: use -TenantId or -TenantCsv.' }

    $ioc = Get-NSPIocSet -Name $IocSet -AdditionalIPs $AdditionalIocIPs -AdditionalAppIds $AdditionalIocAppIds
    $start = if (-not $PSBoundParameters.ContainsKey('Since')) { $ioc.Since }
    elseif ($Since.Kind -eq [DateTimeKind]::Unspecified) { [datetime]::SpecifyKind($Since, [DateTimeKind]::Utc) }
    else { $Since.ToUniversalTime() }
    if (-not $OutputPath) { $OutputPath = Join-Path (Get-Location).ProviderPath ('{0}IOC_{1}' -f $ioc.Name, (Get-Date -Format 'yyyyMMdd_HHmmss')) }
    if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force -WhatIf:$false -Confirm:$false | Out-Null }
    $OutputPath = (Resolve-Path -LiteralPath $OutputPath).ProviderPath

    Import-NSPM365Graph
    $scopes = @($script:NSPHuntScopes)
    if ($DisableIocApps) { $scopes += 'Application.ReadWrite.All' }

    $hunt = @{
        Ioc          = $ioc
        Since        = $start
        SinceIso     = $start.ToString('yyyy-MM-ddTHH:mm:ssZ')
        OutputPath   = $OutputPath
        TenantLabel  = ''
        Findings     = New-Object System.Collections.Generic.List[object]
        AppRoleCache = @{}
    }

    $targets = switch ($PSCmdlet.ParameterSetName) {
        'TenantList' { @($TenantId | ForEach-Object { [pscustomobject]@{ Tenant = $_; Name = $_ } }) }
        'TenantCsv' {
            @(Import-Csv -LiteralPath $TenantCsv | Where-Object { $_.TenantId } | ForEach-Object {
                    $name = if ($_.PSObject.Properties.Name -contains 'Name' -and $_.Name) { $_.Name } else { $_.TenantId }
                    [pscustomobject]@{ Tenant = $_.TenantId.Trim(); Name = $name }
                })
        }
        default { @([pscustomobject]@{ Tenant = $null; Name = 'current' }) }
    }

    Write-Host "$($ioc.Title)" -ForegroundColor Cyan
    Write-Host "IOC hunt '$($ioc.Name)' (indicators as of $($ioc.Updated)). Window: $($hunt.SinceIso) -> now. Tenants: $(@($targets).Count). Output: $OutputPath" -ForegroundColor Cyan
    foreach ($note in $ioc.Notes) { Write-Host "  Note: $note" -ForegroundColor DarkGray }

    foreach ($target in $targets) {
        $hunt.TenantLabel = $target.Name
        try {
            $expected = if ($target.Tenant) { Resolve-NSPHuntTenantId -Tenant $target.Tenant } else { $null }
            Connect-NSPHuntTenant -TenantId $expected -Scopes $scopes -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -UseDeviceCode:$UseDeviceCode
            $result = Invoke-NSPHuntTenant -Hunt $hunt -ExpectedTenantId $expected -SkipSignIns:$SkipSignIns
        } catch {
            $message = $_.Exception.Message
            if ($message -match 'AADSTS650051|AADSTS65001') { $message += ' (The Microsoft Graph Command Line Tools app is not consented in this tenant: use -ClientId/-CertificateThumbprint with your partner app.)' }
            Add-NSPHuntFinding -Hunt $hunt -Severity Warning -Check 'Tenant run' -Object $target.Name -Detail "Failed: $message"
            continue
        }

        if (-not $DisableIocApps) { continue }
        foreach ($sp in @($result.IocServicePrincipals | Where-Object { $_.accountEnabled -and $ioc.Apps.ContainsKey(([string]$_.appId).ToLowerInvariant()) })) {
            $object = "$($sp.displayName) ($($sp.appId))"
            if (-not $PSCmdlet.ShouldProcess("$object in $($result.TenantLabel)", 'Disable service principal (accountEnabled = false)')) { continue }
            try {
                Invoke-NSPGraphRequest -Method PATCH -Uri "servicePrincipals/$($sp.id)" -Body @{ accountEnabled = $false } | Out-Null
                Add-NSPHuntFinding -Hunt $hunt -Severity Info -Check 'Remediation' -Object $object -Detail 'Service principal DISABLED by this run.'
            } catch {
                Add-NSPHuntFinding -Hunt $hunt -Severity Warning -Check 'Remediation' -Object $object -Detail "Disable failed: $($_.Exception.Message)"
            }
        }
    }

    $sorted = @($hunt.Findings | Sort-Object @{ Expression = { $script:NSPHuntSeverityOrder[$_.Severity] } }, Tenant, TimeUtc)
    $csv = Join-Path $OutputPath 'Findings.csv'
    $sorted | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8 -WhatIf:$false -Confirm:$false

    Write-Host ''
    Write-Host '=== Summary ===' -ForegroundColor Cyan
    $sorted | Group-Object Tenant | ForEach-Object {
        $group = $_.Group
        [pscustomobject]@{
            Tenant   = $_.Name
            Critical = @($group | Where-Object Severity -EQ 'Critical').Count
            High     = @($group | Where-Object Severity -EQ 'High').Count
            Medium   = @($group | Where-Object Severity -EQ 'Medium').Count
            Warning  = @($group | Where-Object Severity -EQ 'Warning').Count
            Low      = @($group | Where-Object Severity -EQ 'Low').Count
        }
    } | Format-Table -AutoSize | Out-Host
    Write-Host "Findings: $csv"
    Write-Host "Raw evidence JSON: $OutputPath\<tenant>\"
    if ($PassThru) { $sorted }
}
