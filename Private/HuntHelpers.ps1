# Small helpers shared by the hunt checks. $Hunt is the per-run state Invoke-NSPM365IocHunt builds:
# Ioc (the set), Since / SinceIso, OutputPath, TenantLabel, Findings, AppRoleCache.

function Add-NSPHuntFinding {
    param(
        [Parameter(Mandatory)][hashtable]$Hunt,
        [Parameter(Mandatory)][ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info', 'Warning')][string]$Severity,
        [string]$Check, [string]$Object, [string]$Detail, $Time = $null, $Evidence = $null
    )
    $ev = if ($null -ne $Evidence) { ConvertTo-Json -InputObject $Evidence -Depth 6 -Compress } else { '' }
    $Hunt.Findings.Add([pscustomobject]@{
            Tenant   = $Hunt.TenantLabel
            Severity = $Severity
            Check    = $Check
            Object   = $Object
            Detail   = $Detail
            TimeUtc  = $Time
            Evidence = $ev
        })
    $color = switch ($Severity) { 'Critical' { 'Red' } 'High' { 'Red' } 'Medium' { 'Yellow' } 'Warning' { 'Magenta' } default { 'Gray' } }
    Write-Host ('  [{0}] {1}: {2} - {3}' -f $Severity, $Check, $Object, $Detail) -ForegroundColor $color
}

function Get-NSPHuntCollection {
    # Every page of a Graph collection through Invoke-NSPGraphRequest (so the Fake transport
    # applies), stopping at -MaxPages, with a retry on throttling and transient errors.
    param(
        [Parameter(Mandatory)][string]$Uri,
        [ValidateSet('v1.0', 'beta')][string]$ApiVersion = 'v1.0',
        [int]$MaxPages = 200
    )
    $items = New-Object System.Collections.Generic.List[object]
    $next = $Uri
    $page = 0
    while ($next -and $page -lt $MaxPages) {
        $attempt = 0
        while ($true) {
            try {
                $response = Invoke-NSPGraphRequest -Method GET -Uri $next -ApiVersion $ApiVersion
                break
            } catch {
                $attempt++
                if ($attempt -le 5 -and $_.Exception.Message -match '429|TooManyRequests|503|504|ServiceUnavailable|GatewayTimeout') {
                    $wait = [math]::Min(60, [math]::Pow(2, $attempt) * 2)
                    Write-Verbose "Throttled or transient error ($($_.Exception.Message)). Waiting $wait s."
                    Start-Sleep -Seconds $wait
                    continue
                }
                throw
            }
        }
        foreach ($item in @($response['value'])) { if ($null -ne $item) { $items.Add($item) } }
        $next = $response['@odata.nextLink']
        $page++
    }
    if ($next) { Write-Warning "Stopped after $MaxPages page(s) of $Uri; later results were not read." }
    , $items.ToArray()
}

function New-NSPHuntFilterUri {
    param([Parameter(Mandatory)][string]$Base, [Parameter(Mandatory)][string]$Filter, [string]$Extra)
    $uri = $Base + '?$filter=' + [uri]::EscapeDataString($Filter)
    if ($Extra) { $uri += '&' + $Extra }
    $uri
}

function Get-NSPHuntValue {
    # Nested read that tolerates missing keys (Graph omits nulls) on hashtables or objects.
    param($InputObject, [Parameter(Mandatory)][string[]]$Path)
    $current = $InputObject
    foreach ($key in $Path) {
        if ($null -eq $current) { return $null }
        if ($current -is [System.Collections.IDictionary]) {
            if (-not $current.Contains($key)) { return $null }
            $current = $current[$key]
        } elseif ($current.PSObject.Properties.Name -contains $key) {
            $current = $current.$key
        } else { return $null }
    }
    $current
}

function ConvertTo-NSPHuntUtc {
    # Graph dates arrive as strings or DateTime depending on host and output type.
    param($Value)
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) }
        return $Value.ToUniversalTime()
    }
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    [datetime]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, $styles)
}

function Format-NSPHuntUtc {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return '' }
    try { (ConvertTo-NSPHuntUtc $Value).ToString('yyyy-MM-dd HH:mm:ss') + 'Z' } catch { [string]$Value }
}

function Test-NSPHuntIocIp {
    # 'Exact', 'Prefix', 'Context', or $null.
    param([Parameter(Mandatory)][hashtable]$Hunt, [string]$Ip)
    if (-not $Ip) { return $null }
    if ($Hunt.Ioc.IPs -contains $Ip) { return 'Exact' }
    foreach ($prefix in $Hunt.Ioc.IpPrefixes) { if ($Ip.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { return 'Prefix' } }
    foreach ($prefix in $Hunt.Ioc.ContextIpPrefixes.Keys) { if ($Ip.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { return 'Context' } }
    $null
}

function Get-NSPHuntContextNote {
    param([Parameter(Mandatory)][hashtable]$Hunt, [string]$Ip)
    foreach ($prefix in $Hunt.Ioc.ContextIpPrefixes.Keys) {
        if ($Ip -and $Ip.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { return $Hunt.Ioc.ContextIpPrefixes[$prefix] }
    }
    ''
}

function Test-NSPHuntPremiumError {
    param([string]$Message)
    $Message -match 'RequestFromNonPremiumTenant|premium license|Authentication_RequestFromNonPremiumTenantOrB2CTenant'
}

function Save-NSPHuntEvidence {
    # Raw Graph data per tenant, so evidence outlives log retention. Written even under -WhatIf:
    # -WhatIf covers the remediation, not the report.
    param([Parameter(Mandatory)][hashtable]$Hunt, $Data, [Parameter(Mandatory)][string]$Name)
    $items = @(foreach ($d in $Data) { $d })
    if ($items.Count -eq 0) { return }
    $folder = Join-Path $Hunt.OutputPath ($Hunt.TenantLabel -replace '[^\w\.-]', '_')
    if (-not (Test-Path -LiteralPath $folder)) { New-Item -ItemType Directory -Path $folder -Force -WhatIf:$false -Confirm:$false | Out-Null }
    ConvertTo-Json -InputObject $items -Depth 10 | Out-File -FilePath (Join-Path $folder "$Name.json") -Encoding UTF8 -WhatIf:$false -Confirm:$false
}

function Resolve-NSPHuntAppRoleName {
    # Application permission name for an app role ID, cached per resource service principal.
    param([Parameter(Mandatory)][hashtable]$Hunt, [string]$ResourceId, [string]$AppRoleId)
    if (-not $Hunt.AppRoleCache.ContainsKey($ResourceId)) {
        $map = @{}
        try {
            $resource = Invoke-NSPGraphRequest -Uri ("servicePrincipals/$ResourceId" + '?$select=appRoles')
            foreach ($role in @($resource['appRoles'])) { if ($role) { $map[[string]$role['id']] = [string]$role['value'] } }
        } catch { Write-Verbose "Could not read app roles of $ResourceId`: $($_.Exception.Message)" }
        $Hunt.AppRoleCache[$ResourceId] = $map
    }
    $map = $Hunt.AppRoleCache[$ResourceId]
    if ($map.ContainsKey($AppRoleId)) { return $map[$AppRoleId] }
    $AppRoleId
}
