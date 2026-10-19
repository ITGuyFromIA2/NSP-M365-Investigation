function Get-NSPIocSet {
    <#
    .SYNOPSIS
        Returns an indicator-of-compromise set: the app IDs, IP addresses, user agents and hunt window for one incident.
    .DESCRIPTION
        Sets ship in the module's IocSets\ folder, one .psd1 per incident, named by the file
        (IocSets\SkyKick.psd1 is 'SkyKick'). -Name may also be the path to a .psd1 of the same
        shape, so a new incident can be hunted before a module release.

        With no -Name, every shipped set is returned.

        -AdditionalIPs and -AdditionalAppIds add indicators a vendor published after the set was
        written, without editing it.
    .EXAMPLE
        Get-NSPIocSet
    .EXAMPLE
        Get-NSPIocSet -Name SkyKick -AdditionalIPs '203.0.113.7'
    .EXAMPLE
        Get-NSPIocSet -Name .\NextIncident.psd1
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [ArgumentCompleter({ Get-ChildItem -Path (Join-Path (Get-Module NSP.M365.Investigation).ModuleBase 'IocSets') -Filter "$($args[2])*.psd1" | ForEach-Object BaseName })]
        [string]$Name,
        [string[]]$AdditionalIPs = @(),
        [string[]]$AdditionalAppIds = @()
    )

    $folder = Join-Path $script:ModuleRoot 'IocSets'
    if (-not $Name) {
        foreach ($file in Get-ChildItem -LiteralPath $folder -Filter '*.psd1' -File | Sort-Object Name) {
            Get-NSPIocSet -Name $file.FullName -AdditionalIPs $AdditionalIPs -AdditionalAppIds $AdditionalAppIds
        }
        return
    }

    $path = if ($Name -match '\.psd1$') { $Name } else { Join-Path $folder "$Name.psd1" }
    if (-not (Test-Path -LiteralPath $path)) {
        $available = @(Get-ChildItem -LiteralPath $folder -Filter '*.psd1' -File | ForEach-Object BaseName) -join ', '
        throw "No IOC set '$Name'. Available: $available. -Name also takes the path to a .psd1."
    }
    $data = Import-PowerShellDataFile -LiteralPath $path
    $missing = @('Name', 'Title', 'Since', 'Apps', 'IPs' | Where-Object { -not $data.ContainsKey($_) })
    if ($missing.Count) { throw "IOC set $path is missing: $($missing -join ', ')." }

    # Case-insensitive lookups whatever the file's casing.
    $apps = @{}
    foreach ($key in $data.Apps.Keys) { $apps[([string]$key).ToLowerInvariant()] = [string]$data.Apps[$key] }
    foreach ($appId in $AdditionalAppIds) { if (-not $apps.ContainsKey($appId.ToLowerInvariant())) { $apps[$appId.ToLowerInvariant()] = 'User-supplied IOC app' } }
    $context = @{}
    if ($data.ContainsKey('ContextIpPrefixes')) { foreach ($key in $data.ContextIpPrefixes.Keys) { $context[[string]$key] = [string]$data.ContextIpPrefixes[$key] } }
    $prefixes = @(if ($data.ContainsKey('NamePrefixes')) { $data.NamePrefixes })
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal

    [pscustomobject]@{
        Name              = [string]$data.Name
        Title             = [string]$data.Title
        Updated           = [string]$data.Updated
        Since             = [datetime]::Parse([string]$data.Since, [Globalization.CultureInfo]::InvariantCulture, $styles)
        Apps              = $apps
        OwnerTenantIds    = @(if ($data.ContainsKey('OwnerTenantIds')) { $data.OwnerTenantIds })
        NamePrefixes      = $prefixes
        NameRegex         = if ($prefixes.Count) { (@($prefixes | ForEach-Object { [regex]::Escape($_) }) -join '|') } else { $null }
        IPs               = @(@($data.IPs) + @($AdditionalIPs) | Where-Object { $_ } | Select-Object -Unique)
        IpPrefixes        = @(if ($data.ContainsKey('IpPrefixes')) { $data.IpPrefixes })
        ContextIpPrefixes = $context
        UserAgents        = @(if ($data.ContainsKey('UserAgents')) { $data.UserAgents })
        Sources           = @(if ($data.ContainsKey('Sources')) { $data.Sources })
        Notes             = @(if ($data.ContainsKey('Notes')) { $data.Notes })
        Path              = (Resolve-Path -LiteralPath $path).ProviderPath
    }
}
