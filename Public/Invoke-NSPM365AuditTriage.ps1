function Invoke-NSPM365AuditTriage {
    <#
    .SYNOPSIS
        Triages a Unified Audit Log export for a suspected mailbox compromise and writes a severity-sorted Findings.csv with a timeline, IP table, sign-ins, mail read and inbox rules.
    .DESCRIPTION
        Reads one or more Purview audit CSV exports (Audit > Search > Export) and writes to
        -OutputPath:

          Findings.csv      severity-sorted, the same columns as Invoke-NSPM365IocHunt's
          Timeline.csv      every record, oldest first, with client IP, trust, country, ISP and the raw AuditData
          IPs.csv           one row per client IP: trust, count, users, operations, geolocation and ASN
          Summary.csv       one row per operation: count, untrusted count, first and last time
          SignIns.csv       UserLoggedIn and UserLoginFailed in one timeline, with user agent and logon error
          AccessedMail.csv  MailItemsAccessed, one row per message read (Get-NSPM365AccessedMessage)
          InboxRules.csv    inbox rule and forwarding changes, flagged (Get-NSPM365InboxRuleAudit)

        An address is trusted when it matches -TrustedIP or its ASN is in -TrustedAsn; every other
        address is untrusted. Records with no client IP are not attributed either way. Microsoft's
        ASN (8075) is never trusted on its own, because attackers run from Azure too; it is only
        exempt from the hosting-provider finding. Pass -TrustedAsn 8075 to trust it.

        Findings:
          Critical  a suspicious inbox rule or forwarding change from an untrusted address
          High      a suspicious inbox rule from anywhere; a successful sign-in from a hosting,
                    proxy or VPN address or from outside -ExpectedCountry; a mailbox folder synced
                    (downloaded) from an untrusted address; an app consent from an untrusted address
          Medium    app consents; messages read, sent or hard-deleted from an untrusted address;
                    any activity from a hosting/proxy address or outside -ExpectedCountry; rule
                    changes from an untrusted address
          Low       soft deletes from an untrusted address; failed sign-ins from hosting/proxy addresses

        Untrusted activity is grouped per user and address, so one attacker session is one finding.

        Client IPs are looked up on ip-api.com (Resolve-NSPIpInfo) unless -SkipIpLookup: plain
        HTTP, non-commercial licence. Without the lookup the hosting and country findings are skipped.
    .PARAMETER Path
        One or more Purview audit CSV exports.
    .PARAMETER TrustedIP
        Known-good addresses (office egress, the user's home ISP): exact, CIDR, or a prefix ending in '*'.
    .PARAMETER TrustedAsn
        Known-good ASNs ('7018' or 'AS7018'), e.g. the user's home ISP or mobile carrier.
    .PARAMETER ExpectedCountry
        Two-letter country codes the users sign in from (US). Activity elsewhere is a finding.
    .PARAMETER InternalDomain
        The tenant's own domains, so internal forwarding isn't flagged.
    .PARAMETER OutputPath
        Report folder. Defaults to .\AuditTriage_<timestamp>.
    .PARAMETER SkipIpLookup
        Don't send the client IPs to ip-api.com.
    .PARAMETER PassThru
        Also return the findings.
    .EXAMPLE
        Invoke-NSPM365AuditTriage -Path .\audit.csv -TrustedIP 198.51.100.10 -ExpectedCountry US -InternalDomain contoso.com
    .EXAMPLE
        Invoke-NSPM365AuditTriage -Path .\jdoe-1.csv, .\jdoe-2.csv -TrustedIP 198.51.100.0/24 -TrustedAsn 7018, 22394 -OutputPath .\jdoe-triage
    .NOTES
        Export with every operation for the user (no operation filter) and a window starting
        well before the suspected compromise. MailItemsAccessed needs audit logging enabled for
        the mailbox; E3 tenants have it since 2024.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string[]]$Path,
        [string[]]$TrustedIP = @(),
        [string[]]$TrustedAsn = @(),
        [string[]]$ExpectedCountry = @(),
        [string[]]$InternalDomain = @(),
        [string]$OutputPath,
        [switch]$SkipIpLookup,
        [switch]$PassThru
    )

    $ErrorActionPreference = 'Stop'
    if (-not $OutputPath) { $OutputPath = Join-Path (Get-Location).ProviderPath ('AuditTriage_{0}' -f (Get-Date -Format 'yyyyMMdd_HHmmss')) }
    if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
    $OutputPath = (Resolve-Path -LiteralPath $OutputPath).ProviderPath
    $label = @($Path | ForEach-Object { [IO.Path]::GetFileNameWithoutExtension($_) }) -join '+'
    $hunt = @{ TenantLabel = $label; Findings = New-Object System.Collections.Generic.List[object] }

    $records = Read-NSPAuditCsv -Path $Path
    $views = @(foreach ($record in $records) { ConvertTo-NSPAuditView $record })
    $span = if ($views.Count) { "$($views[0].TimeUtc) -> $($views[-1].TimeUtc)" } else { 'no records' }
    Write-Host "Audit triage: $($views.Count) record(s) from $(@($Path).Count) file(s), $span. Output: $OutputPath" -ForegroundColor Cyan
    if (-not $TrustedIP -and -not $TrustedAsn) { Write-Warning 'No -TrustedIP or -TrustedAsn: every address counts as untrusted, so expect noise.' }
    if ($ExpectedCountry -and $SkipIpLookup) { Write-Warning '-ExpectedCountry needs the IP lookup; it is ignored with -SkipIpLookup.' }

    # Per-address facts, computed once.
    $ips = @($views | ForEach-Object ClientIP | Where-Object { $_ } | Sort-Object -Unique)
    $info = @{}
    if (-not $SkipIpLookup -and $ips.Count) {
        Write-Host "Looking up $($ips.Count) address(es) on ip-api.com..." -ForegroundColor DarkGray
        foreach ($result in (Resolve-NSPIpInfo -IPAddress $ips)) { $info[$result.IP] = $result }
    }
    $asns = @($TrustedAsn | ForEach-Object { ([string]$_) -replace '^(?i)AS', '' })
    $countries = @($ExpectedCountry | ForEach-Object { $_.ToUpperInvariant() })
    $trust = @{ '' = '' }
    $risky = @{}
    $foreign = @{}
    foreach ($ip in $ips) {
        $i = $info[$ip]
        $trusted = (Test-NSPIpInRange -Ip $ip -Range $TrustedIP) -or ($i -and $i.Asn -and $asns -contains $i.Asn)
        $trust[$ip] = if ($trusted) { 'Trusted' } else { 'Untrusted' }
        $risky[$ip] = [bool]($i -and ($i.Hosting -or $i.Proxy) -and $i.Asn -ne $script:NSPMicrosoftAsn)
        $foreign[$ip] = [bool]($i -and $countries.Count -and $i.CountryCode -and $countries -notcontains $i.CountryCode)
    }
    $where = {
        param($ip)
        $i = $info[$ip]
        if (-not $i -or $i.Status -ne 'success') { return $ip }
        "$ip ($(@($i.City, $i.CountryCode, $i.Isp, $(if ($i.Asn) { "AS$($i.Asn)" }) | Where-Object { $_ }) -join ', '))"
    }
    $untrusted = { param($ip) $ip -and $trust[$ip] -eq 'Untrusted' }
    $geoColumns = {
        param($ip)
        $i = $info[$ip]
        [ordered]@{ CountryCode = if ($i) { $i.CountryCode } else { '' }; City = if ($i) { $i.City } else { '' }; Isp = if ($i) { $i.Isp } else { '' }; Asn = if ($i) { $i.Asn } else { '' }; Hosting = if ($i) { $i.Hosting } else { '' }; Proxy = if ($i) { $i.Proxy } else { '' } }
    }
    $write = {
        param($Rows, $Name)
        @($Rows) | Export-Csv -LiteralPath (Join-Path $OutputPath $Name) -NoTypeInformation -Encoding UTF8
    }
    # One finding per user and address for untrusted activity of one kind.
    $grouped = {
        param($Rows, $Severity, $Check, $What)
        foreach ($g in ($Rows | Group-Object UserId, ClientIP)) {
            $first = $g.Group[0]
            $times = @($g.Group | ForEach-Object TimeUtc | Sort-Object)
            Add-NSPHuntFinding -Hunt $hunt -Severity $Severity -Check $Check -Object $first.UserId -Time $times[0] `
                -Detail ("{0} {1} from {2}, {3} -> {4}." -f $g.Count, $What, (& $where $first.ClientIP), $times[0], $times[-1])
        }
    }

    # Timeline, IPs, Summary.
    & $write @(foreach ($v in $views) {
            $row = [ordered]@{ TimeUtc = $v.TimeUtc; Operation = $v.Operation; Workload = $v.Workload; UserId = $v.UserId; ClientIP = $v.ClientIP; Trust = $trust[$v.ClientIP] }
            $geo = & $geoColumns $v.ClientIP
            foreach ($key in 'CountryCode', 'Isp', 'Asn') { $row[$key] = $geo[$key] }
            $row.ResultStatus = $v.ResultStatus
            $row.RecordId = $v.RecordId
            $row.AuditData = if ($v.Record.PSObject.Properties['_Raw'] -and $v.Record._Raw.AuditData) { [string]$v.Record._Raw.AuditData } else { ConvertTo-Json -InputObject $v.Record.AuditData -Depth 10 -Compress }
            [pscustomobject]$row
        }) 'Timeline.csv'

    $ipRows = @(foreach ($g in ($views | Where-Object ClientIP | Group-Object ClientIP)) {
            $i = $info[$g.Name]
            $times = @($g.Group | ForEach-Object TimeUtc | Sort-Object)
            [pscustomobject]@{
                ClientIP    = $g.Name
                Trust       = $trust[$g.Name]
                Count       = $g.Count
                FirstUtc    = $times[0]
                LastUtc     = $times[-1]
                Users       = @($g.Group | ForEach-Object UserId | Sort-Object -Unique) -join '; '
                Operations  = @($g.Group | ForEach-Object Operation | Sort-Object -Unique) -join '; '
                CountryCode = if ($i) { $i.CountryCode } else { '' }
                Country     = if ($i) { $i.Country } else { '' }
                Region      = if ($i) { $i.Region } else { '' }
                City        = if ($i) { $i.City } else { '' }
                Isp         = if ($i) { $i.Isp } else { '' }
                Org         = if ($i) { $i.Org } else { '' }
                Asn         = if ($i) { $i.Asn } else { '' }
                AsName      = if ($i) { $i.AsName } else { '' }
                Hosting     = if ($i) { $i.Hosting } else { '' }
                Proxy       = if ($i) { $i.Proxy } else { '' }
                Mobile      = if ($i) { $i.Mobile } else { '' }
            }
        })
    & $write @($ipRows | Sort-Object @{ Expression = { $_.Trust -eq 'Trusted' } }, @{ Expression = 'Count'; Descending = $true }) 'IPs.csv'

    & $write @(foreach ($g in ($views | Group-Object Operation | Sort-Object Count -Descending)) {
            $times = @($g.Group | ForEach-Object TimeUtc | Sort-Object)
            $bad = @($g.Group | Where-Object { & $untrusted $_.ClientIP })
            [pscustomobject]@{
                Operation      = $g.Name
                Count          = $g.Count
                UntrustedCount = $bad.Count
                FirstUtc       = $times[0]
                LastUtc        = $times[-1]
                Users          = @($g.Group | ForEach-Object UserId | Sort-Object -Unique) -join '; '
                UntrustedIPs   = @($bad | ForEach-Object ClientIP | Sort-Object -Unique) -join '; '
            }
        }) 'Summary.csv'

    # Sign-ins.
    $signIns = @(foreach ($v in ($views | Where-Object { $_.Operation -in 'UserLoggedIn', 'UserLoginFailed' })) {
            $audit = $v.Record.AuditData
            $extended = if ($audit.PSObject.Properties['ExtendedProperties']) { $audit.ExtendedProperties } else { @() }
            $row = [ordered]@{ TimeUtc = $v.TimeUtc; Operation = $v.Operation; UserId = $v.UserId; ClientIP = $v.ClientIP; Trust = $trust[$v.ClientIP] }
            $geo = & $geoColumns $v.ClientIP
            foreach ($key in $geo.Keys) { $row[$key] = $geo[$key] }
            $row.ResultStatus = $v.ResultStatus
            $row.LogonError = if ($audit.PSObject.Properties['LogonError']) { [string]$audit.LogonError } else { '' }
            $row.ErrorNumber = if ($audit.PSObject.Properties['ErrorNumber']) { [string]$audit.ErrorNumber } else { '' }
            $row.UserAgent = [string](Get-NSPAuditNameValue $extended 'UserAgent')
            $row.RequestType = [string](Get-NSPAuditNameValue $extended 'RequestType')
            $row.ApplicationId = if ($audit.PSObject.Properties['ApplicationId']) { [string]$audit.ApplicationId } else { '' }
            $row.RecordId = $v.RecordId
            [pscustomobject]$row
        })
    & $write $signIns 'SignIns.csv'
    $success = @($signIns | Where-Object { $_.Operation -eq 'UserLoggedIn' -and (& $untrusted $_.ClientIP) })
    & $grouped @($success | Where-Object { $risky[$_.ClientIP] }) 'High' 'Sign-in' 'successful sign-in(s) from a hosting/proxy/VPN address'
    & $grouped @($success | Where-Object { -not $risky[$_.ClientIP] -and $foreign[$_.ClientIP] }) 'High' 'Sign-in' 'successful sign-in(s) from outside the expected countries'
    & $grouped @($signIns | Where-Object { $_.Operation -eq 'UserLoginFailed' -and (& $untrusted $_.ClientIP) -and $risky[$_.ClientIP] }) 'Low' 'Sign-in' 'failed sign-in(s) from a hosting/proxy/VPN address'

    # Mail read.
    $accessed = @(Get-NSPM365AccessedMessage -InputObject $records | Select-Object *, @{ Name = 'Trust'; Expression = { $trust[$_.ClientIP] } })
    & $write $accessed 'AccessedMail.csv'
    $badAccess = @($accessed | Where-Object { & $untrusted $_.ClientIP })
    & $grouped @($badAccess | Where-Object MailAccessType -EQ 'Sync') 'High' 'Mail read' 'folder sync(s) - whole folders downloaded -'
    & $grouped @($badAccess | Where-Object MailAccessType -NE 'Sync') 'Medium' 'Mail read' 'message(s) opened'

    # Inbox rules and forwarding.
    $rules = @(Get-NSPM365InboxRuleAudit -InputObject $records -InternalDomain $InternalDomain | Select-Object *, @{ Name = 'Trust'; Expression = { $trust[$_.ClientIP] } })
    & $write $rules 'InboxRules.csv'
    foreach ($rule in $rules) {
        $fromBad = & $untrusted $rule.ClientIP
        $object = if ($rule.RuleName) { "$($rule.UserId): $($rule.RuleName)" } else { "$($rule.UserId): $($rule.Operation)" }
        $detail = "$($rule.Operation) from $(& $where $rule.ClientIP)"
        if ($rule.Flags) { $detail += ". Flags: $($rule.Flags)" }
        if ($rule.ForwardTo) { $detail += ". Forwards to: $($rule.ForwardTo)" }
        if ($rule.MoveToFolder) { $detail += ". Moves to: $($rule.MoveToFolder)" }
        if ($rule.Suspicious) {
            Add-NSPHuntFinding -Hunt $hunt -Severity $(if ($fromBad) { 'Critical' } else { 'High' }) -Check 'Inbox rule' -Object $object -Detail $detail -Time $rule.TimeUtc
        } elseif ($fromBad -and $rule.Operation -notin 'Remove-InboxRule', 'Disable-InboxRule') {
            Add-NSPHuntFinding -Hunt $hunt -Severity Medium -Check 'Inbox rule' -Object $object -Detail "$detail. Not flagged, but changed from an untrusted address." -Time $rule.TimeUtc
        }
    }

    # App consents, sends, deletes.
    foreach ($v in ($views | Where-Object { $script:NSPConsentOperations -contains $_.Operation })) {
        $target = if ($v.Record.AuditData.PSObject.Properties['ObjectId']) { [string]$v.Record.AuditData.ObjectId } else { '' }
        Add-NSPHuntFinding -Hunt $hunt -Severity $(if (& $untrusted $v.ClientIP) { 'High' } else { 'Medium' }) -Check 'App consent' -Object $v.UserId -Time $v.TimeUtc `
            -Detail "$($v.Operation.TrimEnd('.')) $target from $(& $where $v.ClientIP). Check the app's permissions and publisher."
    }
    $badViews = @($views | Where-Object { & $untrusted $_.ClientIP })
    & $grouped @($badViews | Where-Object { $_.Operation -in 'Send', 'SendAs', 'SendOnBehalf' }) 'Medium' 'Mail sent' 'message(s) sent'
    & $grouped @($badViews | Where-Object Operation -EQ 'HardDelete') 'Medium' 'Mail deleted' 'hard delete(s)'
    & $grouped @($badViews | Where-Object { $_.Operation -in 'SoftDelete', 'MoveToDeletedItems' }) 'Low' 'Mail deleted' 'soft delete(s) / move(s) to Deleted Items'

    # Activity from hosting providers or unexpected countries, per address.
    foreach ($row in ($ipRows | Where-Object { $_.Trust -eq 'Untrusted' -and ($risky[$_.ClientIP] -or $foreign[$_.ClientIP]) })) {
        $why = @($(if ($risky[$row.ClientIP]) { 'a hosting/proxy/VPN address' }), $(if ($foreign[$row.ClientIP]) { 'outside the expected countries' }) | Where-Object { $_ }) -join ', '
        Add-NSPHuntFinding -Hunt $hunt -Severity Medium -Check 'Address' -Object (& $where $row.ClientIP) -Time $row.FirstUtc `
            -Detail "$($row.Count) record(s) from $why, $($row.FirstUtc) -> $($row.LastUtc). Users: $($row.Users). Operations: $($row.Operations)."
    }

    $sorted = @($hunt.Findings | Sort-Object @{ Expression = { $script:NSPHuntSeverityOrder[$_.Severity] } }, TimeUtc)
    & $write $sorted 'Findings.csv'

    Write-Host ''
    Write-Host '=== Summary ===' -ForegroundColor Cyan
    [pscustomobject]@{
        Records   = $views.Count
        Addresses = $ips.Count
        Untrusted = @($ips | Where-Object { $trust[$_] -eq 'Untrusted' }).Count
        Critical  = @($sorted | Where-Object Severity -EQ 'Critical').Count
        High      = @($sorted | Where-Object Severity -EQ 'High').Count
        Medium    = @($sorted | Where-Object Severity -EQ 'Medium').Count
        Low       = @($sorted | Where-Object Severity -EQ 'Low').Count
    } | Format-Table -AutoSize | Out-Host
    Write-Host "Findings: $(Join-Path $OutputPath 'Findings.csv')"
    if ($PassThru) { $sorted }
}
