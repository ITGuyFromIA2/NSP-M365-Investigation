function Get-NSPM365AuditSummary {
    <#
    .SYNOPSIS
        Summarizes a Unified Audit Log export by operation, client IP, user or workload: count, first and last time, and who/where/what.
    .DESCRIPTION
        Reads Purview audit CSV exports (-Path) or records already parsed by NSP.LogParse's
        ConvertFrom-NSPM365AuditCsv (pipeline). One row per group, most frequent first:

          Name, Count, FirstUtc, LastUtc, UserCount, IpCount, Users, ClientIPs, Operations, Workloads

        The client IP is read from whichever property the workload uses (ClientIP,
        ClientIPAddress, ActorIpAddress, UserIp), with Exchange's port suffix removed.

        -ExcludeIP leaves out records from known-good addresses (office egress, the user's home
        ISP): exact addresses, CIDR ranges, or prefixes ending in '*'.
    .PARAMETER Path
        One or more Purview audit CSV exports (Audit > Export results).
    .PARAMETER InputObject
        Parsed audit records (ConvertFrom-NSPM365AuditCsv).
    .PARAMETER GroupBy
        Operation (default), ClientIP, UserId or Workload.
    .PARAMETER ExcludeIP
        Addresses, CIDR ranges or '*'-suffixed prefixes to leave out.
    .EXAMPLE
        Get-NSPM365AuditSummary -Path .\audit.csv | Format-Table
    .EXAMPLE
        Get-NSPM365AuditSummary -Path .\audit.csv -GroupBy ClientIP -ExcludeIP 198.51.100.0/24 | Resolve-NSPIpInfo
    #>
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'Path')]
        [string[]]$Path,
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Record')]
        [psobject[]]$InputObject,
        [ValidateSet('Operation', 'ClientIP', 'UserId', 'Workload')]
        [string]$GroupBy = 'Operation',
        [string[]]$ExcludeIP = @()
    )

    begin { $records = New-Object System.Collections.Generic.List[object] }
    process { foreach ($record in $InputObject) { if ($null -ne $record) { $records.Add($record) } } }
    end {
        $source = if ($PSCmdlet.ParameterSetName -eq 'Path') { Read-NSPAuditCsv -Path $Path } else { $records.ToArray() }
        $views = @(foreach ($record in $source) {
                $view = ConvertTo-NSPAuditView $record
                if (-not (Test-NSPIpInRange -Ip $view.ClientIP -Range $ExcludeIP)) { $view }
            })
        $distinct = { param($rows, $property) @($rows | ForEach-Object $property | Where-Object { $_ } | Sort-Object -Unique) }
        foreach ($group in ($views | Group-Object -Property $GroupBy | Sort-Object Count -Descending)) {
            $times = @($group.Group | ForEach-Object TimeUtc | Where-Object { $_ } | Sort-Object)
            $users = & $distinct $group.Group 'UserId'
            $ips = & $distinct $group.Group 'ClientIP'
            [pscustomobject]@{
                Name       = $group.Name
                Count      = $group.Count
                FirstUtc   = if ($times.Count) { $times[0] } else { '' }
                LastUtc    = if ($times.Count) { $times[-1] } else { '' }
                UserCount  = $users.Count
                IpCount    = $ips.Count
                Users      = $users -join '; '
                ClientIPs  = $ips -join '; '
                Operations = (& $distinct $group.Group 'Operation') -join '; '
                Workloads  = (& $distinct $group.Group 'Workload') -join '; '
            }
        }
    }
}
