function Resolve-NSPIpInfo {
    <#
    .SYNOPSIS
        Looks up the country, ISP, ASN and hosting/proxy/mobile flags of IP addresses through ip-api.com, 100 per request.
    .DESCRIPTION
        Addresses are de-duplicated, ports and brackets stripped ("203.0.113.5:51234",
        "[2001:db8::1]:443"), and looked up through ip-api.com's batch endpoint, waiting out its
        rate limit (X-Rl / X-Ttl headers) between batches. Results are cached for the session,
        so the same address is never looked up twice; -NoCache looks them up again.

        Private and reserved addresses come back with Status 'fail' and ip-api's reason in
        Message.

        ip-api.com's free endpoint is plain HTTP and licensed for non-commercial use: the
        addresses cross the internet unencrypted. Check its terms before using it for client work.
    .PARAMETER IPAddress
        One or more addresses. Takes pipeline input, including objects with an IP, ClientIP or
        Query property.
    .PARAMETER NoCache
        Look the addresses up again even when this session already has them.
    .EXAMPLE
        Resolve-NSPIpInfo 203.0.113.5, 198.51.100.7
    .EXAMPLE
        Get-NSPM365AuditSummary -Path .\audit.csv -GroupBy ClientIP | Resolve-NSPIpInfo | Where-Object Hosting
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('IP', 'ClientIP', 'Query', 'Name')]
        [AllowEmptyString()]
        [string[]]$IPAddress,
        [switch]$NoCache
    )

    begin {
        $wanted = New-Object System.Collections.Generic.List[string]
        if ($null -eq $script:NSPIpInfoCache) { $script:NSPIpInfoCache = @{} }
    }
    process {
        foreach ($value in $IPAddress) {
            $ip = ConvertTo-NSPAuditIp $value
            if ($ip -and -not $wanted.Contains($ip)) { $wanted.Add($ip) }
        }
    }
    end {
        $lookup = @($wanted | Where-Object { $NoCache -or -not $script:NSPIpInfoCache.ContainsKey($_) })
        for ($start = 0; $start -lt $lookup.Count; $start += 100) {
            $batch = @($lookup[$start..([math]::Min($start + 99, $lookup.Count - 1))])
            Write-Verbose "ip-api.com: looking up $($batch.Count) address(es) ($($start + 1)-$($start + $batch.Count) of $($lookup.Count))."
            $body = ConvertTo-Json -InputObject $batch -Compress
            $response = Invoke-WebRequest -Method Post -Uri $script:NSPIpApiUri -Body $body -ContentType 'application/json' -UseBasicParsing -ErrorAction Stop
            foreach ($result in (ConvertFrom-Json -InputObject $response.Content)) {
                $asn = if ($result.as -match '^AS(?<n>\d+)') { $Matches.n } else { '' }
                $script:NSPIpInfoCache[[string]$result.query] = [pscustomobject]@{
                    IP          = [string]$result.query
                    Status      = [string]$result.status
                    Message     = [string]$result.message
                    Country     = [string]$result.country
                    CountryCode = [string]$result.countryCode
                    Region      = [string]$result.regionName
                    City        = [string]$result.city
                    Isp         = [string]$result.isp
                    Org         = [string]$result.org
                    Asn         = $asn
                    AsName      = [string]$result.asname
                    Mobile      = [bool]$result.mobile
                    Proxy       = [bool]$result.proxy
                    Hosting     = [bool]$result.hosting
                }
            }
            # X-Rl: requests left in this window; X-Ttl: seconds until it resets.
            $left = @($response.Headers['X-Rl'])[0]
            $ttl = @($response.Headers['X-Ttl'])[0]
            if (($start + 100) -lt $lookup.Count -and "$left" -eq '0') {
                $wait = [int]$ttl + 1
                Write-Host "ip-api.com rate limit reached - waiting $wait s." -ForegroundColor DarkGray
                Start-Sleep -Seconds $wait
            }
        }
        foreach ($ip in $wanted) {
            if ($script:NSPIpInfoCache.ContainsKey($ip)) { $script:NSPIpInfoCache[$ip] }
            else {
                [pscustomobject]@{ IP = $ip; Status = 'fail'; Message = 'No result returned'; Country = ''; CountryCode = ''; Region = ''; City = ''; Isp = ''; Org = ''; Asn = ''; AsName = ''; Mobile = $false; Proxy = $false; Hosting = $false }
            }
        }
    }
}

$script:NSPIpApiUri = 'http://ip-api.com/batch?fields=status,message,query,country,countryCode,regionName,city,isp,org,as,asname,mobile,proxy,hosting'
