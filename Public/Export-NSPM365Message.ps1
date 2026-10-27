function Export-NSPM365Message {
    <#
    .SYNOPSIS
        Saves mailbox messages, found by InternetMessageId, as .eml files with a SHA-256 manifest - the messages an attacker read, from Get-NSPM365AccessedMessage.
    .DESCRIPTION
        For each mailbox and InternetMessageId, finds the message in the mailbox through
        Microsoft Graph (any folder, Deleted Items included) and saves its full MIME content as
        <OutputPath>\<mailbox>\<received>_<subject>.eml. Manifest.csv lists every request with
        its status (Exported, NotFound, Failed), the file and its SHA-256 hash.

        Takes Get-NSPM365AccessedMessage rows from the pipeline (mailbox from MailboxOwnerUPN,
        else UserId; Sync rows have no InternetMessageId and are skipped), or -Mailbox with
        -InternetMessageId. Duplicates are fetched once.

        NotFound usually means the message was purged (hard-deleted past Recoverable Items) or
        lives in another mailbox; the audit record still proves it was read.

        Read-only. Sign-in goes through NSP.M365.Graph: app-only with -ClientId and
        -CertificateThumbprint (Mail.Read application permission - the usual route for someone
        else's mailbox), or delegated with Mail.Read.Shared, which also needs Full Access to the
        mailbox.
    .PARAMETER InputObject
        Rows with an InternetMessageId and a MailboxOwnerUPN, UserId or Mailbox property.
    .PARAMETER Mailbox
        The mailbox (UPN) to search.
    .PARAMETER InternetMessageId
        One or more InternetMessageIds ('<abc@namprd13.prod.outlook.com>').
    .PARAMETER OutputPath
        Export folder. Defaults to .\MessageExport_<timestamp>.
    .PARAMETER TenantId
        Tenant ID or domain to sign in to.
    .PARAMETER ClientId
        App-only: an app with the Mail.Read application permission in the tenant. Needs -CertificateThumbprint.
    .PARAMETER CertificateThumbprint
        Certificate for -ClientId.
    .PARAMETER UseDeviceCode
        Delegated sign-in with a device code.
    .EXAMPLE
        Get-NSPM365AccessedMessage -Path .\audit.csv | Where-Object ClientIP -eq 203.0.113.50 | Export-NSPM365Message -TenantId contoso.com -ClientId $appId -CertificateThumbprint $thumb
    .EXAMPLE
        Export-NSPM365Message -Mailbox jdoe@contoso.com -InternetMessageId '<abc@contoso.com>' -OutputPath .\evidence
    #>
    [CmdletBinding(DefaultParameterSetName = 'Pipeline')]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Pipeline')]
        [psobject[]]$InputObject,
        [Parameter(Mandatory, ParameterSetName = 'Explicit')]
        [string]$Mailbox,
        [Parameter(Mandatory, ParameterSetName = 'Explicit')]
        [string[]]$InternetMessageId,
        [string]$OutputPath,
        [string]$TenantId,
        [string]$ClientId,
        [string]$CertificateThumbprint,
        [switch]$UseDeviceCode
    )

    begin {
        if ([bool]$ClientId -ne [bool]$CertificateThumbprint) { throw 'App-only sign-in needs both -ClientId and -CertificateThumbprint.' }
        $wanted = New-Object System.Collections.Generic.List[object]
        $seen = @{}
        $add = {
            param($Box, $Id)
            $Box = ([string]$Box).Trim()
            $Id = ([string]$Id).Trim()
            if (-not $Box -or -not $Id) { return }
            $key = "$($Box.ToLowerInvariant())|$Id"
            if ($seen.ContainsKey($key)) { return }
            $seen[$key] = $true
            $wanted.Add([pscustomobject]@{ Mailbox = $Box; InternetMessageId = $Id })
        }
    }
    process {
        if ($PSCmdlet.ParameterSetName -eq 'Explicit') {
            foreach ($id in $InternetMessageId) { & $add $Mailbox $id }
            return
        }
        foreach ($row in $InputObject) {
            if ($null -eq $row -or -not $row.PSObject.Properties['InternetMessageId']) { continue }
            $box = foreach ($name in 'MailboxOwnerUPN', 'Mailbox', 'UserId') {
                if ($row.PSObject.Properties[$name] -and $row.$name) { [string]$row.$name; break }
            }
            & $add $box $row.InternetMessageId
        }
    }
    end {
        $ErrorActionPreference = 'Stop'
        if (-not $wanted.Count) { Write-Warning 'No messages to export (rows need an InternetMessageId and a mailbox).'; return }
        if (-not $OutputPath) { $OutputPath = Join-Path (Get-Location).ProviderPath ('MessageExport_{0}' -f (Get-Date -Format 'yyyyMMdd_HHmmss')) }
        if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
        $OutputPath = (Resolve-Path -LiteralPath $OutputPath).ProviderPath

        Import-NSPM365Graph
        $tenant = if ($TenantId) { Resolve-NSPHuntTenantId -Tenant $TenantId } else { $null }
        Connect-NSPHuntTenant -TenantId $tenant -Scopes @('Mail.Read.Shared') -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -UseDeviceCode:$UseDeviceCode
        $fake = (Get-NSPGraphTransport).Name -eq 'Fake'
        Write-Host "Exporting $($wanted.Count) message(s) to $OutputPath" -ForegroundColor Cyan

        $manifest = New-Object System.Collections.Generic.List[object]
        $row = {
            param($Want, $Status, $Message, $File, $Note)
            $entry = [pscustomobject]@{
                Mailbox           = $Want.Mailbox
                InternetMessageId = $Want.InternetMessageId
                Status            = $Status
                Subject           = if ($Message) { [string]$Message['subject'] } else { '' }
                From              = if ($Message) { [string](Get-NSPHuntValue $Message @('from', 'emailAddress', 'address')) } else { '' }
                ReceivedUtc       = if ($Message) { Format-NSPHuntUtc $Message['receivedDateTime'] } else { '' }
                File              = if ($File) { $File.Substring($OutputPath.Length).TrimStart('\', '/') } else { '' }
                Sha256            = if ($File) { (Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash } else { '' }
                GraphId           = if ($Message) { [string]$Message['id'] } else { '' }
                Note              = $Note
            }
            $manifest.Add($entry)
            $entry
        }

        $index = 0
        foreach ($want in $wanted) {
            $index++
            Write-Progress -Activity 'Exporting messages' -Status "$($want.Mailbox): $($want.InternetMessageId)" -PercentComplete (100 * $index / $wanted.Count)
            $user = [uri]::EscapeDataString($want.Mailbox)
            try {
                $filter = "internetMessageId eq '$($want.InternetMessageId.Replace("'", "''"))'"
                $uri = New-NSPHuntFilterUri -Base "users/$user/messages" -Filter $filter -Extra '$select=id,subject,from,receivedDateTime'
                $found = @((Invoke-NSPGraphRetry { Invoke-NSPGraphRequest -Uri $uri })['value'] | Where-Object { $_ })
            } catch {
                & $row $want 'Failed' $null $null $_.Exception.Message
                continue
            }
            if (-not $found.Count) {
                & $row $want 'NotFound' $null $null 'Not in the mailbox: purged, or in another mailbox.'
                continue
            }
            $folder = Join-Path $OutputPath ($want.Mailbox -replace '[^\w\.@-]', '_')
            if (-not (Test-Path -LiteralPath $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
            $copy = 0
            foreach ($message in $found) {
                $copy++
                $stamp = try { (ConvertTo-NSPHuntUtc $message['receivedDateTime']).ToString('yyyyMMdd-HHmmss') } catch { 'unknown' }
                $subject = ([string]$message['subject'] -replace '[^\w\.\- ]', '_').Trim()
                if ($subject.Length -gt 60) { $subject = $subject.Substring(0, 60).Trim() }
                $base = "{0}_{1}" -f $stamp, $(if ($subject) { $subject } else { 'no-subject' })
                $file = Join-Path $folder "$base.eml"
                $n = 1
                while (Test-Path -LiteralPath $file) { $n++; $file = Join-Path $folder "$base ($n).eml" }
                $value = "users/$user/messages/$([uri]::EscapeDataString([string]$message['id']))/`$value"
                try {
                    if ($fake) {
                        [IO.File]::WriteAllText($file, [string](Invoke-NSPGraphRequest -Uri $value), (New-Object Text.UTF8Encoding $false))
                    } else {
                        Invoke-NSPGraphRetry { Invoke-MgGraphRequest -Method GET -Uri "v1.0/$value" -OutputFilePath $file -ErrorAction Stop } | Out-Null
                    }
                    $note = if ($found.Count -gt 1) { "Copy $copy of $($found.Count) in the mailbox." } else { '' }
                    & $row $want 'Exported' $message $file $note
                } catch {
                    & $row $want 'Failed' $message $null $_.Exception.Message
                }
            }
        }
        Write-Progress -Activity 'Exporting messages' -Completed

        $csv = Join-Path $OutputPath 'Manifest.csv'
        $manifest | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
        $counts = $manifest | Group-Object Status | ForEach-Object { "$($_.Name) $($_.Count)" }
        Write-Host "$($counts -join ', '). Manifest: $csv" -ForegroundColor Cyan
    }
}
