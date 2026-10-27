function Get-NSPM365AccessedMessage {
    <#
    .SYNOPSIS
        Expands MailItemsAccessed audit records into one row per message read, with the access type (Bind or Sync), client IP and app.
    .DESCRIPTION
        A Bind record lists the individual messages opened: one row per message, with Subject,
        InternetMessageId and size. A Sync record means a client downloaded whole folders and has
        no per-message detail: one row per folder, Subject empty. Treat a Sync from an attacker's
        IP as every message in that folder read.

        InternetMessageId is what to search for (message trace, Graph, eDiscovery) to pull the
        messages themselves.

        Reads Purview audit CSV exports (-Path) or parsed records (pipeline); records other than
        MailItemsAccessed are skipped.
    .PARAMETER Path
        One or more Purview audit CSV exports.
    .PARAMETER InputObject
        Parsed audit records (ConvertFrom-NSPM365AuditCsv).
    .EXAMPLE
        Get-NSPM365AccessedMessage -Path .\audit.csv | Where-Object ClientIP -eq 203.0.113.5 | Export-Csv .\read-by-attacker.csv -NoTypeInformation
    .EXAMPLE
        Get-NSPM365AccessedMessage -Path .\audit.csv | Group-Object ClientIP, MailAccessType | Sort-Object Count -Descending
    #>
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'Path')]
        [string[]]$Path,
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Record')]
        [psobject[]]$InputObject
    )

    begin {
        Import-NSPLogParse
        $expand = {
            param($Record)
            if ([string]$Record.Operation -ne 'MailItemsAccessed' -or $null -eq $Record.AuditData) { return }
            $audit = $Record.AuditData
            $properties = if ($audit.PSObject.Properties['OperationProperties']) { $audit.OperationProperties } else { @() }
            $value = { param($n) if ($audit.PSObject.Properties[$n]) { [string]$audit.$n } else { '' } }
            $common = [ordered]@{
                TimeUtc          = Get-NSPAuditTime $Record
                UserId           = [string]$Record.UserId
                MailboxOwnerUPN  = & $value 'MailboxOwnerUPN'
                ClientIP         = Get-NSPAuditClientIp $audit
                MailAccessType   = [string](Get-NSPAuditNameValue $properties 'MailAccessType')
                IsThrottled      = [string](Get-NSPAuditNameValue $properties 'IsThrottled')
                AppId            = & $value 'AppId'
                ClientAppId      = & $value 'ClientAppId'
                ClientInfoString = & $value 'ClientInfoString'
            }
            foreach ($row in (Expand-NSPM365AuditRecord -InputObject $Record -ItemSource FolderItems -IncludeEmpty)) {
                $item = $row.Item
                $line = [ordered]@{}
                foreach ($key in $common.Keys) { $line[$key] = $common[$key] }
                $line.FolderPath = if ($row.Folder -and $row.Folder.PSObject.Properties['Path']) { [string]$row.Folder.Path } else { '' }
                $line.Subject = if ($item -and $item.PSObject.Properties['Subject']) { [string]$item.Subject } else { '' }
                $line.InternetMessageId = if ($item -and $item.PSObject.Properties['InternetMessageId']) { [string]$item.InternetMessageId } else { '' }
                $line.SizeBytes = if ($item -and $item.PSObject.Properties['SizeInBytes']) { $item.SizeInBytes } else { $null }
                $line.RecordId = [string]$Record.RecordId
                [pscustomobject]$line
            }
        }
    }
    process { foreach ($record in $InputObject) { if ($null -ne $record) { & $expand $record } } }
    end {
        if ($PSCmdlet.ParameterSetName -eq 'Path') {
            foreach ($record in (Read-NSPAuditCsv -Path $Path)) { & $expand $record }
        }
    }
}
