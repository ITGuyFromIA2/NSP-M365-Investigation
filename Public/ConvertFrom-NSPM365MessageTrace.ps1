function ConvertFrom-NSPM365MessageTrace {
    <#
    .SYNOPSIS
        Reads Exchange Online message trace CSVs, in either export format, as one row per recipient with sender and recipient domains split out.
    .DESCRIPTION
        Two formats are recognized by their header:

          Historical search (MTSummary_*.csv, UTF-16): origin_timestamp_utc, sender_address,
            recipient_status ('a@x.com##Receive, Deliver;b@y.com##Receive, Fail'),
            original_client_ip, directionality, ... One message per row; split into one row per
            recipient here.
          Message trace (the Exchange admin center export or Get-MessageTraceV2): Received,
            SenderAddress, RecipientAddress, Status, FromIP, ... Already one row per recipient.

        Every row comes out with the same columns:

          TimeUtc, Sender, SenderDomain, Recipient, RecipientDomain, Subject, Status, Direction,
          ClientIP, SizeBytes, MessageId, TraceId, SourceFile

        Direction and the historical search's original_client_ip (the sending client's address)
        are only in the historical format; for the other, ClientIP is FromIP.

        Pass a sender trace and a recipient trace together to read both directions at once.
    .PARAMETER Path
        One or more message trace CSVs. The encoding is read from the file's byte order mark.
    .EXAMPLE
        ConvertFrom-NSPM365MessageTrace .\MTSummary_jdoe_90DaySender.csv, .\MTSummary_jdoe_90DayRecipient.csv | Sort-Object TimeUtc | Out-GridView
    .EXAMPLE
        ConvertFrom-NSPM365MessageTrace .\trace.csv | Where-Object { $_.Subject -like '*shared*' -and $_.Status -eq 'Delivered' } | Group-Object RecipientDomain | Sort-Object Count -Descending

        Who a phishing blast sent from a compromised mailbox reached, by recipient domain.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('FullName')]
        [string[]]$Path
    )

    process {
        foreach ($file in $Path) {
            $resolved = (Resolve-Path -LiteralPath $file -ErrorAction Stop).ProviderPath
            $name = Split-Path -Leaf $resolved
            $rows = @(Import-Csv -LiteralPath $resolved -Encoding (Get-NSPFileEncoding $resolved))
            if (-not $rows.Count) { continue }
            $columns = @($rows[0].PSObject.Properties.Name)
            $domain = { param($address) if ($address -like '*@*') { ($address -split '@')[-1].ToLowerInvariant() } else { '' } }

            if ($columns -contains 'recipient_status') {
                foreach ($row in $rows) {
                    $from = [string]$row.sender_address
                    foreach ($entry in ([string]$row.recipient_status -split ';')) {
                        if (-not $entry.Trim()) { continue }
                        $parts = $entry -split '##', 2
                        $recipient = $parts[0].Trim()
                        [pscustomobject]@{
                            TimeUtc         = Format-NSPHuntUtc $row.origin_timestamp_utc
                            Sender          = $from
                            SenderDomain    = & $domain $from
                            Recipient       = $recipient
                            RecipientDomain = & $domain $recipient
                            Subject         = [string]$row.message_subject
                            Status          = if ($parts.Count -gt 1) { (($parts[1] -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -join ', ' } else { '' }
                            Direction       = [string]$row.directionality
                            ClientIP        = [string]$row.original_client_ip
                            SizeBytes       = [string]$row.total_bytes
                            MessageId       = [string]$row.message_id
                            TraceId         = [string]$row.network_message_id
                            SourceFile      = $name
                        }
                    }
                }
            } elseif ($columns -contains 'RecipientAddress') {
                foreach ($row in $rows) {
                    $from = [string]$row.SenderAddress
                    $recipient = [string]$row.RecipientAddress
                    [pscustomobject]@{
                        TimeUtc         = Format-NSPHuntUtc $row.Received
                        Sender          = $from
                        SenderDomain    = & $domain $from
                        Recipient       = $recipient
                        RecipientDomain = & $domain $recipient
                        Subject         = [string]$row.Subject
                        Status          = [string]$row.Status
                        Direction       = ''
                        ClientIP        = [string]$row.FromIP
                        SizeBytes       = [string]$row.Size
                        MessageId       = [string]$row.MessageId
                        TraceId         = [string]$row.MessageTraceId
                        SourceFile      = $name
                    }
                }
            } else {
                throw "$name is not a message trace export I recognize (expected a recipient_status or RecipientAddress column; found: $($columns -join ', '))."
            }
        }
    }
}
