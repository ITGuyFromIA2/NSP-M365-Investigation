# Helpers shared by the Unified Audit Log, inbox rule, message trace and IP functions.

function Import-NSPLogParse {
    # Loads NSP.LogParse on first use (ConvertFrom-NSPM365AuditCsv, Expand-NSPM365AuditRecord).
    Import-NSPToolkitModule -Name 'NSP.LogParse' -MinimumVersion '0.1.0'
}

function Read-NSPAuditCsv {
    # Parsed audit records from one or more Purview audit CSV exports, oldest first.
    param([Parameter(Mandatory)][string[]]$Path)
    Import-NSPLogParse
    $records = @(foreach ($file in $Path) { ConvertFrom-NSPM365AuditCsv -Path $file })
    , @($records | Sort-Object { Get-NSPAuditTime $_ })
}

function ConvertTo-NSPAuditIp {
    # Exchange writes ClientIP with a port ("203.0.113.5:51234", "[2001:db8::1]:443") and
    # sometimes IPv4-mapped IPv6; everything else writes a bare address.
    param([string]$Value)
    if (-not $Value) { return '' }
    $ip = $Value.Trim()
    if ($ip -match '^\[(?<ip>[^\]]+)\](:\d+)?$') { $ip = $Matches.ip }
    elseif ($ip -match '^(?<ip>\d{1,3}(\.\d{1,3}){3}):\d+$') { $ip = $Matches.ip }
    if ($ip -match '^::ffff:(?<ip>\d{1,3}(\.\d{1,3}){3})$') { $ip = $Matches.ip }
    $ip
}

function Get-NSPAuditClientIp {
    # The client address, whichever property this workload put it in.
    param($AuditData)
    if ($null -eq $AuditData) { return '' }
    foreach ($name in 'ClientIP', 'ClientIPAddress', 'ActorIpAddress', 'UserIp') {
        $property = $AuditData.PSObject.Properties[$name]
        if ($property -and $property.Value) { return (ConvertTo-NSPAuditIp ([string]$property.Value)) }
    }
    ''
}

function Get-NSPAuditTime {
    param($Record)
    $value = $null
    if ($Record.AuditData -and $Record.AuditData.PSObject.Properties['CreationTime']) { $value = $Record.AuditData.CreationTime }
    if (-not $value) { $value = $Record.CreationDate }
    Format-NSPHuntUtc $value
}

function Get-NSPAuditNameValue {
    # Value of one entry in the Name/Value arrays audit records use (Parameters,
    # OperationProperties, ExtendedProperties).
    param($List, [Parameter(Mandatory)][string]$Name)
    foreach ($entry in @($List)) {
        if ($entry -and $entry.PSObject.Properties['Name'] -and [string]$entry.Name -eq $Name) { return $entry.Value }
    }
    $null
}

function ConvertTo-NSPAuditView {
    # One normalized row per record: the columns every audit report starts from.
    param([Parameter(Mandatory)]$Record)
    $audit = $Record.AuditData
    $value = { param($n) if ($audit -and $audit.PSObject.Properties[$n]) { [string]$audit.$n } else { '' } }
    [pscustomobject]@{
        TimeUtc      = Get-NSPAuditTime $Record
        Operation    = [string]$Record.Operation
        Workload     = & $value 'Workload'
        UserId       = if ($Record.UserId) { [string]$Record.UserId } else { & $value 'UserId' }
        ClientIP     = Get-NSPAuditClientIp $audit
        ResultStatus = & $value 'ResultStatus'
        RecordId     = [string]$Record.RecordId
        Record       = $Record
    }
}

function Test-NSPIpInRange {
    # True when $Ip matches an entry: exact address, CIDR (IPv4 or IPv6), or a prefix ending in '*'.
    param([string]$Ip, [string[]]$Range)
    if (-not $Ip -or -not $Range) { return $false }
    $address = $null
    $parsed = [Net.IPAddress]::TryParse($Ip, [ref]$address)
    foreach ($entry in $Range) {
        if (-not $entry) { continue }
        if ($entry.Contains('/')) {
            $parts = $entry.Split('/', 2)
            $network = $null
            if (-not $parsed -or -not [Net.IPAddress]::TryParse($parts[0], [ref]$network) -or $network.AddressFamily -ne $address.AddressFamily) { continue }
            $a = $address.GetAddressBytes()
            $n = $network.GetAddressBytes()
            $bits = [int]$parts[1]
            $match = $true
            for ($i = 0; $i -lt $a.Length -and $bits -gt 0; $i++) {
                $mask = if ($bits -ge 8) { 255 } else { (0xFF -shl (8 - $bits)) -band 0xFF }
                if (($a[$i] -band $mask) -ne ($n[$i] -band $mask)) { $match = $false; break }
                $bits -= 8
            }
            if ($match) { return $true }
        } elseif ($entry.EndsWith('*')) {
            if ($Ip.StartsWith($entry.TrimEnd('*'), [StringComparison]::OrdinalIgnoreCase)) { return $true }
        } elseif ($Ip -eq $entry) { return $true }
    }
    $false
}

function Get-NSPFileEncoding {
    # Import-Csv -Encoding value from the byte order mark. Historical message trace exports are
    # UTF-16 LE; the rest are UTF-8, with or without a BOM.
    param([Parameter(Mandatory)][string]$Path)
    $bytes = New-Object byte[] 3
    $stream = [IO.File]::OpenRead($Path)
    try { $read = $stream.Read($bytes, 0, 3) } finally { $stream.Dispose() }
    if ($read -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) { return 'Unicode' }
    if ($read -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) { return 'BigEndianUnicode' }
    'UTF8'
}

function ConvertTo-NSPRuleTarget {
    # Forwarding targets as addresses. Get-InboxRule gives '"Name" [SMTP:a@b.com]' or
    # '"Name" [EX:/o=...]' (an internal recipient); audit Parameters give 'a@b.com;c@d.com'.
    param($Value)
    foreach ($item in @($Value)) {
        if (-not $item) { continue }
        foreach ($part in ([string]$item -split ';')) {
            $text = $part.Trim()
            if (-not $text) { continue }
            if ($text -match 'SMTP:(?<a>[^\]\s]+)') { $Matches.a }
            elseif ($text -match '\[EX:') { 'EX:' + ($text -replace '^"([^"]*)".*$', '$1') }
            else { $text.Trim('"') }
        }
    }
}

function Get-NSPInboxRuleFlag {
    # Why an inbox rule (or mailbox forwarding) looks like attacker tradecraft. Empty when it doesn't.
    # 'ForwardsInternal' is informational: every target is internal.
    param(
        [string]$Name,
        [string]$MoveToFolder,
        [string[]]$ForwardTarget = @(),
        [bool]$Delete,
        [bool]$MarkAsRead,
        [string]$Conditions,
        [string[]]$InternalDomain = @()
    )
    $flags = New-Object System.Collections.Generic.List[string]
    $targets = @($ForwardTarget | Where-Object { $_ })
    if ($targets.Count) {
        $external = @($targets | Where-Object {
                if ($_ -like 'EX:*') { return $false }
                $domain = ($_ -split '@')[-1]
                -not ($_ -like '*@*' -and @($InternalDomain | Where-Object { $_ -and $domain -eq $_ }).Count)
            })
        if ($external.Count) { $flags.Add('Forwards') } else { $flags.Add('ForwardsInternal') }
    }
    if ($Delete) { $flags.Add('Deletes') }
    if ($MarkAsRead) { $flags.Add('MarksRead') }
    if ($MoveToFolder) {
        $leaf = ($MoveToFolder -split '\\')[-1].Trim()
        if ($script:NSPRuleHidingFolders -contains $leaf) { $flags.Add("MovesTo:$leaf") }
    }
    # Mailbox forwarding has no name: only judge one that was passed.
    if ($PSBoundParameters.ContainsKey('Name') -and $Name -notmatch '[\p{L}\p{N}]{3}') { $flags.Add('OddName') }
    if ($Conditions -and $Conditions -match $script:NSPRuleKeywordPattern) { $flags.Add('TargetsKeywords') }
    $flags.ToArray()
}

# Folders attackers move mail into so the victim never sees replies.
$script:NSPRuleHidingFolders = @('RSS Feeds', 'RSS Subscriptions', 'Conversation History', 'Archive', 'Junk Email', 'Junk E-mail', 'Deleted Items', 'Notes', 'Sync Issues', 'Outbox')

# Rule conditions that hide replies about the fraud or the compromise.
$script:NSPRuleKeywordPattern = '(?i)\b(invoice|payment|wire|ach|bank|remit|payroll|w-?2|hack|hacked|phish|spam|compromis|suspicious|password|mfa|helpdesk|help desk|virus|scam|fraud)'

# Audit operations that change inbox rules or mailbox forwarding.
$script:NSPRuleOperations = @('New-InboxRule', 'Set-InboxRule', 'Enable-InboxRule', 'Disable-InboxRule', 'Remove-InboxRule', 'UpdateInboxRules', 'Set-Mailbox')

# Audit operations that grant an app access to the tenant or a user's data.
$script:NSPConsentOperations = @('Consent to application.', 'Add delegated permission grant.', 'Add app role assignment grant to user.', 'Add app role assignment to service principal.', 'Add service principal.')

# Microsoft's ASN. Exchange-side activity comes from it, but so do Azure VMs: never trusted
# implicitly, only exempt from the hosting-provider finding. Pass -TrustedAsn 8075 to trust it.
$script:NSPMicrosoftAsn = '8075'
