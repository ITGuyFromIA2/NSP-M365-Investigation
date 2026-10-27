function Get-NSPM365InboxRuleAudit {
    <#
    .SYNOPSIS
        Pulls inbox rule and mailbox forwarding changes out of Unified Audit Log records, flagging the ones that look like attacker tradecraft.
    .DESCRIPTION
        Covers New-/Set-/Enable-/Disable-/Remove-InboxRule (Exchange cmdlets and Outlook on the
        web), UpdateInboxRules (Outlook desktop), and Set-Mailbox when it changes forwarding.
        Rule parameters (Name, MoveToFolder, ForwardTo, DeleteMessage, ...) come out as columns
        so you don't have to dig through the Parameters array.

        Flags (the same as Get-NSPM365InboxRuleReport):
          Forwards          forwards or redirects outside -InternalDomain (anywhere, without it)
          ForwardsInternal  forwards only to internal recipients (informational)
          Deletes, MarksRead
          MovesTo:<folder>  RSS Feeds, Conversation History, Archive, Junk Email, Deleted Items, ...
          OddName           a name with no three letters or digits in a row ('.', '..', 'aa')
          TargetsKeywords   conditions on invoice / payment / wire / hacked / phish / password ...

        Suspicious is true when any flag other than ForwardsInternal is set.
    .PARAMETER Path
        One or more Purview audit CSV exports.
    .PARAMETER InputObject
        Parsed audit records (ConvertFrom-NSPM365AuditCsv).
    .PARAMETER InternalDomain
        The tenant's own domains, so internal forwarding isn't flagged.
    .EXAMPLE
        Get-NSPM365InboxRuleAudit -Path .\audit.csv | Where-Object Suspicious | Format-List
    .EXAMPLE
        Get-NSPM365InboxRuleAudit -Path .\audit.csv -InternalDomain contoso.com, contoso.onmicrosoft.com
    #>
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'Path')]
        [string[]]$Path,
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Record')]
        [psobject[]]$InputObject,
        [string[]]$InternalDomain = @()
    )

    begin {
        $domains = $InternalDomain
        $convert = {
            param($Record)
            $operation = [string]$Record.Operation
            if ($script:NSPRuleOperations -notcontains $operation -or $null -eq $Record.AuditData) { return }
            $audit = $Record.AuditData
            $parameters = if ($audit.PSObject.Properties['Parameters']) { $audit.Parameters } else { @() }
            $get = { param($n) $v = Get-NSPAuditNameValue $parameters $n; if ($null -eq $v) { '' } else { [string]$v } }

            if ($operation -eq 'UpdateInboxRules') {
                $properties = if ($audit.PSObject.Properties['OperationProperties']) { $audit.OperationProperties } else { @() }
                $actions = [string](Get-NSPAuditNameValue $properties 'RuleActions')
                $condition = [string](Get-NSPAuditNameValue $properties 'RuleCondition')
                $ruleName = [string](Get-NSPAuditNameValue $properties 'RuleName')
                $moveTo = ''
                $targets = @(if ($actions -match '(?i)forward|redirect') { 'unknown (see RuleActions)' })
                $delete = $actions -match '(?i)delete'
                $markRead = $actions -match '(?i)markasread|mark as read'
                $conditions = $condition
                $detail = "RuleOperation=$(Get-NSPAuditNameValue $properties 'RuleOperation'); RuleActions=$actions; RuleCondition=$condition"
            } else {
                if ($operation -eq 'Set-Mailbox' -and -not (@('ForwardingSmtpAddress', 'ForwardingAddress', 'DeliverToMailboxAndForward') | Where-Object { $null -ne (Get-NSPAuditNameValue $parameters $_) })) { return }
                $ruleName = & $get 'Name'
                if (-not $ruleName -and $operation -ne 'Set-Mailbox') { $ruleName = ((& $get 'Identity') -split '\\')[-1] }
                $moveTo = & $get 'MoveToFolder'
                $targets = @(ConvertTo-NSPRuleTarget @((& $get 'ForwardTo'), (& $get 'RedirectTo'), (& $get 'ForwardAsAttachmentTo'), (& $get 'ForwardingSmtpAddress'), (& $get 'ForwardingAddress')))
                $delete = (& $get 'DeleteMessage') -eq 'True' -or (& $get 'SoftDeleteMessage') -eq 'True'
                $markRead = (& $get 'MarkAsRead') -eq 'True'
                $conditions = @(foreach ($n in 'From', 'FromAddressContainsWords', 'SubjectContainsWords', 'SubjectOrBodyContainsWords', 'BodyContainsWords', 'SentTo', 'HeaderContainsWords') {
                        $v = & $get $n
                        if ($v) { "$n=$v" }
                    }) -join '; '
                $detail = @(foreach ($p in @($parameters)) { if ($p) { "$($p.Name)=$($p.Value)" } }) -join '; '
            }

            $flagArgs = @{ MoveToFolder = $moveTo; ForwardTarget = $targets; Delete = [bool]$delete; MarkAsRead = [bool]$markRead; Conditions = $conditions; InternalDomain = $domains }
            if ($operation -ne 'Set-Mailbox' -and $operation -ne 'Remove-InboxRule') { $flagArgs.Name = $ruleName }
            $flags = if ($operation -eq 'Remove-InboxRule' -or $operation -eq 'Disable-InboxRule') { @() } else { @(Get-NSPInboxRuleFlag @flagArgs) }
            [pscustomobject]@{
                TimeUtc      = Get-NSPAuditTime $Record
                Operation    = $operation
                UserId       = [string]$Record.UserId
                Mailbox      = if ($audit.PSObject.Properties['ObjectId']) { [string]$audit.ObjectId } else { '' }
                ClientIP     = Get-NSPAuditClientIp $audit
                RuleName     = $ruleName
                MoveToFolder = $moveTo
                ForwardTo    = $targets -join '; '
                DeleteMessage = [bool]$delete
                MarkAsRead   = [bool]$markRead
                Conditions   = $conditions
                Flags        = $flags -join '; '
                Suspicious   = [bool](@($flags | Where-Object { $_ -ne 'ForwardsInternal' }).Count)
                Detail       = $detail
                RecordId     = [string]$Record.RecordId
            }
        }
    }
    process { foreach ($record in $InputObject) { if ($null -ne $record) { & $convert $record } } }
    end {
        if ($PSCmdlet.ParameterSetName -eq 'Path') {
            foreach ($record in (Read-NSPAuditCsv -Path $Path)) { & $convert $record }
        }
    }
}
