function Get-NSPM365InboxRuleReport {
    <#
    .SYNOPSIS
        Lists the inbox rules (hidden ones included) and mailbox forwarding of Exchange Online mailboxes, flagging the ones that look like attacker tradecraft.
    .DESCRIPTION
        Read-only. Needs an Exchange Online session (Connect-ExchangeOnline, from the
        ExchangeOnlineManagement module) with rights to read mailboxes and inbox rules.

        One row per rule (Kind 'InboxRule') and one per mailbox that forwards at the mailbox
        level (Kind 'MailboxForwarding'). The flags are Get-NSPM365InboxRuleAudit's: Forwards,
        ForwardsInternal, Deletes, MarksRead, MovesTo:<folder>, OddName, TargetsKeywords.
        Internal domains default to the tenant's accepted domains.

        Rules are read with -IncludeHidden. The built-in 'Junk E-mail Rule' is skipped. A rule
        hidden by editing its MAPI properties may still not show here: when a rule shows up in
        the audit log (Get-NSPM365InboxRuleAudit) but not here, look at the mailbox with MFCMAPI.

        To remove or disable what you've confirmed, pipe the rows to Remove-NSPM365InboxRule.
    .PARAMETER Mailbox
        Mailboxes to check. Defaults to every user and shared mailbox.
    .PARAMETER InternalDomain
        Domains that count as internal for forwarding. Defaults to Get-AcceptedDomain.
    .PARAMETER SuspiciousOnly
        Only the flagged rows.
    .EXAMPLE
        Connect-ExchangeOnline; Get-NSPM365InboxRuleReport -SuspiciousOnly | Format-Table Mailbox, RuleName, Flags, ForwardTo
    .EXAMPLE
        Get-NSPM365InboxRuleReport -Mailbox jdoe@contoso.com, ap@contoso.com | Export-Csv .\rules.csv -NoTypeInformation
    #>
    [CmdletBinding()]
    param(
        [string[]]$Mailbox,
        [string[]]$InternalDomain,
        [switch]$SuspiciousOnly
    )

    if (-not (Get-Command Get-InboxRule -ErrorAction SilentlyContinue)) {
        throw 'Get-InboxRule is not available: run Connect-ExchangeOnline (ExchangeOnlineManagement module) first.'
    }
    if (-not $PSBoundParameters.ContainsKey('InternalDomain')) {
        $InternalDomain = @(Get-AcceptedDomain | ForEach-Object { [string]$_.DomainName })
    }
    $mailboxes = if ($Mailbox) { @($Mailbox | ForEach-Object { Get-Mailbox -Identity $_ }) }
    else { @(Get-Mailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox, SharedMailbox) }

    $emit = {
        param($Row)
        if (-not $SuspiciousOnly -or $Row.Suspicious) { $Row }
    }
    $index = 0
    foreach ($mb in $mailboxes) {
        $index++
        $address = [string]$mb.PrimarySmtpAddress
        Write-Progress -Activity 'Reading inbox rules' -Status $address -PercentComplete (100 * $index / [math]::Max(1, $mailboxes.Count))

        $forwarding = @(ConvertTo-NSPRuleTarget @([string]$mb.ForwardingSmtpAddress, [string]$mb.ForwardingAddress))
        if ($forwarding.Count) {
            $flags = @(Get-NSPInboxRuleFlag -ForwardTarget $forwarding -InternalDomain $InternalDomain)
            & $emit ([pscustomobject]@{
                    Mailbox      = $address
                    Kind         = 'MailboxForwarding'
                    RuleName     = ''
                    Enabled      = $true
                    MoveToFolder = ''
                    ForwardTo    = $forwarding -join '; '
                    DeleteMessage = -not [bool]$mb.DeliverToMailboxAndForward
                    MarkAsRead   = $false
                    Conditions   = ''
                    Flags        = $flags -join '; '
                    Suspicious   = [bool](@($flags | Where-Object { $_ -ne 'ForwardsInternal' }).Count)
                    Description  = "DeliverToMailboxAndForward=$($mb.DeliverToMailboxAndForward)"
                    RuleIdentity = ''
                })
        }

        try {
            $rules = @(Get-InboxRule -Mailbox $address -IncludeHidden -ErrorAction Stop)
        } catch {
            Write-Warning "Could not read inbox rules of $address`: $($_.Exception.Message)"
            continue
        }
        foreach ($rule in $rules) {
            if ([string]$rule.Name -eq 'Junk E-mail Rule') { continue }
            $targets = @(ConvertTo-NSPRuleTarget @($rule.ForwardTo, $rule.RedirectTo, $rule.ForwardAsAttachmentTo))
            $conditions = @(foreach ($n in 'From', 'FromAddressContainsWords', 'SubjectContainsWords', 'SubjectOrBodyContainsWords', 'BodyContainsWords', 'SentTo', 'HeaderContainsWords') {
                    $v = @($rule.$n | Where-Object { $_ })
                    if ($v.Count) { "$n=$($v -join ',')" }
                }) -join '; '
            $delete = [bool]$rule.DeleteMessage -or [bool]$rule.SoftDeleteMessage
            $flags = @(Get-NSPInboxRuleFlag -Name ([string]$rule.Name) -MoveToFolder ([string]$rule.MoveToFolder) -ForwardTarget $targets -Delete $delete -MarkAsRead ([bool]$rule.MarkAsRead) -Conditions $conditions -InternalDomain $InternalDomain)
            & $emit ([pscustomobject]@{
                    Mailbox      = $address
                    Kind         = 'InboxRule'
                    RuleName     = [string]$rule.Name
                    Enabled      = [bool]$rule.Enabled
                    MoveToFolder = [string]$rule.MoveToFolder
                    ForwardTo    = $targets -join '; '
                    DeleteMessage = $delete
                    MarkAsRead   = [bool]$rule.MarkAsRead
                    Conditions   = $conditions
                    Flags        = $flags -join '; '
                    Suspicious   = [bool](@($flags | Where-Object { $_ -ne 'ForwardsInternal' }).Count)
                    Description  = ([string]$rule.Description).Trim()
                    RuleIdentity = [string]$rule.Identity
                })
        }
    }
    Write-Progress -Activity 'Reading inbox rules' -Completed
}
