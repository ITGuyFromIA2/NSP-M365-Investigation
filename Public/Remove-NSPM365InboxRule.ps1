function Remove-NSPM365InboxRule {
    <#
    .SYNOPSIS
        Removes (or with -Disable, disables) inbox rules and clears mailbox forwarding found by Get-NSPM365InboxRuleReport, confirming each and returning what was there first.
    .DESCRIPTION
        Takes Get-NSPM365InboxRuleReport rows from the pipeline, or rule identities. Needs an
        Exchange Online session (Connect-ExchangeOnline) with rights to change mailboxes.

          InboxRule rows          Remove-InboxRule, or Disable-InboxRule with -Disable
          MailboxForwarding rows  Set-Mailbox -ForwardingSmtpAddress $null -ForwardingAddress $null
                                  -DeliverToMailboxAndForward $false (also with -Disable: there is
                                  no disabled state for forwarding)

        Each change is confirmed (ConfirmImpact High); -WhatIf shows them all without changing
        anything. Before each change the rule is read again (Get-InboxRule) and returned in
        Before as JSON, so the evidence survives the removal: pipe the results to Export-Csv.

        -Disable is the reversible choice while the investigation is open: the rule stops
        running but keeps its settings for the report.

        Exchange warns that changing rules outside Outlook deletes rules that were turned off in
        Outlook desktop; that prompt is answered yes (-AlwaysDeleteOutlookRulesBlob), or the
        command would stop for input. Those client-side rules are lost - the same as when the
        user edits a rule in Outlook on the web.

        Audit rows (Get-NSPM365InboxRuleAudit) don't carry the rule identity: find the live rule
        with Get-NSPM365InboxRuleReport first.
    .PARAMETER InputObject
        Rows from Get-NSPM365InboxRuleReport.
    .PARAMETER Identity
        Rule identities ('jdoe@contoso.com\1234567890', the report's RuleIdentity).
    .PARAMETER Disable
        Disable rules instead of removing them.
    .EXAMPLE
        Get-NSPM365InboxRuleReport -Mailbox jdoe@contoso.com -SuspiciousOnly | Remove-NSPM365InboxRule -WhatIf
    .EXAMPLE
        Get-NSPM365InboxRuleReport -SuspiciousOnly | Remove-NSPM365InboxRule -Disable | Export-Csv .\rules-disabled.csv -NoTypeInformation
    .EXAMPLE
        Remove-NSPM365InboxRule -Identity 'jdoe@contoso.com\1234567890' -Confirm:$false
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'Report')]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Report')]
        [psobject[]]$InputObject,
        [Parameter(Mandatory, ParameterSetName = 'Identity')]
        [string[]]$Identity,
        [switch]$Disable
    )

    begin {
        $disableRules = [bool]$Disable
        if (-not (Get-Command Remove-InboxRule -ErrorAction SilentlyContinue)) {
            throw 'Remove-InboxRule is not available: run Connect-ExchangeOnline (ExchangeOnlineManagement module) first.'
        }
        $result = {
            param($Row, $Action, $Outcome, $Before)
            [pscustomobject]@{
                Mailbox      = [string]$Row.Mailbox
                Kind         = [string]$Row.Kind
                RuleName     = [string]$Row.RuleName
                RuleIdentity = [string]$Row.RuleIdentity
                Action       = $Action
                Result       = $Outcome
                Flags        = [string]$Row.Flags
                Before       = if ($null -ne $Before) { ConvertTo-Json -InputObject $Before -Depth 4 -Compress } else { '' }
            }
        }
        $handle = {
            param($Row)
            if ($Row.Kind -eq 'MailboxForwarding') {
                $before = Get-Mailbox -Identity $Row.Mailbox -ErrorAction Stop | Select-Object PrimarySmtpAddress, ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward
                if (-not $PSCmdlet.ShouldProcess("$($Row.Mailbox) (forwarding to $($Row.ForwardTo))", 'Clear mailbox forwarding')) {
                    return (& $result $Row 'ClearForwarding' 'Skipped' $before)
                }
                try {
                    Set-Mailbox -Identity $Row.Mailbox -ForwardingSmtpAddress $null -ForwardingAddress $null -DeliverToMailboxAndForward $false -Confirm:$false -ErrorAction Stop
                    & $result $Row 'ClearForwarding' 'Done' $before
                } catch { & $result $Row 'ClearForwarding' "Failed: $($_.Exception.Message)" $before }
                return
            }

            if (-not $Row.RuleIdentity) {
                Write-Error "No RuleIdentity on '$($Row.RuleName)' ($($Row.Mailbox)): pass rows from Get-NSPM365InboxRuleReport, or -Identity."
                return
            }
            $action = if ($disableRules) { 'Disable' } else { 'Remove' }
            try {
                $before = Get-InboxRule -Identity $Row.RuleIdentity -ErrorAction Stop | Select-Object *
            } catch {
                return (& $result $Row $action "Failed: rule not found ($($_.Exception.Message))" $null)
            }
            $name = if ($Row.RuleName) { $Row.RuleName } else { [string]$before.Name }
            $mailbox = if ($Row.Mailbox) { $Row.Mailbox } else { [string]$before.MailboxOwnerId }
            if (-not $PSCmdlet.ShouldProcess("'$name' ($($Row.RuleIdentity)) in $mailbox", "$action inbox rule")) {
                return (& $result $Row $action 'Skipped' $before)
            }
            try {
                if ($disableRules) {
                    Disable-InboxRule -Identity $Row.RuleIdentity -AlwaysDeleteOutlookRulesBlob -Force -Confirm:$false -ErrorAction Stop
                } else {
                    Remove-InboxRule -Identity $Row.RuleIdentity -AlwaysDeleteOutlookRulesBlob -Force -Confirm:$false -ErrorAction Stop
                }
                & $result $Row $action 'Done' $before
            } catch { & $result $Row $action "Failed: $($_.Exception.Message)" $before }
        }
    }
    process {
        $rows = if ($PSCmdlet.ParameterSetName -eq 'Identity') {
            @($Identity | ForEach-Object { [pscustomobject]@{ Mailbox = ''; Kind = 'InboxRule'; RuleName = ''; RuleIdentity = $_; Flags = '' } })
        } else { @($InputObject) }
        foreach ($row in $rows) { if ($null -ne $row) { & $handle $row } }
    }
}
