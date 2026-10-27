# Remove-NSPM365InboxRule against mocked Exchange Online cmdlets, and Export-NSPM365Message
# against NSP.M365.Graph's Fake transport. Nothing signs in or leaves the host.

BeforeAll {
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'NSP.M365.Investigation.psd1') -Force -ErrorAction Stop
    InModuleScope NSP.M365.Investigation { Import-NSPM365Graph }
}
AfterAll { Set-NSPGraphTransport -Name MgGraphRequest }

Describe 'Remove-NSPM365InboxRule' {
    BeforeAll {
        # Stand-ins for the ExchangeOnlineManagement cmdlets, so they can be mocked.
        function global:Get-InboxRule { [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')] param($Identity, $Mailbox, [switch]$IncludeHidden) }
        function global:Remove-InboxRule { [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')] [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')] [CmdletBinding(SupportsShouldProcess)] param($Identity, [switch]$AlwaysDeleteOutlookRulesBlob, [switch]$Force) }
        function global:Disable-InboxRule { [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')] [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')] [CmdletBinding(SupportsShouldProcess)] param($Identity, [switch]$AlwaysDeleteOutlookRulesBlob, [switch]$Force) }
        function global:Get-Mailbox { [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')] param($Identity) }
        function global:Set-Mailbox { [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')] [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')] [CmdletBinding(SupportsShouldProcess)] param($Identity, $ForwardingSmtpAddress, $ForwardingAddress, $DeliverToMailboxAndForward) }

        $script:RuleRow = [pscustomobject]@{ Mailbox = 'jdoe@contoso.com'; Kind = 'InboxRule'; RuleName = '.'; RuleIdentity = 'jdoe\123'; ForwardTo = 'drop@evil.example'; Flags = 'Forwards; OddName' }
        $script:ForwardRow = [pscustomobject]@{ Mailbox = 'jdoe@contoso.com'; Kind = 'MailboxForwarding'; RuleName = ''; RuleIdentity = ''; ForwardTo = 'drop@evil.example'; Flags = 'Forwards' }
    }
    AfterAll { Remove-Item function:\Get-InboxRule, function:\Remove-InboxRule, function:\Disable-InboxRule, function:\Get-Mailbox, function:\Set-Mailbox -ErrorAction SilentlyContinue }
    BeforeEach {
        Mock Get-InboxRule -ModuleName NSP.M365.Investigation { [pscustomobject]@{ Name = '.'; Identity = $Identity; MailboxOwnerId = 'jdoe'; ForwardTo = @('"Drop" [SMTP:drop@evil.example]'); MoveToFolder = 'RSS Feeds' } }
        Mock Remove-InboxRule -ModuleName NSP.M365.Investigation { }
        Mock Disable-InboxRule -ModuleName NSP.M365.Investigation { }
        Mock Get-Mailbox -ModuleName NSP.M365.Investigation { [pscustomobject]@{ PrimarySmtpAddress = 'jdoe@contoso.com'; ForwardingSmtpAddress = 'smtp:drop@evil.example'; ForwardingAddress = $null; DeliverToMailboxAndForward = $false } }
        Mock Set-Mailbox -ModuleName NSP.M365.Investigation { }
    }

    It 'removes a reported rule and returns its settings from before' {
        $result = $script:RuleRow | Remove-NSPM365InboxRule -Confirm:$false
        $result.Action | Should -Be 'Remove'
        $result.Result | Should -Be 'Done'
        $result.Before | Should -Match 'RSS Feeds'
        $result.Flags | Should -Be 'Forwards; OddName'
        Should -Invoke Remove-InboxRule -ModuleName NSP.M365.Investigation -Times 1 -Exactly -ParameterFilter { $Identity -eq 'jdoe\123' -and $AlwaysDeleteOutlookRulesBlob -and $Force }
    }
    It 'disables instead with -Disable' {
        ($script:RuleRow | Remove-NSPM365InboxRule -Disable -Confirm:$false).Action | Should -Be 'Disable'
        Should -Invoke Disable-InboxRule -ModuleName NSP.M365.Investigation -Times 1 -Exactly
        Should -Invoke Remove-InboxRule -ModuleName NSP.M365.Investigation -Times 0 -Exactly
    }
    It 'changes nothing under -WhatIf but still reports what is there' {
        $result = @($script:RuleRow, $script:ForwardRow | Remove-NSPM365InboxRule -WhatIf)
        $result.Result | Should -Be @('Skipped', 'Skipped')
        $result[1].Before | Should -Match 'drop@evil.example'
        Should -Invoke Remove-InboxRule -ModuleName NSP.M365.Investigation -Times 0 -Exactly
        Should -Invoke Set-Mailbox -ModuleName NSP.M365.Investigation -Times 0 -Exactly
    }
    It 'clears mailbox forwarding' {
        ($script:ForwardRow | Remove-NSPM365InboxRule -Confirm:$false).Action | Should -Be 'ClearForwarding'
        Should -Invoke Set-Mailbox -ModuleName NSP.M365.Investigation -Times 1 -Exactly -ParameterFilter { $null -eq $ForwardingSmtpAddress -and $DeliverToMailboxAndForward -eq $false }
    }
    It 'takes rule identities' {
        (Remove-NSPM365InboxRule -Identity 'jdoe\456' -Confirm:$false).RuleName | Should -Be ''
        Should -Invoke Remove-InboxRule -ModuleName NSP.M365.Investigation -Times 1 -Exactly -ParameterFilter { $Identity -eq 'jdoe\456' }
    }
    It 'reports a failure instead of stopping the batch' {
        Mock Remove-InboxRule -ModuleName NSP.M365.Investigation { throw 'The operation could not be performed' }
        $result = @($script:RuleRow, $script:ForwardRow | Remove-NSPM365InboxRule -Confirm:$false)
        $result[0].Result | Should -Match '^Failed: The operation'
        $result[1].Result | Should -Be 'Done'
    }
    It 'refuses audit rows, which carry no rule identity' {
        $audit = [pscustomobject]@{ Mailbox = 'jdoe\.'; Kind = $null; RuleName = '.'; Flags = 'OddName' }
        { $audit | Remove-NSPM365InboxRule -Confirm:$false -ErrorAction Stop } | Should -Throw '*Get-NSPM365InboxRuleReport*'
    }
}

Describe 'Export-NSPM365Message' {
    BeforeAll {
        Mock Connect-NSPHuntTenant { } -ModuleName NSP.M365.Investigation
        Mock Write-Host { } -ModuleName NSP.M365.Investigation
        Set-NSPGraphTransport -Name Fake -Responder {
            param($Method, $Uri, $Body)
            $null = $Method, $Body
            $decoded = [uri]::UnescapeDataString($Uri)
            if ($decoded -match '/messages/(?<id>[^/]+)/\$value$') { return "Message-ID: <$($Matches.id)>`r`nSubject: test`r`n`r`nBody of $($Matches.id)" }
            $message = { param($Id, $Subject) @{ id = $Id; subject = $Subject; receivedDateTime = '2026-10-02T03:10:00Z'; from = @{ emailAddress = @{ address = 'ap@fabrikam.example' } } } }
            if ($decoded -match "internetMessageId eq '<i1@contoso.com>'") { return @{ value = @((& $message 'g-1' 'Invoice 1: "Overdue"')) } }
            if ($decoded -match "internetMessageId eq '<dup@contoso.com>'") { return @{ value = @((& $message 'g-2' 'Copy'), (& $message 'g-3' 'Copy')) } }
            if ($decoded -match "internetMessageId eq '<boom@contoso.com>'") { throw 'Forbidden' }
            @{ value = @() }
        }
        $rows = @(
            [pscustomobject]@{ MailboxOwnerUPN = 'jdoe@contoso.com'; UserId = 'jdoe@contoso.com'; InternetMessageId = '<i1@contoso.com>' }
            [pscustomobject]@{ MailboxOwnerUPN = 'jdoe@contoso.com'; UserId = 'jdoe@contoso.com'; InternetMessageId = '<i1@contoso.com>' }
            [pscustomobject]@{ MailboxOwnerUPN = ''; UserId = 'jdoe@contoso.com'; InternetMessageId = '<dup@contoso.com>' }
            [pscustomobject]@{ MailboxOwnerUPN = 'jdoe@contoso.com'; UserId = 'jdoe@contoso.com'; InternetMessageId = '<gone@contoso.com>' }
            [pscustomobject]@{ MailboxOwnerUPN = 'jdoe@contoso.com'; UserId = 'jdoe@contoso.com'; InternetMessageId = '<boom@contoso.com>' }
            [pscustomobject]@{ MailboxOwnerUPN = 'jdoe@contoso.com'; UserId = 'jdoe@contoso.com'; InternetMessageId = '' }
        )
        $script:Out = Join-Path $TestDrive 'export'
        $script:Result = @($rows | Export-NSPM365Message -OutputPath $script:Out)
    }

    It 'fetches each mailbox and message once, skipping rows without an id' {
        @($script:Result | Where-Object InternetMessageId -EQ '<i1@contoso.com>').Count | Should -Be 1
        @($script:Result).Count | Should -Be 5
    }
    It 'saves the MIME content as .eml with a SHA-256 in the manifest' {
        $exported = $script:Result | Where-Object InternetMessageId -EQ '<i1@contoso.com>'
        $exported.Status | Should -Be 'Exported'
        $exported.From | Should -Be 'ap@fabrikam.example'
        $file = Join-Path $script:Out $exported.File
        $file | Should -Exist
        $file | Should -Match '20261002-031000_Invoice 1_ _Overdue_\.eml$'
        Get-Content -LiteralPath $file -Raw | Should -Match 'Body of g-1'
        $exported.Sha256 | Should -Be (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
        @(Import-Csv (Join-Path $script:Out 'Manifest.csv')).Count | Should -Be 5
    }
    It 'saves every copy when the message is in more than one folder' {
        $copies = @($script:Result | Where-Object InternetMessageId -EQ '<dup@contoso.com>')
        $copies.Count | Should -Be 2
        ($copies.File | Sort-Object -Unique).Count | Should -Be 2
        $copies[0].Note | Should -Be 'Copy 1 of 2 in the mailbox.'
    }
    It 'reports purged and failed lookups without stopping' {
        ($script:Result | Where-Object InternetMessageId -EQ '<gone@contoso.com>').Status | Should -Be 'NotFound'
        $failed = $script:Result | Where-Object InternetMessageId -EQ '<boom@contoso.com>'
        $failed.Status | Should -Be 'Failed'
        $failed.Note | Should -Match 'Forbidden'
    }
    It 'needs both halves of app-only sign-in' {
        { Export-NSPM365Message -Mailbox a@contoso.com -InternetMessageId '<x@y>' -ClientId 'abc' } | Should -Throw '*both -ClientId and -CertificateThumbprint*'
    }
}
