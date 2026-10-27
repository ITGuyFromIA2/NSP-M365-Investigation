# Audit triage, inbox rules, message trace and IP lookup against synthetic exports written to
# TestDrive (addresses from the documentation ranges). ip-api.com is mocked; nothing leaves the host.

BeforeAll {
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'NSP.M365.Investigation.psd1') -Force -ErrorAction Stop
    InModuleScope NSP.M365.Investigation { Import-NSPLogParse }

    $script:Trusted = '198.51.100.10'
    $script:Attacker = '203.0.113.50'
    $script:Foreign = '192.0.2.77'

    function New-AuditCsv {
        param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][object[]]$Records)
        $i = 0
        @(foreach ($r in $Records) {
                $i++
                $audit = $r.AuditData
                $audit.Operation = $r.Operation
                if (-not $audit.ContainsKey('CreationTime')) { $audit.CreationTime = $r.Time }
                [pscustomobject]@{
                    RecordId     = "rec-$i"
                    CreationDate = $r.Time + 'Z'
                    RecordType   = 'ExchangeItem'
                    Operation    = $r.Operation
                    UserId       = 'jdoe@contoso.com'
                    AuditData    = ConvertTo-Json -InputObject $audit -Depth 10 -Compress
                }
            }) | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
        $Path
    }

    function New-CompromiseAudit {
        # jdoe signs in from the office, then from a hosting provider that reads and syncs the
        # inbox, hides replies about invoices, forwards them out and consents an app.
        param([Parameter(Mandatory)][string]$Path)
        New-AuditCsv -Path $Path -Records @(
            @{ Time = '2026-10-01T08:00:00'; Operation = 'UserLoggedIn'; AuditData = @{ Workload = 'AzureActiveDirectory'; ClientIP = $script:Trusted; ResultStatus = 'Success' } }
            @{ Time = '2026-10-02T03:00:00'; Operation = 'UserLoggedIn'; AuditData = @{ Workload = 'AzureActiveDirectory'; ClientIP = $script:Attacker; ResultStatus = 'Success'; ExtendedProperties = @(@{ Name = 'UserAgent'; Value = 'python-requests/2.31' }, @{ Name = 'RequestType'; Value = 'OAuth2:Token' }) } }
            @{ Time = '2026-10-02T03:01:00'; Operation = 'UserLoginFailed'; AuditData = @{ Workload = 'AzureActiveDirectory'; ClientIP = $script:Foreign; ResultStatus = 'Failed'; LogonError = 'InvalidUserNameOrPassword' } }
            @{ Time = '2026-10-02T03:05:00'; Operation = 'New-InboxRule'; AuditData = @{ Workload = 'Exchange'; ClientIP = "$($script:Attacker):51234"; ObjectId = 'jdoe\.'; Parameters = @(@{ Name = 'Name'; Value = '.' }, @{ Name = 'MoveToFolder'; Value = 'RSS Feeds' }, @{ Name = 'SubjectContainsWords'; Value = 'invoice' }, @{ Name = 'ForwardTo'; Value = 'drop@evil.example' }, @{ Name = 'MarkAsRead'; Value = 'True' }) } }
            @{ Time = '2026-10-01T09:00:00'; Operation = 'New-InboxRule'; AuditData = @{ Workload = 'Exchange'; ClientIP = $script:Trusted; ObjectId = 'jdoe\Newsletters'; Parameters = @(@{ Name = 'Name'; Value = 'Newsletters' }, @{ Name = 'MoveToFolder'; Value = 'Newsletters' }) } }
            @{ Time = '2026-10-02T03:10:00'; Operation = 'MailItemsAccessed'; AuditData = @{ Workload = 'Exchange'; ClientIPAddress = $script:Attacker; MailboxOwnerUPN = 'jdoe@contoso.com'; AppId = 'app-1'; OperationProperties = @(@{ Name = 'MailAccessType'; Value = 'Bind' }, @{ Name = 'IsThrottled'; Value = 'False' })
                    Folders = @(@{ Path = '\Inbox'; FolderItems = @(@{ Subject = 'Invoice 1'; InternetMessageId = '<i1@contoso.com>'; SizeInBytes = 1000 }, @{ Subject = 'Invoice 2'; InternetMessageId = '<i2@contoso.com>'; SizeInBytes = 2000 }) }) } }
            @{ Time = '2026-10-02T03:11:00'; Operation = 'MailItemsAccessed'; AuditData = @{ Workload = 'Exchange'; ClientIPAddress = $script:Attacker; OperationProperties = @(@{ Name = 'MailAccessType'; Value = 'Sync' }); Folders = @(@{ Path = '\Inbox' }) } }
            @{ Time = '2026-10-02T04:00:00'; Operation = 'Send'; AuditData = @{ Workload = 'Exchange'; ClientIP = "$($script:Foreign):4431" } }
            @{ Time = '2026-10-02T04:05:00'; Operation = 'Consent to application.'; AuditData = @{ Workload = 'AzureActiveDirectory'; ClientIP = $script:Attacker; ObjectId = 'Mail Sync Pro' } }
            @{ Time = '2026-10-01T10:00:00'; Operation = 'Set-Mailbox'; AuditData = @{ Workload = 'Exchange'; ClientIP = $script:Trusted; ObjectId = 'jdoe'; Parameters = @(@{ Name = 'Identity'; Value = 'jdoe' }, @{ Name = 'ForwardingSmtpAddress'; Value = 'smtp:boss@contoso.com' }) } }
        )
    }

    $script:IpApiMock = {
        $geo = @{
            '198.51.100.10' = @{ country = 'United States'; countryCode = 'US'; regionName = 'Iowa'; city = 'Des Moines'; isp = 'Office ISP'; org = ''; as = 'AS64500 Office ISP'; asname = 'OFFICE'; hosting = $false; proxy = $false; mobile = $false }
            '203.0.113.50'  = @{ country = 'Netherlands'; countryCode = 'NL'; regionName = 'North Holland'; city = 'Amsterdam'; isp = 'Cheap VPS'; org = ''; as = 'AS64501 Cheap VPS'; asname = 'VPS'; hosting = $true; proxy = $false; mobile = $false }
            '192.0.2.77'    = @{ country = 'Elsewhere'; countryCode = 'ZZ'; regionName = ''; city = ''; isp = 'Far ISP'; org = ''; as = 'AS64502 Far ISP'; asname = 'FAR'; hosting = $false; proxy = $false; mobile = $false }
        }
        $results = @(foreach ($ip in (ConvertFrom-Json -InputObject $Body)) {
                $entry = if ($geo.ContainsKey($ip)) { $geo[$ip].Clone() } else { @{ country = 'United States'; countryCode = 'US'; as = 'AS64503 Other' } }
                $entry.status = 'success'
                $entry.query = $ip
                $entry
            })
        [pscustomobject]@{ Content = (ConvertTo-Json -InputObject $results -Depth 4 -Compress); Headers = @{ 'X-Rl' = '44'; 'X-Ttl' = '60' } }
    }
}

Describe 'Address helpers' {
    It 'strips Exchange port suffixes and brackets from <In>' -ForEach @(
        @{ In = '203.0.113.5:51234'; Out = '203.0.113.5' }
        @{ In = '[2001:db8::1]:443'; Out = '2001:db8::1' }
        @{ In = '2001:db8::1'; Out = '2001:db8::1' }
        @{ In = '::ffff:203.0.113.5'; Out = '203.0.113.5' }
        @{ In = ' 198.51.100.7 '; Out = '198.51.100.7' }
    ) {
        InModuleScope NSP.M365.Investigation -Parameters $_ { param($In, $Out) ConvertTo-NSPAuditIp $In | Should -Be $Out }
    }
    It 'matches <Ip> against <Range>: <Expected>' -ForEach @(
        @{ Ip = '198.51.100.77'; Range = '198.51.100.0/24'; Expected = $true }
        @{ Ip = '198.51.101.1'; Range = '198.51.100.0/24'; Expected = $false }
        @{ Ip = '198.51.100.77'; Range = '198.51.100.64/27'; Expected = $true }
        @{ Ip = '198.51.100.100'; Range = '198.51.100.64/27'; Expected = $false }
        @{ Ip = '2001:db8:abcd::5'; Range = '2001:db8::/32'; Expected = $true }
        @{ Ip = '2001:db9::5'; Range = '2001:db8::/32'; Expected = $false }
        @{ Ip = '203.0.113.9'; Range = '203.0.113.*'; Expected = $true }
        @{ Ip = '203.0.113.9'; Range = '203.0.113.9'; Expected = $true }
        @{ Ip = '203.0.113.90'; Range = '203.0.113.9'; Expected = $false }
        @{ Ip = '203.0.113.9'; Range = '2001:db8::/32'; Expected = $false }
    ) {
        InModuleScope NSP.M365.Investigation -Parameters $_ { param($Ip, $Range, $Expected) Test-NSPIpInRange -Ip $Ip -Range $Range | Should -Be $Expected }
    }
}

Describe 'Inbox rule flags' {
    It 'flags the classic hide-the-replies rule' {
        InModuleScope NSP.M365.Investigation {
            $flags = Get-NSPInboxRuleFlag -Name '..' -MoveToFolder 'jdoe\RSS Feeds' -ForwardTarget 'drop@evil.example' -MarkAsRead $true -Conditions 'SubjectContainsWords=Invoice' -InternalDomain contoso.com
            $flags | Should -Contain 'Forwards'
            $flags | Should -Contain 'MovesTo:RSS Feeds'
            $flags | Should -Contain 'MarksRead'
            $flags | Should -Contain 'OddName'
            $flags | Should -Contain 'TargetsKeywords'
        }
    }
    It 'treats forwarding to internal domains and EX recipients as internal' {
        InModuleScope NSP.M365.Investigation {
            Get-NSPInboxRuleFlag -Name 'To my assistant' -ForwardTarget 'amy@contoso.com', 'EX:Amy' -InternalDomain contoso.com | Should -Be @('ForwardsInternal')
        }
    }
    It 'does not flag an ordinary filing rule' {
        InModuleScope NSP.M365.Investigation { @(Get-NSPInboxRuleFlag -Name 'Newsletters' -MoveToFolder 'Newsletters').Count | Should -Be 0 }
    }
    It 'reads addresses out of Get-InboxRule and audit formats' {
        InModuleScope NSP.M365.Investigation {
            @(ConvertTo-NSPRuleTarget @('"Drop" [SMTP:drop@evil.example]', 'a@b.example;c@d.example', '"Amy Smith" [EX:/o=ExchangeLabs/cn=Recipients/cn=amy]')) |
                Should -Be @('drop@evil.example', 'a@b.example', 'c@d.example', 'EX:Amy Smith')
        }
    }
}

Describe 'Resolve-NSPIpInfo' {
    BeforeEach {
        InModuleScope NSP.M365.Investigation { $script:NSPIpInfoCache = @{} }
        Mock Invoke-WebRequest -ModuleName NSP.M365.Investigation -MockWith $script:IpApiMock
        Mock Start-Sleep -ModuleName NSP.M365.Investigation {}
    }
    It 'returns geolocation, ASN and hosting for each distinct address' {
        $result = @(Resolve-NSPIpInfo "$($script:Attacker):443", $script:Attacker, $script:Trusted)
        $result.Count | Should -Be 2
        $attacker = $result | Where-Object IP -EQ $script:Attacker
        $attacker.CountryCode | Should -Be 'NL'
        $attacker.Asn | Should -Be '64501'
        $attacker.Hosting | Should -BeTrue
        Should -Invoke Invoke-WebRequest -ModuleName NSP.M365.Investigation -Times 1 -Exactly
    }
    It 'batches 100 per request and caches for the session' {
        $ips = 1..150 | ForEach-Object { "198.18.0.$_" }
        @(Resolve-NSPIpInfo $ips).Count | Should -Be 150
        Should -Invoke Invoke-WebRequest -ModuleName NSP.M365.Investigation -Times 2 -Exactly
        @(Resolve-NSPIpInfo $ips[0..9]).Count | Should -Be 10
        Should -Invoke Invoke-WebRequest -ModuleName NSP.M365.Investigation -Times 2 -Exactly
    }
    It 'waits out the rate limit between batches' {
        Mock Invoke-WebRequest -ModuleName NSP.M365.Investigation {
            $r = & $script:IpApiMock
            $r.Headers = @{ 'X-Rl' = '0'; 'X-Ttl' = '30' }
            $r
        }
        Resolve-NSPIpInfo (1..101 | ForEach-Object { "198.18.1.$_" }) | Out-Null
        Should -Invoke Start-Sleep -ModuleName NSP.M365.Investigation -Times 1 -Exactly -ParameterFilter { $Seconds -eq 31 }
    }
    It 'accepts summary rows from the pipeline' {
        $rows = @([pscustomobject]@{ Name = $script:Foreign; Count = 3 })
        ($rows | Resolve-NSPIpInfo).CountryCode | Should -Be 'ZZ'
    }
}

Describe 'Audit record functions' {
    BeforeAll { $script:AuditCsv = New-CompromiseAudit -Path (Join-Path $TestDrive 'audit.csv') }

    It 'summarizes by operation with the client IP read from every workload' {
        $summary = @(Get-NSPM365AuditSummary -Path $script:AuditCsv)
        ($summary | Where-Object Name -EQ 'MailItemsAccessed').Count | Should -Be 2
        ($summary | Where-Object Name -EQ 'New-InboxRule').ClientIPs | Should -Be "$($script:Trusted); $($script:Attacker)"
    }
    It 'groups by client IP and leaves out excluded ranges' {
        $summary = @(Get-NSPM365AuditSummary -Path $script:AuditCsv -GroupBy ClientIP -ExcludeIP '198.51.100.0/24')
        $summary.Name | Should -Not -Contain $script:Trusted
        ($summary | Where-Object Name -EQ $script:Attacker).Count | Should -Be 5
    }
    It 'expands MailItemsAccessed into one row per message, and one per synced folder' {
        $rows = @(Get-NSPM365AccessedMessage -Path $script:AuditCsv)
        $rows.Count | Should -Be 3
        @($rows | Where-Object MailAccessType -EQ 'Bind').InternetMessageId | Should -Be @('<i1@contoso.com>', '<i2@contoso.com>')
        $sync = $rows | Where-Object MailAccessType -EQ 'Sync'
        $sync.FolderPath | Should -Be '\Inbox'
        $sync.Subject | Should -Be ''
        $rows[0].ClientIP | Should -Be $script:Attacker
    }
    It 'pulls rule parameters into columns and flags the attacker rule' {
        $rules = @(Get-NSPM365InboxRuleAudit -Path $script:AuditCsv -InternalDomain contoso.com)
        $rules.Count | Should -Be 3
        $bad = $rules | Where-Object RuleName -EQ '.'
        $bad.Suspicious | Should -BeTrue
        $bad.ClientIP | Should -Be $script:Attacker
        $bad.ForwardTo | Should -Be 'drop@evil.example'
        $bad.Flags | Should -Match 'Forwards; MarksRead; MovesTo:RSS Feeds; OddName; TargetsKeywords'
        ($rules | Where-Object RuleName -EQ 'Newsletters').Suspicious | Should -BeFalse
        $forwarding = $rules | Where-Object Operation -EQ 'Set-Mailbox'
        $forwarding.Flags | Should -Be 'ForwardsInternal'
        $forwarding.Suspicious | Should -BeFalse
    }
    It 'takes parsed records from the pipeline' {
        $records = InModuleScope NSP.M365.Investigation -Parameters @{ P = $script:AuditCsv } { param($P) Read-NSPAuditCsv -Path $P }
        @($records | Get-NSPM365AccessedMessage).Count | Should -Be 3
    }
}

Describe 'Invoke-NSPM365AuditTriage' {
    BeforeAll {
        InModuleScope NSP.M365.Investigation { $script:NSPIpInfoCache = @{} }
        Mock Invoke-WebRequest -ModuleName NSP.M365.Investigation -MockWith $script:IpApiMock
        Mock Write-Host -ModuleName NSP.M365.Investigation {}
        $csv = New-CompromiseAudit -Path (Join-Path $TestDrive 'triage.csv')
        $script:Out = Join-Path $TestDrive 'triage-out'
        $script:Findings = @(Invoke-NSPM365AuditTriage -Path $csv -TrustedIP $script:Trusted -ExpectedCountry US -InternalDomain contoso.com -OutputPath $script:Out -PassThru -WarningAction SilentlyContinue)
    }

    It 'writes every report' {
        foreach ($name in 'Findings', 'Timeline', 'IPs', 'Summary', 'SignIns', 'AccessedMail', 'InboxRules') {
            Join-Path $script:Out "$name.csv" | Should -Exist
        }
        @(Import-Csv (Join-Path $script:Out 'Timeline.csv')).Count | Should -Be 10
    }
    It 'makes the attacker inbox rule Critical and sorts it first' {
        $script:Findings[0].Severity | Should -Be 'Critical'
        $script:Findings[0].Check | Should -Be 'Inbox rule'
        $script:Findings[0].Detail | Should -Match 'drop@evil.example'
    }
    It 'flags the hosting-provider sign-in, the folder sync and the app consent as High' {
        $high = @($script:Findings | Where-Object Severity -EQ 'High')
        $high.Check | Should -Contain 'Sign-in'
        $high.Check | Should -Contain 'Mail read'
        $high.Check | Should -Contain 'App consent'
        ($high | Where-Object Check -EQ 'Sign-in').Detail | Should -Match 'Amsterdam, NL'
    }
    It 'groups untrusted message reads and sends per user and address' {
        $read = @($script:Findings | Where-Object { $_.Check -eq 'Mail read' -and $_.Severity -eq 'Medium' })
        $read.Count | Should -Be 1
        $read[0].Detail | Should -Match '^2 message'
        ($script:Findings | Where-Object Check -EQ 'Mail sent').Detail | Should -Match $([regex]::Escape($script:Foreign))
    }
    It 'reports hosting and unexpected-country addresses once each' {
        $addresses = @($script:Findings | Where-Object Check -EQ 'Address')
        $addresses.Count | Should -Be 2
    }
    It 'raises nothing for the trusted address or internal forwarding' {
        @($script:Findings | Where-Object { $_.Detail -match [regex]::Escape($script:Trusted) }).Count | Should -Be 0
        @($script:Findings | Where-Object { $_.Object -match 'Newsletters' }).Count | Should -Be 0
    }
    It 'marks trust and geolocation in the IP table, untrusted first' {
        $ips = @(Import-Csv (Join-Path $script:Out 'IPs.csv'))
        $ips[-1].ClientIP | Should -Be $script:Trusted
        $ips[-1].Trust | Should -Be 'Trusted'
        ($ips | Where-Object ClientIP -EQ $script:Attacker).Asn | Should -Be '64501'
    }
    It 'puts sign-ins and failures in one timeline with the user agent' {
        $signIns = @(Import-Csv (Join-Path $script:Out 'SignIns.csv'))
        $signIns.Count | Should -Be 3
        ($signIns | Where-Object ClientIP -EQ $script:Attacker).UserAgent | Should -Be 'python-requests/2.31'
        ($signIns | Where-Object Operation -EQ 'UserLoginFailed').LogonError | Should -Be 'InvalidUserNameOrPassword'
    }
    It 'sends nothing to ip-api.com with -SkipIpLookup' {
        InModuleScope NSP.M365.Investigation { $script:NSPIpInfoCache = @{} }
        $csv = New-CompromiseAudit -Path (Join-Path $TestDrive 'offline.csv')
        Invoke-NSPM365AuditTriage -Path $csv -SkipIpLookup -OutputPath (Join-Path $TestDrive 'offline-out') -WarningAction SilentlyContinue | Out-Null
        Should -Invoke Invoke-WebRequest -ModuleName NSP.M365.Investigation -Times 1 -Exactly -Scope Describe
    }
}

Describe 'Get-NSPM365InboxRuleReport' {
    BeforeAll {
        # Stand-ins for the ExchangeOnlineManagement cmdlets, so they can be mocked.
        function global:Get-InboxRule { [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')] param($Mailbox, [switch]$IncludeHidden) }
        function global:Get-Mailbox { [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')] param($Identity, $ResultSize, $RecipientTypeDetails) }
        function global:Get-AcceptedDomain { }
        Mock Get-AcceptedDomain -ModuleName NSP.M365.Investigation { [pscustomobject]@{ DomainName = 'contoso.com' } }
        Mock Get-Mailbox -ModuleName NSP.M365.Investigation {
            [pscustomobject]@{ PrimarySmtpAddress = 'jdoe@contoso.com'; ForwardingSmtpAddress = 'smtp:drop@evil.example'; ForwardingAddress = $null; DeliverToMailboxAndForward = $false }
            [pscustomobject]@{ PrimarySmtpAddress = 'amy@contoso.com'; ForwardingSmtpAddress = $null; ForwardingAddress = $null; DeliverToMailboxAndForward = $false }
        }
        Mock Get-InboxRule -ModuleName NSP.M365.Investigation {
            if ($Mailbox -eq 'jdoe@contoso.com') {
                [pscustomobject]@{ Name = '.'; Enabled = $true; Identity = 'jdoe\123'; MoveToFolder = 'jdoe:\RSS Feeds'; ForwardTo = @('"Drop" [SMTP:drop@evil.example]'); RedirectTo = $null; ForwardAsAttachmentTo = $null; DeleteMessage = $false; SoftDeleteMessage = $false; MarkAsRead = $true; SubjectContainsWords = @('invoice'); Description = 'If the subject includes invoice...' }
                [pscustomobject]@{ Name = 'Junk E-mail Rule'; Enabled = $true; Identity = 'jdoe\1' }
            } else {
                [pscustomobject]@{ Name = 'Team'; Enabled = $true; Identity = 'amy\5'; MoveToFolder = 'amy:\Team'; ForwardTo = @('"Boss" [EX:/o=ExchangeLabs/cn=boss]'); DeleteMessage = $false; MarkAsRead = $false }
            }
        }
    }
    AfterAll { Remove-Item function:\Get-InboxRule, function:\Get-Mailbox, function:\Get-AcceptedDomain -ErrorAction SilentlyContinue }

    It 'reports mailbox forwarding and rules, skipping the junk mail rule' {
        $rows = @(Get-NSPM365InboxRuleReport)
        $rows.Count | Should -Be 3
        $rows.RuleName | Should -Not -Contain 'Junk E-mail Rule'
        ($rows | Where-Object Kind -EQ 'MailboxForwarding').Flags | Should -Be 'Forwards'
        ($rows | Where-Object RuleName -EQ '.').Flags | Should -Be 'Forwards; MarksRead; MovesTo:RSS Feeds; OddName; TargetsKeywords'
        ($rows | Where-Object RuleName -EQ 'Team').Suspicious | Should -BeFalse
    }
    It 'keeps only flagged rows with -SuspiciousOnly' {
        @(Get-NSPM365InboxRuleReport -SuspiciousOnly).Count | Should -Be 2
    }
    It 'reads hidden rules' {
        Get-NSPM365InboxRuleReport | Out-Null
        Should -Invoke Get-InboxRule -ModuleName NSP.M365.Investigation -ParameterFilter { $IncludeHidden } -Times 2 -Exactly
    }
}

Describe 'ConvertFrom-NSPM365MessageTrace' {
    It 'splits a historical (UTF-16) trace into one row per recipient' {
        $path = Join-Path $TestDrive 'MTSummary_jdoe_Sender.csv'
        @([pscustomobject]@{ origin_timestamp_utc = '2026-10-02T04:00:00.0000000Z'; sender_address = 'jdoe@contoso.com'; recipient_status = 'a@fabrikam.example##Receive, Deliver;b@tailspin.example##Receive, Fail'; message_subject = 'jdoe shared "Overdue invoice" with you'; total_bytes = '5120'; message_id = '<m1@contoso.com>'; network_message_id = 'n-1'; original_client_ip = $script:Foreign; directionality = 'Originating'; connector_id = ''; delivery_priority = 'Normal' }) |
            Export-Csv -LiteralPath $path -NoTypeInformation -Encoding Unicode
        $rows = @(ConvertFrom-NSPM365MessageTrace $path)
        $rows.Count | Should -Be 2
        $rows[0].Recipient | Should -Be 'a@fabrikam.example'
        $rows[0].RecipientDomain | Should -Be 'fabrikam.example'
        $rows[0].Status | Should -Be 'Receive, Deliver'
        $rows[1].Status | Should -Be 'Receive, Fail'
        $rows[0].SenderDomain | Should -Be 'contoso.com'
        $rows[0].ClientIP | Should -Be $script:Foreign
        $rows[0].TimeUtc | Should -Be '2026-10-02 04:00:00Z'
        $rows[0].SourceFile | Should -Be 'MTSummary_jdoe_Sender.csv'
    }
    It 'reads the current export format' {
        $path = Join-Path $TestDrive 'MessageTraceResult.csv'
        @([pscustomobject]@{ MessageId = '<m2@contoso.com>'; Received = '2026-10-02T04:05:00.000Z'; SenderAddress = 'jdoe@contoso.com'; RecipientAddress = 'C@Fabrikam.example'; Subject = 'Hi'; Status = 'Delivered'; ToIP = ''; FromIP = $script:Foreign; Size = '100'; MessageTraceId = 't-2' }) |
            Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8
        $row = ConvertFrom-NSPM365MessageTrace -Path $path
        $row.RecipientDomain | Should -Be 'fabrikam.example'
        $row.Status | Should -Be 'Delivered'
        $row.TraceId | Should -Be 't-2'
    }
    It 'refuses a CSV that is not a message trace' {
        $path = Join-Path $TestDrive 'other.csv'
        @([pscustomobject]@{ A = 1 }) | Export-Csv -LiteralPath $path -NoTypeInformation
        { ConvertFrom-NSPM365MessageTrace $path } | Should -Throw '*not a message trace export*'
    }
}
