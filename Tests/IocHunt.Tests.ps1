# Invoke-NSPM365IocHunt against a synthetic tenant planted with the SkyKick tradecraft Huntress and
# Guardz describe. Graph is the NSP.M365.Graph Fake transport; nothing signs in or leaves the host.

BeforeAll {
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'NSP.M365.Investigation.psd1') -Force -ErrorAction Stop
    InModuleScope NSP.M365.Investigation { Import-NSPM365Graph }

    $script:TenantGuid = '00000000-0000-4000-8000-0000000000a1'
    $script:OtherGuid = '00000000-0000-4000-8000-0000000000b2'
    $script:TeamsAppId = '24205314-2b89-4e07-a2a4-579e898a5640'
    $script:HuntressAppId = 'aaaaaaaa-0000-4000-8000-000000000001'

    function New-FakeTenant {
        # A tenant where the vendor's Teams app gave itself Global Administrator, planted a secret
        # on an unrelated app, and used it from an IOC IP.
        param([switch]$NoPremium)
        $sp = {
            param($Id, $AppId, $Name, $Enabled, $Owner = '00000000-0000-4000-8000-0000000000ff')
            @{ id = $Id; appId = $AppId; displayName = $Name; accountEnabled = $Enabled; appOwnerOrganizationId = $Owner; servicePrincipalType = 'Application'; keyCredentials = @(); passwordCredentials = @() }
        }
        $state = @{
            NoPremium = [bool]$NoPremium
            Org = @{ id = $script:TenantGuid; displayName = 'Contoso' }
            Sps = @(
                (& $sp 'sp-teams' $script:TeamsAppId 'ConnectWise Cloud Management - MS Teams' $true '3f9cd7a0-127a-4ed4-bf06-2f830d5616b7')
                (& $sp 'sp-backup' '506e08f9-6e9a-4da4-942b-a099a03644ae' 'SkyKick Cloud Backup' $false)
                (& $sp 'sp-psa' '11111111-2222-4333-8444-555555555555' 'ConnectWise PSA Sync' $true)
                (& $sp 'sp-huntress' $script:HuntressAppId 'Huntress Integration' $true)
                (& $sp 'sp-backuptool' 'bbbbbbbb-0000-4000-8000-000000000002' 'Backup Tool' $true)
            )
            RoleAssignments = @(
                @{ id = 'ra-1'; principalId = 'sp-teams'; roleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'; directoryScopeId = '/'
                    roleDefinition = @{ displayName = 'Global Administrator' }
                    principal = @{ '@odata.type' = '#microsoft.graph.servicePrincipal'; displayName = 'ConnectWise Cloud Management - MS Teams'; appId = $script:TeamsAppId } }
                @{ id = 'ra-2'; principalId = 'u-admin'; roleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'; directoryScopeId = '/'
                    principal = @{ '@odata.type' = '#microsoft.graph.user'; displayName = 'Admin' } }
                @{ id = 'ra-3'; principalId = 'sp-backuptool'; roleDefinitionId = '29232cdf-9323-42fd-ade2-1d097af3e4de'; directoryScopeId = '/'
                    principal = @{ '@odata.type' = '#microsoft.graph.servicePrincipal'; displayName = 'Backup Tool'; appId = 'bbbbbbbb-0000-4000-8000-000000000002' } }
            )
            AppRoleAssignments = @{
                'sp-teams' = @(@{ resourceId = 'res-graph'; resourceDisplayName = 'Microsoft Graph'; appRoleId = 'role-drw' })
            }
            AppRoles = @{ 'res-graph' = @(@{ id = 'role-drw'; value = 'Directory.ReadWrite.All' }) }
            Audits = @(
                @{ id = 'a-1'; category = 'RoleManagement'; activityDisplayName = 'Add member to role'; activityDateTime = '2026-10-15T03:12:00Z'; result = 'success'
                    initiatedBy = @{ app = @{ servicePrincipalId = 'sp-teams'; appId = $script:TeamsAppId; displayName = 'ConnectWise Cloud Management - MS Teams' } }
                    targetResources = @(@{ id = 'sp-teams'; displayName = 'ConnectWise Cloud Management - MS Teams' }, @{ id = 'role-ga'; displayName = 'Global Administrator' })
                    additionalDetails = @(@{ key = 'User-Agent'; value = 'python-requests/2.31.0' }) }
                @{ id = 'a-2'; category = 'ApplicationManagement'; activityDisplayName = 'Update application - Certificates and secrets management'; activityDateTime = '2026-10-15T03:20:00Z'; result = 'success'
                    initiatedBy = @{ app = @{ servicePrincipalId = 'sp-teams'; appId = $script:TeamsAppId; displayName = 'ConnectWise Cloud Management - MS Teams' } }
                    targetResources = @(@{ id = 'app-huntress'; displayName = 'Huntress Integration' }) }
                @{ id = 'a-3'; category = 'ApplicationManagement'; activityDisplayName = 'Update application - Certificates and secrets management'; activityDateTime = '2026-10-16T14:00:00Z'; result = 'success'
                    initiatedBy = @{ user = @{ userPrincipalName = 'admin@contoso.com' } }
                    targetResources = @(@{ id = 'app-payroll'; displayName = 'Payroll Sync' }) }
            )
            Apps = @(
                @{ id = 'app-huntress'; appId = $script:HuntressAppId; displayName = 'Huntress Integration'; keyCredentials = @()
                    passwordCredentials = @(
                        @{ keyId = 'k-new'; displayName = 'x'; startDateTime = '2026-10-15T03:20:00Z'; endDateTime = '2028-10-15T03:20:00Z' }
                        @{ keyId = 'k-old'; displayName = 'prod'; startDateTime = '2025-01-01T00:00:00Z'; endDateTime = '2027-01-01T00:00:00Z' }
                    ) }
                @{ id = 'app-payroll'; appId = 'cccccccc-0000-4000-8000-000000000003'; displayName = 'Payroll Sync'; keyCredentials = @(); passwordCredentials = @() }
            )
            SignIns = @(
                @{ id = 's-1'; appId = $script:TeamsAppId; appDisplayName = 'ConnectWise Cloud Management - MS Teams'; ipAddress = '144.172.64.128'; createdDateTime = '2026-10-15T03:10:00Z'
                    signInEventTypes = @('servicePrincipal'); resourceDisplayName = 'Microsoft Graph'; status = @{ errorCode = 0 } }
                @{ id = 's-2'; appId = $script:TeamsAppId; appDisplayName = 'ConnectWise Cloud Management - MS Teams'; ipAddress = 'fde4:8dba:2600:37ce:6d26:200:a76:a0e9'; createdDateTime = '2026-10-12T08:00:00Z'
                    signInEventTypes = @('servicePrincipal'); resourceDisplayName = 'Microsoft Graph'; status = @{ errorCode = 0 } }
                @{ id = 's-3'; appId = 'de8bc8b5-d9f9-48b1-a8ad-b748da725064'; appDisplayName = 'Graph Explorer'; userPrincipalName = 'admin@contoso.com'; ipAddress = '144.172.64.99'; createdDateTime = '2026-10-13T22:00:00Z'
                    signInEventTypes = @('interactiveUser'); userAgent = 'curl/7.88.1'; status = @{ errorCode = 50126; failureReason = 'Invalid username or password.' } }
                @{ id = 's-4'; appId = $script:HuntressAppId; appDisplayName = 'Huntress Integration'; ipAddress = '144.172.64.60'; createdDateTime = '2026-10-15T04:00:00Z'
                    signInEventTypes = @('servicePrincipal'); resourceDisplayName = 'Microsoft Graph'; servicePrincipalCredentialKeyId = 'k-new'; status = @{ errorCode = 0 } }
                @{ id = 's-5'; appId = $script:HuntressAppId; appDisplayName = 'Huntress Integration'; ipAddress = '203.0.113.20'; createdDateTime = '2026-10-15T05:00:00Z'
                    signInEventTypes = @('servicePrincipal'); resourceDisplayName = 'Microsoft Graph'; servicePrincipalCredentialKeyId = 'k-old'; status = @{ errorCode = 0 } }
            )
            Users = @(@{ id = 'u-temp'; userPrincipalName = 'temp@contoso.com'; userType = 'Member'; accountEnabled = $true; createdDateTime = '2026-10-15T04:30:00Z' })
        }

        $responder = {
            param($Method, $Uri)
            $path = [uri]::UnescapeDataString($Uri) -replace '^(v1\.0|beta)/', ''
            if ($Method -eq 'PATCH') { return @{} }
            if ($path -like 'organization*') { return @{ value = @($state.Org) } }
            if ($path -match '^auditLogs/signIns') {
                if ($state.NoPremium) { throw 'Authentication_RequestFromNonPremiumTenantOrB2CTenant: Neither tenant is B2C or tenant does not have premium license' }
                $eventType = if ($path -match "t eq '([^']+)'") { $Matches[1] }
                $items = @($state.SignIns | Where-Object { $_.signInEventTypes -contains $eventType })
                if ($path -match "ipAddress eq '([^']+)'") { $ip = $Matches[1]; return @{ value = @($items | Where-Object { $_.ipAddress -eq $ip }) } }
                if ($path -match "appId eq '([^']+)'") { $appId = $Matches[1]; return @{ value = @($items | Where-Object { $_.appId -eq $appId }) } }
            }
            if ($path -match "^servicePrincipals\?.*appId eq '([^']+)'") { $appId = $Matches[1]; return @{ value = @($state.Sps | Where-Object { $_.appId -eq $appId }) } }
            if ($path -match '^servicePrincipals\?.*appOwnerOrganizationId eq ([0-9a-f-]+)') { $owner = $Matches[1]; return @{ value = @($state.Sps | Where-Object { $_.appOwnerOrganizationId -eq $owner }) } }
            if ($path -match "^servicePrincipals\?.*startswith\(displayName,'([^']+)'\)") { $prefix = $Matches[1]; return @{ value = @($state.Sps | Where-Object { $_.displayName -like "$prefix*" }) } }
            if ($path -match '^servicePrincipals\?\$select=') { return @{ value = @($state.Sps) } }
            if ($path -match '^servicePrincipals/([^/?]+)/appRoleAssignments') { return @{ value = @($state.AppRoleAssignments[$Matches[1]] | Where-Object { $_ }) } }
            if ($path -match '^servicePrincipals/([^/?]+)\?\$select=appRoles') { return @{ appRoles = @($state.AppRoles[$Matches[1]]) } }
            if ($path -match "^roleManagement/directory/roleAssignments\?.*principalId eq '([^']+)'") { $id = $Matches[1]; return @{ value = @($state.RoleAssignments | Where-Object { $_.principalId -eq $id }) } }
            if ($path -match "^roleManagement/directory/roleAssignments\?.*roleDefinitionId eq '([^']+)'") { $id = $Matches[1]; return @{ value = @($state.RoleAssignments | Where-Object { $_.roleDefinitionId -eq $id }) } }
            if ($path -match "^auditLogs/directoryAudits\?.*category eq '([^']+)'") { $category = $Matches[1]; return @{ value = @($state.Audits | Where-Object { $_.category -eq $category }) } }
            if ($path -match '^applications\?') { return @{ value = @($state.Apps) } }
            if ($path -match '^users\?') { return @{ value = @($state.Users) } }
            throw "Fake tenant cannot answer $Method $path"
        }.GetNewClosure()
        Set-NSPGraphTransport -Name Fake -Responder $responder
        $state
    }

    function Invoke-Hunt {
        # Runs the hunt quietly into a fresh folder and returns the findings.
        param([hashtable]$Extra = @{})
        $script:Out = Join-Path $TestDrive ([guid]::NewGuid().Guid)
        $hunt = @{ IocSet = 'SkyKick'; TenantId = $script:TenantGuid; OutputPath = $script:Out; PassThru = $true }
        foreach ($key in $Extra.Keys) { $hunt[$key] = $Extra[$key] }
        if ($hunt.ContainsKey('TenantCsv')) { $hunt.Remove('TenantId') }
        @(Invoke-NSPM365IocHunt @hunt)
    }

    function Find-Finding {
        param([object[]]$Findings, [string]$Check, [string]$Object = '*')
        @($Findings | Where-Object { $_.Check -like $Check -and $_.Object -like $Object })
    }
}

AfterAll { Set-NSPGraphTransport -Name MgGraphRequest }

Describe 'Invoke-NSPM365IocHunt against a planted tenant' {
    BeforeAll {
        Mock Connect-NSPHuntTenant { } -ModuleName NSP.M365.Investigation
        Mock Start-Sleep { } -ModuleName NSP.M365.Investigation
        Mock Write-Host { } -ModuleName NSP.M365.Investigation
        Mock Out-Host { } -ModuleName NSP.M365.Investigation
        $null = New-FakeTenant
        $script:Findings = Invoke-Hunt
    }

    It 'flags an app giving a role to itself as Critical' {
        $f = Find-Finding $Findings 'Audit: Add member to role'
        $f.Severity | Should -Be 'Critical'
        $f.Detail | Should -Match 'ITSELF'
        $f.Detail | Should -Match 'IOC user agent'
    }

    It 'reports the enabled IOC app High, the disabled one Info, and a name-only match for review' {
        (Find-Finding $Findings 'IOC app ENABLED' 'ConnectWise Cloud Management - MS Teams*').Severity | Should -Be 'High'
        (Find-Finding $Findings 'IOC app disabled' 'SkyKick Cloud Backup*').Severity | Should -Be 'Info'
        (Find-Finding $Findings 'Related app ENABLED' 'ConnectWise PSA Sync*').Severity | Should -Be 'Medium'
    }

    It 'reports the IOC app''s Global Administrator role and high-risk permissions' {
        (Find-Finding $Findings 'IOC app holds directory role').Severity | Should -Be 'High'
        $permissions = Find-Finding $Findings 'IOC app permissions'
        $permissions.Severity | Should -Be 'Medium'
        $permissions.Detail | Should -Match 'Directory\.ReadWrite\.All'
    }

    It 'lists other privileged service principals for review, but not the IOC app twice' {
        (Find-Finding $Findings 'Service principal with privileged role' 'Backup Tool*').Severity | Should -Be 'Low'
        Find-Finding $Findings 'Service principal with privileged role' 'ConnectWise*' | Should -BeNullOrEmpty
    }

    It 'raises a secret an application planted on an unrelated app to High, and ignores old secrets' {
        $f = @(Find-Finding $Findings 'New credential (App registration)' 'Huntress Integration*')
        $f.Count | Should -Be 1
        $f.Severity | Should -Be 'High'
        $f.Detail | Should -Match 'k-new'
        (Find-Finding $Findings 'Audit: Update application*' 'Payroll Sync').Severity | Should -Be 'Low'
    }

    It 'flags IOC app and IOC IP sign-ins' {
        (Find-Finding $Findings 'IOC app sign-in from IOC IP').Severity | Should -Be 'Critical'
        $failed = Find-Finding $Findings 'Sign-in from IOC IP' 'admin@contoso.com*'
        $failed.Severity | Should -Be 'High'
        $failed.Detail | Should -Match 'curl/7\.88\.1'
    }

    It 'summarises other IOC app sign-ins with the context note' {
        $f = Find-Finding $Findings 'IOC app sign-ins (summary)'
        $f.Severity | Should -Be 'Medium'
        $f.Detail | Should -Match 'Microsoft-internal ULA'
    }

    It 'reports the planted secret signing in from an IOC IP as Critical, and not the old secret' {
        $f = @(Find-Finding $Findings 'New credential USED')
        $f.Count | Should -Be 1
        $f.Severity | Should -Be 'Critical'
        $f.Detail | Should -Match 'k-new used from 144\.172\.64\.60'
    }

    It 'lists users created in the window' {
        (Find-Finding $Findings 'User created in window' 'temp@contoso.com').Severity | Should -Be 'Info'
    }

    It 'labels findings with the tenant it read' {
        @($Findings.Tenant | Select-Object -Unique) | Should -Be @("Contoso [$TenantGuid]")
    }

    It 'writes Findings.csv sorted by severity, and the raw evidence' {
        $csv = @(Import-Csv -LiteralPath (Join-Path $Out 'Findings.csv'))
        $csv.Count | Should -Be $Findings.Count
        $csv[0].Severity | Should -Be 'Critical'
        $csv[-1].Severity | Should -Be 'Info'
        # 'Contoso [<id>]' as a folder name.
        $evidence = Join-Path $Out "Contoso__$($TenantGuid)_"
        foreach ($name in 'directoryAudits_AppAndRoleMgmt', 'signIns_IocApps_ServicePrincipal', 'signIns_IocIPs_AllTypes', 'signIns_NewCredentialUse') {
            Join-Path $evidence "$name.json" | Should -Exist
        }
    }

    It 'changes nothing without -DisableIocApps' {
        @((Get-NSPGraphTransport).CallLog | Where-Object Method -NE 'GET').Count | Should -Be 0
    }
}

Describe 'Tenant guard' {
    BeforeAll {
        Mock Connect-NSPHuntTenant { } -ModuleName NSP.M365.Investigation
        Mock Start-Sleep { } -ModuleName NSP.M365.Investigation
        Mock Write-Host { } -ModuleName NSP.M365.Investigation
        Mock Out-Host { } -ModuleName NSP.M365.Investigation
    }

    It 'refuses to report a tenant other than the one asked for' {
        $null = New-FakeTenant
        $findings = @(Invoke-Hunt -Extra @{ TenantId = $OtherGuid })
        $findings.Count | Should -Be 1
        $findings[0].Severity | Should -Be 'Warning'
        $findings[0].Check | Should -Be 'Tenant run'
        $findings[0].Detail | Should -Match "expected $OtherGuid"
        @((Get-NSPGraphTransport).CallLog).Count | Should -Be 1
    }

    It 'resolves a domain to its tenant ID and connects to that ID' {
        Mock Invoke-RestMethod { [pscustomobject]@{ issuer = "https://login.microsoftonline.com/$TenantGuid/v2.0" } } -ModuleName NSP.M365.Investigation
        $null = New-FakeTenant
        $findings = Invoke-Hunt -Extra @{ TenantId = 'contoso.com' }
        Find-Finding $findings 'Tenant run' | Should -BeNullOrEmpty
        Should -Invoke Connect-NSPHuntTenant -ModuleName NSP.M365.Investigation -ParameterFilter { $TenantId -eq $TenantGuid }
    }

    It 'runs each tenant in a CSV and reports a failed one without stopping' {
        $null = New-FakeTenant
        $csv = Join-Path $TestDrive 'tenants.csv'
        @([pscustomobject]@{ TenantId = $OtherGuid; Name = 'Fabrikam' }, [pscustomobject]@{ TenantId = $TenantGuid; Name = 'Contoso' }) | Export-Csv -LiteralPath $csv -NoTypeInformation
        $findings = Invoke-Hunt -Extra @{ TenantCsv = $csv }
        (Find-Finding $findings 'Tenant run' 'Fabrikam').Severity | Should -Be 'Warning'
        (Find-Finding $findings 'Audit: Add member to role').Severity | Should -Be 'Critical'
    }
}

Describe 'Tenant without Entra ID P1' {
    BeforeAll {
        Mock Connect-NSPHuntTenant { } -ModuleName NSP.M365.Investigation
        Mock Start-Sleep { } -ModuleName NSP.M365.Investigation
        Mock Write-Host { } -ModuleName NSP.M365.Investigation
        Mock Out-Host { } -ModuleName NSP.M365.Investigation
        $null = New-FakeTenant -NoPremium
        $script:Findings = Invoke-Hunt
    }

    It 'says to export the sign-ins by hand, once, and stops asking' {
        (Find-Finding $Findings 'Sign-in logs').Severity | Should -Be 'Warning'
        Find-Finding $Findings 'Sign-in query' | Should -BeNullOrEmpty
        @((Get-NSPGraphTransport).CallLog | Where-Object Uri -Match 'signIns').Count | Should -Be 1
    }

    It 'still reports everything that does not need sign-in logs' {
        (Find-Finding $Findings 'Audit: Add member to role').Severity | Should -Be 'Critical'
        (Find-Finding $Findings 'New credential (App registration)').Severity | Should -Be 'High'
    }
}

Describe '-DisableIocApps' {
    BeforeAll {
        Mock Connect-NSPHuntTenant { } -ModuleName NSP.M365.Investigation
        Mock Start-Sleep { } -ModuleName NSP.M365.Investigation
        Mock Write-Host { } -ModuleName NSP.M365.Investigation
        Mock Out-Host { } -ModuleName NSP.M365.Investigation
    }

    It 'changes nothing under -WhatIf, and still writes the report' {
        $null = New-FakeTenant
        $null = Invoke-Hunt -Extra @{ DisableIocApps = $true; WhatIf = $true }
        @((Get-NSPGraphTransport).CallLog | Where-Object Method -NE 'GET').Count | Should -Be 0
        Join-Path $Out 'Findings.csv' | Should -Exist
    }

    It 'disables only the enabled apps whose app ID is in the set' {
        $null = New-FakeTenant
        $findings = Invoke-Hunt -Extra @{ DisableIocApps = $true; Confirm = $false }
        $writes = @((Get-NSPGraphTransport).CallLog | Where-Object Method -NE 'GET')
        $writes.Count | Should -Be 1
        $writes[0].Method | Should -Be 'PATCH'
        $writes[0].Uri | Should -Be 'v1.0/servicePrincipals/sp-teams'
        $writes[0].Body.accountEnabled | Should -BeFalse
        (Find-Finding $findings 'Remediation').Detail | Should -Match 'DISABLED'
    }

    It 'asks for write access only when disabling' {
        $null = New-FakeTenant
        $null = Invoke-Hunt
        Should -Invoke Connect-NSPHuntTenant -ModuleName NSP.M365.Investigation -ParameterFilter { $Scopes -notcontains 'Application.ReadWrite.All' }
        $null = Invoke-Hunt -Extra @{ DisableIocApps = $true; WhatIf = $true }
        Should -Invoke Connect-NSPHuntTenant -ModuleName NSP.M365.Investigation -ParameterFilter { $Scopes -contains 'Application.ReadWrite.All' }
    }
}

Describe 'Parameter checks' {
    It 'needs both -ClientId and -CertificateThumbprint' {
        { Invoke-NSPM365IocHunt -IocSet SkyKick -TenantId $TenantGuid -ClientId 'x' -OutputPath $TestDrive } | Should -Throw '*both -ClientId and -CertificateThumbprint*'
    }

    It 'needs a tenant for app-only sign-in' {
        { Invoke-NSPM365IocHunt -IocSet SkyKick -ClientId 'x' -CertificateThumbprint 'y' -OutputPath $TestDrive } | Should -Throw '*needs a tenant*'
    }
}
