# The per-tenant checks Invoke-NSPHuntTenant runs, in the order it runs them. Each reads Graph
# through Get-NSPHuntCollection and records findings with Add-NSPHuntFinding.

$script:NSPHuntSpSelect = 'id,appId,displayName,accountEnabled,appOwnerOrganizationId,servicePrincipalType,keyCredentials,passwordCredentials'

function Find-NSPHuntIocServicePrincipal {
    # The IOC apps' service principals (by app ID, owner tenant, display name prefix): whether they
    # are enabled, which directory roles they hold, and what application permissions they have.
    # Returns the service principals.
    param([Parameter(Mandatory)][hashtable]$Hunt)
    $ioc = $Hunt.Ioc
    $select = '$select=' + $script:NSPHuntSpSelect
    $found = @{}
    foreach ($appId in $ioc.Apps.Keys) {
        foreach ($sp in (Get-NSPHuntCollection -Uri (New-NSPHuntFilterUri 'servicePrincipals' "appId eq '$appId'" $select))) { $found[$sp.id] = $sp }
    }
    foreach ($owner in $ioc.OwnerTenantIds) {
        try {
            foreach ($sp in (Get-NSPHuntCollection -Uri (New-NSPHuntFilterUri 'servicePrincipals' "appOwnerOrganizationId eq $owner" $select))) { $found[$sp.id] = $sp }
        } catch { Write-Verbose "Owner-tenant filter not supported here: $($_.Exception.Message)" }
    }
    foreach ($prefix in $ioc.NamePrefixes) {
        foreach ($sp in (Get-NSPHuntCollection -Uri (New-NSPHuntFilterUri 'servicePrincipals' "startswith(displayName,'$prefix')" $select))) { $found[$sp.id] = $sp }
    }
    $sps = @($found.Values)

    if ($sps.Count -eq 0) {
        Add-NSPHuntFinding -Hunt $Hunt -Severity Info -Check 'IOC apps present' -Object '-' -Detail "No $($ioc.Name) service principals found."
    }
    foreach ($sp in $sps) {
        $object = "$($sp.displayName) ($($sp.appId))"
        $known = $ioc.Apps.ContainsKey(([string]$sp.appId).ToLowerInvariant())
        $label = if ($known) { $ioc.Apps[([string]$sp.appId).ToLowerInvariant()] } else { "Matched by owner tenant $($sp.appOwnerOrganizationId) or name; not a listed IOC app ID" }
        if ($sp.accountEnabled -and $known) {
            Add-NSPHuntFinding -Hunt $Hunt -Severity High -Check 'IOC app ENABLED' -Object $object -Detail "$label. Service principal still enabled; disable (do not delete)."
        } elseif ($sp.accountEnabled) {
            Add-NSPHuntFinding -Hunt $Hunt -Severity Medium -Check 'Related app ENABLED' -Object $object -Detail "$label. Review whether it is in use; -DisableIocApps leaves it alone."
        } else {
            Add-NSPHuntFinding -Hunt $Hunt -Severity Info -Check 'IOC app disabled' -Object $object -Detail $label
        }

        $assignments = Get-NSPHuntCollection -Uri (New-NSPHuntFilterUri 'roleManagement/directory/roleAssignments' "principalId eq '$($sp.id)'" '$expand=roleDefinition')
        foreach ($assignment in $assignments) {
            $roleName = Get-NSPHuntValue $assignment 'roleDefinition', 'displayName'
            $severity = if ($script:NSPHuntPrivilegedRoles.ContainsKey([string]$assignment.roleDefinitionId)) { 'High' } else { 'Medium' }
            Add-NSPHuntFinding -Hunt $Hunt -Severity $severity -Check 'IOC app holds directory role' -Object $object -Detail "Role: $roleName (scope $($assignment.directoryScopeId)). Remove if not intentionally granted." -Evidence $assignment
        }

        $permissions = New-Object System.Collections.Generic.List[string]
        foreach ($grant in (Get-NSPHuntCollection -Uri "servicePrincipals/$($sp.id)/appRoleAssignments")) {
            $permissions.Add("$($grant.resourceDisplayName):$(Resolve-NSPHuntAppRoleName -Hunt $Hunt -ResourceId $grant.resourceId -AppRoleId $grant.appRoleId)")
        }
        if ($permissions.Count -gt 0) {
            $risky = @($permissions | Where-Object { $p = $_; @($script:NSPHuntHighRiskAppPermissions | Where-Object { $p -like "*:$_" }).Count })
            $severity = if ($risky.Count -gt 0 -and $sp.accountEnabled) { 'Medium' } else { 'Info' }
            Add-NSPHuntFinding -Hunt $Hunt -Severity $severity -Check 'IOC app permissions' -Object $object -Detail ('{0} app permissions; high-risk: {1}' -f $permissions.Count, ($risky -join ', ')) -Evidence $permissions.ToArray()
        }
    }
    $sps
}

function Find-NSPHuntPrivilegedServicePrincipal {
    # Every other service principal holding a privileged role: a review list.
    param([Parameter(Mandatory)][hashtable]$Hunt, [string[]]$IocSpIds = @())
    foreach ($roleId in $script:NSPHuntPrivilegedRoles.Keys) {
        foreach ($assignment in (Get-NSPHuntCollection -Uri (New-NSPHuntFilterUri 'roleManagement/directory/roleAssignments' "roleDefinitionId eq '$roleId'" '$expand=principal'))) {
            if ((Get-NSPHuntValue $assignment 'principal', '@odata.type') -ne '#microsoft.graph.servicePrincipal') { continue }
            if ($IocSpIds -contains $assignment.principalId) { continue }
            $name = Get-NSPHuntValue $assignment 'principal', 'displayName'
            $appId = Get-NSPHuntValue $assignment 'principal', 'appId'
            Add-NSPHuntFinding -Hunt $Hunt -Severity Low -Check 'Service principal with privileged role' -Object "$name ($appId)" -Detail "$($script:NSPHuntPrivilegedRoles[$roleId]) - confirm this is intended."
        }
    }
}

function Find-NSPHuntAuditEvent {
    # ApplicationManagement and RoleManagement directory audits in the window. Flags apps granting
    # roles (to themselves: Critical), IOC apps acting or being granted roles, credentials added by
    # applications, and IOC user agents. Returns the object IDs an application added credentials to.
    param([Parameter(Mandatory)][hashtable]$Hunt, [string[]]$IocSpIds = @())
    $ioc = $Hunt.Ioc
    $audits = New-Object System.Collections.Generic.List[object]
    foreach ($category in 'ApplicationManagement', 'RoleManagement') {
        try {
            foreach ($e in (Get-NSPHuntCollection -Uri (New-NSPHuntFilterUri 'auditLogs/directoryAudits' "activityDateTime ge $($Hunt.SinceIso) and category eq '$category'" '$top=999'))) { $audits.Add($e) }
        } catch {
            Add-NSPHuntFinding -Hunt $Hunt -Severity Warning -Check 'Audit log query' -Object $category -Detail "Failed: $($_.Exception.Message)"
        }
    }
    Save-NSPHuntEvidence -Hunt $Hunt -Data $audits.ToArray() -Name 'directoryAudits_AppAndRoleMgmt'

    $appCredentialTargets = @{}
    foreach ($e in $audits) {
        $activity = [string]$e.activityDisplayName
        $appSpId = Get-NSPHuntValue $e 'initiatedBy', 'app', 'servicePrincipalId'
        $appId = Get-NSPHuntValue $e 'initiatedBy', 'app', 'appId'
        $appName = Get-NSPHuntValue $e 'initiatedBy', 'app', 'displayName'
        $user = Get-NSPHuntValue $e 'initiatedBy', 'user', 'userPrincipalName'
        $userAgent = $null
        foreach ($detail in @(Get-NSPHuntValue $e 'additionalDetails')) { if ($detail -and (Get-NSPHuntValue $detail 'key') -eq 'User-Agent') { $userAgent = Get-NSPHuntValue $detail 'value' } }
        $targets = @(Get-NSPHuntValue $e 'targetResources' | Where-Object { $_ })
        $targetIds = @($targets | ForEach-Object { [string](Get-NSPHuntValue $_ 'id') })
        $targetNames = @($targets | ForEach-Object { Get-NSPHuntValue $_ 'displayName' }) -join '; '
        $initiator = if ($appName -or $appSpId) { "app:$appName ($appSpId)" } else { "user:$user" }

        $byApp = [bool]($appSpId -or $appId)
        $byIocApp = ($appSpId -and $IocSpIds -contains $appSpId) -or ($appId -and $ioc.Apps.ContainsKey(([string]$appId).ToLowerInvariant())) -or ($appName -and $ioc.NameRegex -and $appName -match $ioc.NameRegex)
        $targetsIoc = @($targetIds | Where-Object { $IocSpIds -contains $_ }).Count -gt 0 -or ($ioc.NameRegex -and $targetNames -match $ioc.NameRegex)
        $userAgentHit = $userAgent -and @($ioc.UserAgents | Where-Object { $userAgent -like "*$_*" }).Count -gt 0
        $isRoleAdd = $activity -match 'Add (eligible )?member to role'
        $isCredential = $activity -match 'credentials|Certificates and secrets'
        $selfAssigned = $isRoleAdd -and $appSpId -and ($targetIds -contains $appSpId)

        if ($isCredential -and $byApp) { foreach ($t in $targetIds) { $appCredentialTargets[$t] = $true } }

        $severity = $null
        $why = @()
        if ($selfAssigned) { $severity = 'Critical'; $why += 'service principal assigned a role to ITSELF' }
        if ($byIocApp) { if (-not $severity) { $severity = 'High' }; $why += "initiated by $($ioc.Name) app" }
        if ($isRoleAdd -and $targetsIoc) { if (-not $severity) { $severity = 'High' }; $why += "role granted to $($ioc.Name) app" }
        if ($isRoleAdd -and $byApp -and -not $severity) { $severity = 'Medium'; $why += 'role assignment made by an application' }
        if ($isCredential -and $byApp -and -not $severity) { $severity = 'Medium'; $why += 'credential added by an application' }
        if ($userAgentHit) { if (-not $severity) { $severity = 'Medium' }; $why += "IOC user agent ($userAgent)" }
        if (-not $severity -and $isCredential) { $severity = 'Low'; $why += 'credential change by user (verify)' }

        if ($severity) {
            Add-NSPHuntFinding -Hunt $Hunt -Severity $severity -Check "Audit: $activity" -Object $targetNames -Detail ('{0}; by {1}; result {2}' -f ($why -join '; '), $initiator, $e.result) -Time (Format-NSPHuntUtc $e.activityDateTime) -Evidence $e
        }
    }
    $appCredentialTargets
}

function Find-NSPHuntNewCredential {
    # Secrets and certificates added in the window on every app registration and service principal
    # (the actor planted secrets on unrelated apps). High when an application added it. Returns the
    # new credentials (AppId, Name, KeyId, Type) for the sign-in check.
    param([Parameter(Mandatory)][hashtable]$Hunt, [hashtable]$AppCredentialTargets = @{})
    $newCredentials = New-Object System.Collections.Generic.List[object]
    $apps = Get-NSPHuntCollection -Uri 'applications?$select=id,appId,displayName,keyCredentials,passwordCredentials&$top=999'
    $sps = Get-NSPHuntCollection -Uri ('servicePrincipals?$select=' + $script:NSPHuntSpSelect + '&$top=999')
    # Small grace: some tools backdate startDateTime by a few minutes.
    $windowStart = $Hunt.Since.AddMinutes(-10)
    foreach ($set in @(@{ Kind = 'App registration'; Items = $apps }, @{ Kind = 'Service principal'; Items = $sps })) {
        foreach ($o in $set.Items) {
            $credentials = @(
                foreach ($c in @(Get-NSPHuntValue $o 'passwordCredentials')) { if ($c) { [pscustomobject]@{ Type = 'Secret'; C = $c } } }
                foreach ($c in @(Get-NSPHuntValue $o 'keyCredentials')) { if ($c) { [pscustomobject]@{ Type = 'Certificate'; C = $c } } }
            )
            foreach ($credential in $credentials) {
                $start = Get-NSPHuntValue $credential.C 'startDateTime'
                if (-not $start -or (ConvertTo-NSPHuntUtc $start) -lt $windowStart) { continue }
                $severity = 'Medium'
                $why = 'Added in hunt window. Verify someone on your side created it.'
                if ($AppCredentialTargets.ContainsKey([string]$o.id)) { $severity = 'High'; $why = 'Added in hunt window BY AN APPLICATION (see audit findings).' }
                if ($set.Kind -eq 'Service principal' -and $credential.Type -eq 'Certificate' -and (Get-NSPHuntValue $credential.C 'usage') -eq 'Verify' -and (Get-NSPHuntValue $o 'servicePrincipalType') -eq 'Application' -and $severity -eq 'Medium') {
                    # SAML signing certificates show up here; keep them, lower, when nothing else points at them.
                    $severity = 'Low'; $why += ' (possibly a SAML/SSO signing cert)'
                }
                $keyId = Get-NSPHuntValue $credential.C 'keyId'
                Add-NSPHuntFinding -Hunt $Hunt -Severity $severity -Check "New credential ($($set.Kind))" -Object "$($o.displayName) ($($o.appId))" -Detail ("{0} '{1}' keyId {2}, expires {3}. {4}" -f $credential.Type, (Get-NSPHuntValue $credential.C 'displayName'), $keyId, (Format-NSPHuntUtc (Get-NSPHuntValue $credential.C 'endDateTime')), $why) -Time (Format-NSPHuntUtc $start)
                $newCredentials.Add([pscustomobject]@{ AppId = $o.appId; Name = $o.displayName; KeyId = $keyId; Type = $credential.Type })
            }
        }
    }
    , $newCredentials.ToArray()
}

function Find-NSPHuntSignIn {
    # Sign-in logs (beta): service principal sign-ins of the IOC apps, sign-ins of any type from
    # the IOC IPs, and whether a credential added in the window has signed in.
    param([Parameter(Mandatory)][hashtable]$Hunt, [object[]]$AddedKeys = @())
    $ioc = $Hunt.Ioc
    $base = 'auditLogs/signIns'
    $top = '$top=999'
    $premiumBlocked = $false

    # IOC apps' service principal sign-ins
    $appSignIns = New-Object System.Collections.Generic.List[object]
    foreach ($appId in $ioc.Apps.Keys) {
        try {
            $filter = "createdDateTime ge $($Hunt.SinceIso) and appId eq '$appId' and signInEventTypes/any(t: t eq 'servicePrincipal')"
            foreach ($s in (Get-NSPHuntCollection -Uri (New-NSPHuntFilterUri $base $filter $top) -ApiVersion beta)) { $appSignIns.Add($s) }
        } catch {
            if (Test-NSPHuntPremiumError $_.Exception.Message) { $premiumBlocked = $true; break }
            Add-NSPHuntFinding -Hunt $Hunt -Severity Warning -Check 'Sign-in query' -Object $appId -Detail $_.Exception.Message
        }
        Start-Sleep -Milliseconds 300
    }
    Save-NSPHuntEvidence -Hunt $Hunt -Data $appSignIns.ToArray() -Name 'signIns_IocApps_ServicePrincipal'

    $summary = @{}
    foreach ($s in $appSignIns) {
        $ip = [string](Get-NSPHuntValue $s 'ipAddress')
        $hit = Test-NSPHuntIocIp -Hunt $Hunt -Ip $ip
        $errorCode = Get-NSPHuntValue $s 'status', 'errorCode'
        $ok = ($errorCode -eq 0)
        $result = if ($ok) { 'success' } else { "fail:$errorCode" }
        $resource = Get-NSPHuntValue $s 'resourceDisplayName'
        if ($hit -eq 'Exact' -or $hit -eq 'Prefix') {
            $severity = if ($ok) { 'Critical' } else { 'High' }
            Add-NSPHuntFinding -Hunt $Hunt -Severity $severity -Check 'IOC app sign-in from IOC IP' -Object "$($s.appDisplayName) ($($s.appId))" -Detail ('IP {0} ({1} match) -> {2}; {3}' -f $ip, $hit, $resource, $(if ($ok) { 'SUCCESS' } else { "failed $errorCode" })) -Time (Format-NSPHuntUtc $s.createdDateTime) -Evidence $s
            continue
        }
        # The rest is aggregated so the report is not flooded.
        $key = '{0}|{1}|{2}|{3}' -f $s.appId, $ip, $resource, $result
        $created = ConvertTo-NSPHuntUtc $s.createdDateTime
        if (-not $summary.ContainsKey($key)) {
            $summary[$key] = [pscustomobject]@{ App = $s.appDisplayName; AppId = $s.appId; Ip = $ip; Resource = $resource; Result = $result; Hits = 0; First = $created; Last = $created; Context = ($hit -eq 'Context') }
        }
        $row = $summary[$key]
        $row.Hits++
        if ($created -lt $row.First) { $row.First = $created }
        if ($created -gt $row.Last) { $row.Last = $created }
    }
    foreach ($row in $summary.Values) {
        $severity = 'Info'
        $note = ''
        if ($row.Result -eq 'success') { $severity = 'Medium'; $note = 'Successful IOC app sign-in in window; confirm it matches normal vendor traffic.' }
        if ($row.Result -eq 'fail:7000112') { $note = 'App disabled - blocked (expected after disable).' }
        if ($row.Result -eq 'fail:7000229') { $note = 'Service principal missing in tenant (probe; matches the pre-compromise recon pattern).' }
        if ($row.Context) { $note = ($note + ' ' + (Get-NSPHuntContextNote -Hunt $Hunt -Ip $row.Ip)).Trim() }
        Add-NSPHuntFinding -Hunt $Hunt -Severity $severity -Check 'IOC app sign-ins (summary)' -Object "$($row.App) ($($row.AppId))" -Detail ('{0}x from {1} -> {2}; {3}; {4} to {5}. {6}' -f $row.Hits, $row.Ip, $row.Resource, $row.Result, (Format-NSPHuntUtc $row.First), (Format-NSPHuntUtc $row.Last), $note) -Time (Format-NSPHuntUtc $row.First)
    }

    # Any sign-in, every event type, from the exact IOC IPs
    $ipSignIns = New-Object System.Collections.Generic.List[object]
    if (-not $premiumBlocked) {
        foreach ($ip in $ioc.IPs) {
            foreach ($eventType in 'interactiveUser', 'nonInteractiveUser', 'servicePrincipal', 'managedIdentity') {
                try {
                    $filter = "createdDateTime ge $($Hunt.SinceIso) and ipAddress eq '$ip' and signInEventTypes/any(t: t eq '$eventType')"
                    foreach ($s in (Get-NSPHuntCollection -Uri (New-NSPHuntFilterUri $base $filter $top) -ApiVersion beta)) { $ipSignIns.Add($s) }
                } catch {
                    if (Test-NSPHuntPremiumError $_.Exception.Message) { $premiumBlocked = $true; break }
                    Add-NSPHuntFinding -Hunt $Hunt -Severity Warning -Check 'Sign-in query' -Object "$ip/$eventType" -Detail $_.Exception.Message
                }
                Start-Sleep -Milliseconds 300
            }
            if ($premiumBlocked) { break }
        }
    }
    $seen = @{}
    $unique = @(foreach ($s in $ipSignIns) {
            $id = [string](Get-NSPHuntValue $s 'id')
            if (-not $id) { $s; continue }
            if (-not $seen.ContainsKey($id)) { $seen[$id] = $true; $s }
        })
    Save-NSPHuntEvidence -Hunt $Hunt -Data $unique -Name 'signIns_IocIPs_AllTypes'
    foreach ($s in $unique) {
        $errorCode = Get-NSPHuntValue $s 'status', 'errorCode'
        $who = Get-NSPHuntValue $s 'userPrincipalName'
        if (-not $who) { $who = Get-NSPHuntValue $s 'servicePrincipalName' }
        $severity = if ($errorCode -eq 0) { 'Critical' } else { 'High' }
        $outcome = if ($errorCode -eq 0) { 'SUCCESS' } else { "failed $errorCode $(Get-NSPHuntValue $s 'status', 'failureReason')" }
        Add-NSPHuntFinding -Hunt $Hunt -Severity $severity -Check 'Sign-in from IOC IP' -Object "$who / $($s.appDisplayName)" -Detail ('IP {0}, type {1}, {2}, UA {3}' -f $s.ipAddress, (@(Get-NSPHuntValue $s 'signInEventTypes') -join ','), $outcome, (Get-NSPHuntValue $s 'userAgent')) -Time (Format-NSPHuntUtc $s.createdDateTime) -Evidence $s
    }

    # Has a credential added in the window been used?
    $credentialSignIns = New-Object System.Collections.Generic.List[object]
    if (-not $premiumBlocked) {
        foreach ($group in ($AddedKeys | Group-Object AppId)) {
            if (-not $group.Name) { continue }
            try {
                $filter = "createdDateTime ge $($Hunt.SinceIso) and appId eq '$($group.Name)' and signInEventTypes/any(t: t eq 'servicePrincipal')"
                $signIns = Get-NSPHuntCollection -Uri (New-NSPHuntFilterUri $base $filter $top) -ApiVersion beta -MaxPages 20
            } catch {
                if (Test-NSPHuntPremiumError $_.Exception.Message) { $premiumBlocked = $true; break }
                Add-NSPHuntFinding -Hunt $Hunt -Severity Warning -Check 'Sign-in query' -Object $group.Name -Detail $_.Exception.Message
                continue
            }
            $keyIds = @($group.Group | ForEach-Object { [string]$_.KeyId })
            foreach ($s in $signIns) {
                $keyId = [string](Get-NSPHuntValue $s 'servicePrincipalCredentialKeyId')
                if (-not $keyId -or $keyIds -notcontains $keyId) { continue }
                $credentialSignIns.Add($s)
                $hit = Test-NSPHuntIocIp -Hunt $Hunt -Ip ([string]$s.ipAddress)
                $severity = if ($hit -eq 'Exact' -or $hit -eq 'Prefix') { 'Critical' } else { 'Medium' }
                Add-NSPHuntFinding -Hunt $Hunt -Severity $severity -Check 'New credential USED' -Object "$($s.appDisplayName) ($($s.appId))" -Detail ('keyId {0} used from {1} -> {2}; error {3}' -f $keyId, $s.ipAddress, (Get-NSPHuntValue $s 'resourceDisplayName'), (Get-NSPHuntValue $s 'status', 'errorCode')) -Time (Format-NSPHuntUtc $s.createdDateTime) -Evidence $s
            }
            Start-Sleep -Milliseconds 300
        }
    }
    Save-NSPHuntEvidence -Hunt $Hunt -Data $credentialSignIns.ToArray() -Name 'signIns_NewCredentialUse'

    if ($premiumBlocked) {
        Add-NSPHuntFinding -Hunt $Hunt -Severity Warning -Check 'Sign-in logs' -Object '-' -Detail 'Sign-in logs not readable through Graph (no Entra ID P1). Export Service principal sign-ins from the Entra portal NOW; these tenants keep 7 days.'
    }
}

function Find-NSPHuntNewUser {
    param([Parameter(Mandatory)][hashtable]$Hunt)
    try {
        $users = Get-NSPHuntCollection -Uri (New-NSPHuntFilterUri 'users' "createdDateTime ge $($Hunt.SinceIso)" '$select=id,userPrincipalName,displayName,createdDateTime,accountEnabled,userType')
        foreach ($u in $users) {
            Add-NSPHuntFinding -Hunt $Hunt -Severity Info -Check 'User created in window' -Object $u.userPrincipalName -Detail "Type $($u.userType), enabled $($u.accountEnabled)" -Time (Format-NSPHuntUtc $u.createdDateTime)
        }
    } catch {
        Add-NSPHuntFinding -Hunt $Hunt -Severity Warning -Check 'New users query' -Object '-' -Detail $_.Exception.Message
    }
}
