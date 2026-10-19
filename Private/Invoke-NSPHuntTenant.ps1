function Invoke-NSPHuntTenant {
    # Runs every check against the connected tenant. Refuses to report when the connected tenant
    # is not the one asked for. Returns the tenant ID, label and the IOC service principals found.
    param(
        [Parameter(Mandatory)][hashtable]$Hunt,
        [string]$ExpectedTenantId,
        [switch]$SkipSignIns
    )

    $org = @((Invoke-NSPGraphRequest -Uri 'organization?$select=id,displayName')['value'])[0]
    if (-not $org) { throw 'Could not read the connected tenant (organization).' }
    if ($ExpectedTenantId -and ([string]$org.id).ToLowerInvariant() -ne $ExpectedTenantId.ToLowerInvariant()) {
        throw "Connected to tenant $($org.id) ($($org.displayName)) but expected $ExpectedTenantId. Skipped so the wrong tenant is not reported."
    }
    $Hunt.TenantLabel = "$($org.displayName) [$($org.id)]"
    $Hunt.AppRoleCache = @{}
    Write-Host ''
    Write-Host "=== $($Hunt.TenantLabel) ===" -ForegroundColor Cyan

    $iocSps = @(Find-NSPHuntIocServicePrincipal -Hunt $Hunt)
    $iocSpIds = @($iocSps | ForEach-Object { [string]$_.id })
    Find-NSPHuntPrivilegedServicePrincipal -Hunt $Hunt -IocSpIds $iocSpIds
    # Audits before credentials, so a credential an application added is raised to High.
    $appCredentialTargets = Find-NSPHuntAuditEvent -Hunt $Hunt -IocSpIds $iocSpIds
    $addedKeys = Find-NSPHuntNewCredential -Hunt $Hunt -AppCredentialTargets $appCredentialTargets
    if (-not $SkipSignIns) { Find-NSPHuntSignIn -Hunt $Hunt -AddedKeys $addedKeys }
    Find-NSPHuntNewUser -Hunt $Hunt

    [pscustomobject]@{
        TenantId             = [string]$org.id
        TenantLabel          = $Hunt.TenantLabel
        IocServicePrincipals = $iocSps
    }
}
