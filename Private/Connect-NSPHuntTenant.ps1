function Connect-NSPHuntTenant {
    # Signs in to one tenant through NSP.M365.Graph. -ClientId with -CertificateThumbprint is
    # app-only (a partner multi-tenant app consented in the tenant); otherwise delegated, reusing
    # the current session when it already has the scopes and tenant. With no -TenantId, an
    # existing app-only session is used as it is.
    param(
        [string]$TenantId,
        [Parameter(Mandatory)][string[]]$Scopes,
        [string]$ClientId,
        [string]$CertificateThumbprint,
        [switch]$UseDeviceCode
    )

    if ($ClientId -and $CertificateThumbprint) {
        Connect-NSPGraphAppOnly -ClientId $ClientId -TenantId $TenantId -CertificateThumbprint $CertificateThumbprint | Out-Null
        return
    }
    if (-not $TenantId -and (Get-Command Get-MgContext -ErrorAction SilentlyContinue)) {
        $context = Get-MgContext
        if ($context -and [string]$context.AuthType -eq 'AppOnly') { return }
    }
    $connect = @{ Scopes = $Scopes; Connect = $true }
    if ($TenantId) { $connect.TenantId = $TenantId }
    if ($UseDeviceCode) { $connect.UseDeviceCode = $true }
    Connect-NSPGraph @connect | Out-Null
}
