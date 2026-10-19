function Resolve-NSPHuntTenantId {
    # A tenant ID for a tenant ID or domain, from the tenant's public OpenID configuration. Every
    # hunt then checks the connected tenant against this ID before reporting anything.
    param([Parameter(Mandatory)][string]$Tenant)

    $Tenant = $Tenant.Trim()
    if ($Tenant -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { return $Tenant.ToLowerInvariant() }
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    try {
        $config = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$([uri]::EscapeDataString($Tenant))/v2.0/.well-known/openid-configuration" -ErrorAction Stop
    } catch {
        throw "Could not resolve '$Tenant' to a tenant ID: $($_.Exception.Message)"
    }
    if ([string]$config.issuer -match '/([0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})/') { return $Matches[1].ToLowerInvariant() }
    throw "Could not resolve '$Tenant' to a tenant ID: no tenant ID in its OpenID configuration."
}
