@{
    # Indicator set for Invoke-NSPM365IocHunt. Public vendor indicators only: nothing here names an
    # NSP client. When a vendor publishes more, add them here (and to CHANGELOG.md), or pass
    # -AdditionalIocIPs / -AdditionalIocAppIds for a one-off run.
    Name    = 'SkyKick'
    Title   = 'ConnectWise Cloud Backup (SkyKick) / ConnectWise Cloud Management breach, October 2026'
    Updated = '2026-10-19'

    # Start of the hunt window: password spray began 10/13, app abuse 10/15.
    Since   = '2026-10-10T00:00:00Z'

    # Service principals by app ID. Only these are disabled by -DisableIocApps; apps matched by
    # owner tenant or display name are reported for review.
    Apps = @{
        '506e08f9-6e9a-4da4-942b-a099a03644ae' = 'ConnectWise Cloud Backup (SkyKick) - credential abused'
        '24205314-2b89-4e07-a2a4-579e898a5640' = 'CW Cloud Management - MS Teams - abused (self-assigned GA)'
        'b78f6a77-d4e5-46fb-87e5-d1648bd02519' = 'CW Cloud Management - Exchange Online - abused'
        'b2b55f5b-7758-4719-8d8f-88ae172e6bdb' = 'CW Cloud Management - SharePoint Online - abused'
        '2399d300-6fca-4e6a-a686-399fefe75b83' = 'CW Cloud Management - review'
        '0de14c77-b9b0-4137-9360-34878a929827' = 'CW Cloud Management - MS Graph - review'
        '412dcf96-176d-4b3a-a1b0-4981ad66971e' = 'CW Cloud Management - Partner Center - review'
    }

    # Tenants that own the vendor's apps (appOwnerOrganizationId), and display-name prefixes.
    OwnerTenantIds = @('3f9cd7a0-127a-4ed4-bf06-2f830d5616b7')
    NamePrefixes   = @('SkyKick', 'ConnectWise')

    IPs = @(
        '144.172.64.128'        # original (spray 10/13-14, app auth 10/15)
        '144.172.64.99'         # ConnectWise trust advisory, 2026-10-19
        '144.172.64.60'         # ConnectWise trust advisory, 2026-10-19
        '144.172.94.243'        # Guardz
        '2602:fa59:13:5f::1'    # Guardz
        '2602:fa59:2:3559::1'   # Guardz
    )

    # Matched client-side on sign-ins already returned (hosting space seen in this campaign).
    IpPrefixes = @('144.172.64.', '144.172.94.', '2602:fa59:')

    # Context only - legitimate vendor traffic uses these too. Never raises severity on its own.
    ContextIpPrefixes = @{
        'fde4:8dba:2600:37ce:6d26:200:a76:' = 'Source is the Microsoft-internal ULA seen on the abused Teams app connection (context only, not proof).'
    }

    # Low fidelity alone; raise severity only alongside another signal.
    UserAgents = @('curl/7.88.1', 'Python-urllib/3.12', 'python-requests/2.31', 'python-httpx/0.28.1')

    Sources = @(
        'Huntress: ConnectWise (SkyKick) Vendor Credentials Abused in M365 Attacks'
        'Guardz: ConnectWise SkyKick Breach in Microsoft 365'
        'SpecterOps: How to Check Your Microsoft 365 Tenant'
        'ConnectWise trust advisory: Cloud Backup technical investigation and remediation (IPs updated 2026-10-19)'
        'r/msp: ConnectWise SkyKick vendor megathread; Additional IPs related to SkyKick breach (2026-10-19)'
    )

    Notes = @(
        'Run your own (MSP) tenant first: the Exchange Online app granting itself Exchange Admin was seen mostly in MSP tenants.'
        'Tenants without Entra ID P1 keep sign-in logs 7 days and cannot read them through Graph: export Service principal sign-ins from the Entra portal by hand.'
        'Disabling ConnectWise Cloud Backup pauses backups for that tenant.'
    )
}
