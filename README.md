# NSP.M365.Investigation

Incident response for Microsoft 365 / Entra ID. `Invoke-NSPM365IocHunt` checks one tenant or a list
for an incident's indicators and writes a severity-sorted `Findings.csv`, plus raw evidence JSON per
tenant so you still have it after the logs expire. It is read-only unless you pass `-DisableIocApps`.

Indicators live in indicator sets (`IocSets\*.psd1`, listed by `Get-NSPIocSet`). The first one is
**SkyKick**: the October 2026 ConnectWise Cloud Backup (SkyKick) / Cloud Management breach.

```powershell
Install-Module NSP.M365.Investigation        # NSP.M365.Graph is installed on first use

Invoke-NSPM365IocHunt -IocSet SkyKick -UseCurrentConnection                    # your own tenant first
Invoke-NSPM365IocHunt -IocSet SkyKick -TenantCsv .\tenants.csv                 # columns: TenantId, Name
Invoke-NSPM365IocHunt -IocSet SkyKick -TenantCsv .\tenants.csv -ClientId <id> -CertificateThumbprint <thumb>
Invoke-NSPM365IocHunt -IocSet SkyKick -TenantId <guid or domain> -DisableIocApps -WhatIf
Invoke-NSPM365IocHunt -IocSet SkyKick -TenantId <guid> -AdditionalIocIPs 203.0.113.7   # newly published IPs
```

## What it checks, per tenant

| Check | Flags |
| --- | --- |
| The incident's service principals (by app ID, owner tenant, display name) | Still enabled (High); directory roles held; high-risk application permissions |
| Every other service principal holding a privileged role | Review list (Low) |
| Directory audits (ApplicationManagement, RoleManagement) since the window | An app giving a role to **itself** (Critical); IOC apps acting or granted roles; credentials added by an app; IOC user agents |
| Secrets and certificates added since the window, on **every** app | Medium; High when an application added it (the actor planted secrets on unrelated apps) |
| Sign-ins (beta) | IOC app sign-ins; any sign-in from the IOC IPs (Critical on success); a newly added credential signing in, and from where |
| Users created since the window | Info |

Every tenant is checked against the tenant you asked for (a domain is resolved to its tenant ID
first). A mismatch is reported as a warning and nothing else is reported for that tenant.

## Before you run it

- **Run your own tenant first.** Guardz saw the Exchange Online app grant itself Exchange Admin
  mostly in MSPs' own tenants.
- **Time limit.** Tenants without Entra ID P1 keep sign-in logs for 7 days and can't read them
  through Graph. The run flags them; export "Service principal sign-ins" from the Entra portal by
  hand.
- **GDAP.** A delegated sign-in to a client tenant needs the "Microsoft Graph Command Line Tools"
  app consented there. On AADSTS650051 / AADSTS65001, use `-ClientId` / `-CertificateThumbprint`
  with your partner app (application permissions: Application.Read.All, Directory.Read.All,
  AuditLog.Read.All, RoleManagement.Read.Directory, plus Application.ReadWrite.All to disable).
- **`-DisableIocApps` disables, never deletes**, and only the apps whose app ID is in the set. Apps
  matched only by owner tenant or name (other ConnectWise integrations) are reported for review.
  Disabling ConnectWise Cloud Backup pauses backups for that client. `-WhatIf` still writes the
  report.
- **Not covered.** Mailbox and file access live in the Unified Audit Log, which this doesn't
  search, and Microsoft doesn't log Graph directory reads. A clean result doesn't prove nothing
  was read.

## New indicators or a new incident

Pass `-AdditionalIocIPs` / `-AdditionalIocAppIds` for a one-off run. To keep them, add them to
the set's `.psd1` and release. For a new incident, copy `IocSets\SkyKick.psd1` and pass its path
as `-IocSet` until it ships.

## Requirements

Windows PowerShell 5.1 or PowerShell 7. NSP.M365.Graph (installed on first use) and
Microsoft.Graph.Authentication.
