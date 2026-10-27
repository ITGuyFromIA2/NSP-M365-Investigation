# CLAUDE.md

## What this is

`NSP.M365.Investigation`: incident-response hunts across Microsoft 365 / Entra ID tenants.
`Invoke-NSPM365IocHunt` runs generic checks driven by an indicator set (`IocSets\*.psd1`, loaded by
`Get-NSPIocSet`); the first set is SkyKick (October 2026). Graph goes through NSP.M365.Graph
(`Connect-NSPGraph`, `Connect-NSPGraphAppOnly`, `Invoke-NSPGraphRequest`), loaded on first use by
`Private\Import-NSPToolkitModule.ps1` - a generated copy of NSP-Toolkit's canonical loader (don't
edit it here).

`Invoke-NSPM365AuditTriage` and the `Get-NSPM365*` audit functions work from Purview audit CSV
exports: parsing is NSP.LogParse's `ConvertFrom-NSPM365AuditCsv` / `Expand-NSPM365AuditRecord`
(loaded on first use, `Import-NSPLogParse`); this module adds the analysis. Inbox rule flags live
in one place (`Get-NSPInboxRuleFlag`, Private\AuditHelpers.ps1), shared by the audit and live
(Exchange Online) rule functions.

## Hard rules

- Windows PowerShell 5.1 is the floor; imports on a bare host (no RequiredModules).
- Read-only except `Remove-NSPM365InboxRule` (removes or disables inbox rules, clears mailbox
  forwarding; returns each rule's settings first) and `-DisableIocApps`, which disables (never
  deletes) only the set's own app IDs. Both confirm each change (ConfirmImpact High).
  Reports and evidence are written even under `-WhatIf`.
- Never report on a tenant other than the one asked for: the connected tenant is checked against
  the resolved tenant ID before any check runs.
- Indicator sets hold public vendor indicators only. Nothing client-specific in tracked files:
  hunt output and tenant CSVs are git-ignored. New IOC IPv4s go in `.nsp-repotools.psd1` Allow.
- Tests never sign in or reach the network: Graph is NSP.M365.Graph's `Fake` transport; mock
  `Connect-NSPHuntTenant`, `Invoke-RestMethod`, `Start-Sleep`; ip-api.com is `Invoke-WebRequest`
  (mock it). Audit and message trace fixtures are written to TestDrive (`*.csv` is git-ignored),
  with documentation-range addresses only.
- On 5.1 a single `[pscustomobject]` has no `.Count`: wrap results in `@()`.
- Don't use `@($list)` on a `New-Object Collections.Generic.List[...]` - pwsh 7.6 throws; use `.ToArray()`.
- One function per file in `Public\`. `FunctionsToExport` matches `Public\`. Exported functions
  need `.SYNOPSIS` and `.EXAMPLE`. CRLF, no BOM, ASCII only.

## Testing

Pester 5+. Run `.\tools\Test-Repo.ps1` (PSScriptAnalyzer, then Pester under 5.1 and pwsh).

## Publishing

`tools\Publish-ToGallery.ps1` runs `Publish-NSPModule` from NSP.RepoTools. Dry run first with
`-WhatIf`. At release, change the CHANGELOG heading from `## <version> (unreleased)` to
`## <version>`. Needs a GitHub remote first (the manifest's ProjectUri points at it).
