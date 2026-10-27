# Changelog

All notable changes to NSP.M365.Investigation are documented here. Versions follow
[SemVer](https://semver.org/). `0.x` until it has real use outside NSP.

## 0.1.1 (unreleased)

Mailbox-compromise triage from Unified Audit Log and message trace exports: the patterns the
per-client NSP-Investigation scripts repeated, as functions. NSP.LogParse (audit CSV parsing) is
loaded on first use, like NSP.M365.Graph.

- `Invoke-NSPM365AuditTriage`: one or more Purview audit CSVs to Findings.csv (severity-sorted,
  the hunt's columns) plus Timeline, IPs, Summary, SignIns, AccessedMail and InboxRules CSVs.
  Trusted addresses by IP, CIDR, prefix or ASN; findings grouped per user and address.
- `Resolve-NSPIpInfo`: ip-api.com batch lookup (country, ISP, ASN, hosting/proxy/mobile), rate
  limit aware, cached per session. Replaces the scripts' `IPAPI_BatchResolve` copies.
- `Get-NSPM365AuditSummary`: count, first/last, users and IPs per operation, IP, user or workload.
- `Get-NSPM365AccessedMessage`: MailItemsAccessed as one row per message (Bind) or folder (Sync),
  with InternetMessageId.
- `Get-NSPM365InboxRuleAudit` / `Get-NSPM365InboxRuleReport`: inbox rule and forwarding changes
  from the audit log, and the live rules (hidden included) and forwarding from Exchange Online,
  with shared flags (Forwards, Deletes, MarksRead, MovesTo:<folder>, OddName, TargetsKeywords).
  Read-only.
- `Remove-NSPM365InboxRule`: removes (or `-Disable`s) rules and clears mailbox forwarding from
  report rows or rule identities, confirming each; returns each rule's settings from before the change.
- `Export-NSPM365Message`: saves messages by InternetMessageId (e.g. from AccessedMail) as .eml with
  a SHA-256 manifest, through NSP.M365.Graph (app-only Mail.Read or delegated Mail.Read.Shared).
  Replaces the third-party Export-M365-Messages.ps1.
- `ConvertFrom-NSPM365MessageTrace`: historical-search (MTSummary, UTF-16) and current message
  trace exports as one row per recipient with sender and recipient domains.
- Client IPs are normalized across workloads (ClientIP / ClientIPAddress / ActorIpAddress /
  UserIp) with Exchange's port suffix removed.

## 0.1.0

First release: the SkyKick IOC hunt script (`Invoke-SkyKickIocHunt.ps1`) as a module.

- `Invoke-NSPM365IocHunt`: one tenant, a list, or a CSV; delegated or certificate app-only sign-in
  through NSP.M365.Graph; Findings.csv sorted by severity and raw evidence JSON per tenant.
- `Get-NSPIocSet` and `IocSets\SkyKick.psd1`: 7 ConnectWise/SkyKick app IDs, the ConnectWise owner
  tenant, 144.172.64.128/.99/.60, 144.172.94.243 and two 2602:fa59: addresses, hosting-range
  prefixes, IOC user agents. Indicators as of 2026-10-19.
- Changes from the script:
  - A domain is resolved to its tenant ID, so the wrong-tenant guard covers domains too (the
    script only checked GUIDs).
  - `-DisableIocApps` touches only the set's app IDs. Other apps matched by ConnectWise's owner
    tenant or name are reported as "Related app ENABLED" for review rather than disabled.
  - `-WhatIf` still writes Findings.csv and the evidence (the script's -WhatIf skipped them).
  - Graph requests go through NSP.M365.Graph's transport, so the tests run the hunt against a
    synthetic tenant with no sign-in.
