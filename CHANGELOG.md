# Changelog

All notable changes to NSP.M365.Investigation are documented here. Versions follow
[SemVer](https://semver.org/). `0.x` until it has real use outside NSP.

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
