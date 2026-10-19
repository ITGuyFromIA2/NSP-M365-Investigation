# Get-NSPIocSet: the shipped sets load, extra indicators merge, and a set can come from a path.

BeforeAll {
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'NSP.M365.Investigation.psd1') -Force -ErrorAction Stop
}

Describe 'Get-NSPIocSet' {
    It 'lists the shipped sets' {
        @(Get-NSPIocSet).Name | Should -Contain 'SkyKick'
    }

    It 'loads the SkyKick set with every published app ID and IP' {
        $set = Get-NSPIocSet -Name SkyKick
        $set.Apps.Count | Should -Be 7
        $set.Apps.ContainsKey('506e08f9-6e9a-4da4-942b-a099a03644ae') | Should -BeTrue
        $set.IPs | Should -Contain '144.172.64.99'
        $set.IPs | Should -Contain '2602:fa59:2:3559::1'
        $set.OwnerTenantIds | Should -Contain '3f9cd7a0-127a-4ed4-bf06-2f830d5616b7'
        $set.Since | Should -Be ([datetime]::SpecifyKind([datetime]'2026-10-10', [DateTimeKind]::Utc))
        $set.Since.Kind | Should -Be ([DateTimeKind]::Utc)
        'ConnectWise Cloud Backup' | Should -Match $set.NameRegex
    }

    It 'matches app IDs whatever their case' {
        (Get-NSPIocSet -Name SkyKick).Apps.ContainsKey('506E08F9-6E9A-4DA4-942B-A099A03644AE') | Should -BeTrue
    }

    It 'merges indicators published after the set, without duplicates' {
        $set = Get-NSPIocSet -Name SkyKick -AdditionalIPs '203.0.113.7', '144.172.64.128' -AdditionalAppIds 'AAAAAAAA-0000-4000-8000-000000000009'
        @($set.IPs | Where-Object { $_ -eq '144.172.64.128' }).Count | Should -Be 1
        $set.IPs | Should -Contain '203.0.113.7'
        $set.Apps['aaaaaaaa-0000-4000-8000-000000000009'] | Should -Be 'User-supplied IOC app'
    }

    It 'names the available sets when asked for one that does not exist' {
        { Get-NSPIocSet -Name NoSuchIncident } | Should -Throw '*Available: *SkyKick*'
    }

    It 'loads a set from a path' {
        $path = Join-Path $TestDrive 'Next.psd1'
        Set-Content -LiteralPath $path -Value "@{ Name = 'Next'; Title = 'Next incident'; Since = '2026-11-01T00:00:00Z'; Apps = @{}; IPs = @('203.0.113.9') }"
        $set = Get-NSPIocSet -Name $path
        $set.Name | Should -Be 'Next'
        $set.NameRegex | Should -BeNullOrEmpty
        $set.IPs | Should -Be @('203.0.113.9')
    }

    It 'refuses a set missing required keys' {
        $path = Join-Path $TestDrive 'Broken.psd1'
        Set-Content -LiteralPath $path -Value "@{ Name = 'Broken'; Title = 'x' }"
        { Get-NSPIocSet -Name $path } | Should -Throw '*missing: Since, Apps, IPs*'
    }
}
