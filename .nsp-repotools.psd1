@{
    ClientSweep = @{
        ExcludePath = @()
        # Published threat-actor IPs in IocSets\ and the tests: public indicators, not client addresses.
        Allow = @(
            '144.172.64.128'
            '144.172.64.99'
            '144.172.64.60'
            '144.172.94.243'
        )
        AllowPattern = @()
    }
}
