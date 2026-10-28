@{
    ClientSweep = @{
        ExcludePath = @()
        # Published threat-actor IPs in IocSets\ and the tests: public indicators, not client addresses.
        Allow = @(
            '144.172.64.128'
            '144.172.64.99'
            '144.172.64.60'
            '144.172.94.243'
            # Address formats shown in comments and help: placeholders, not mailboxes.
            'a@b.com'
            'c@d.com'
            'a@x.com'
            'b@y.com'
            'abc@namprd13.prod.outlook.com'
            # Test address just outside the 198.51.100.0/24 documentation range, on purpose.
            '198.51.101.1'
        )
        AllowPattern = @()
    }
}
