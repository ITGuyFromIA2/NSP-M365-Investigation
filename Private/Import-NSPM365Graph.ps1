function Import-NSPM365Graph {
    # Loads NSP.M365.Graph on first use, so this module still imports on a bare host.
    Import-NSPToolkitModule -Name 'NSP.M365.Graph' -MinimumVersion '0.1.0'
}
