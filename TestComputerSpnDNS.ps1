function Test-ComputerSpnDns {
    param (
        [string]$SearchBase = "",
		[bool]$checkComputer = $true
    )
 
    if (-not (Get-Module ActiveDirectory)) {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
 
    $computers = if ($SearchBase) {
        Get-ADComputer -Filter * -Properties ServicePrincipalName -SearchBase $SearchBase
    } else {
        Get-ADComputer -Filter * -Properties ServicePrincipalName
    }
 
    if (-not $computers) {
        return @()
    }
 
    $results = @()
 
    foreach ($c in $computers) {
        $computerName = $c.Name.ToLower()
 
        if (-not $c.ServicePrincipalName) {
            continue
        }
 
        $unresolvedHosts = @()
        $unresolvedSpns  = @()
        $checkedHosts    = @{}
 
        # collect candidate SPNs whose host part is different from the computerName
        $candidateSpns = @()
        foreach ($spn in $c.ServicePrincipalName) {
            if ($spn -match '^[^/]+/([^:/]+)') {
                $spnHost = $matches[1].ToLower()
                $hostname = $spnHost.Split('.')[0]
 
                # Skip GUID-style hostnames
                if ($hostname -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
                    continue
                }
 
                if ($hostname -ieq $computerName) {
                    continue
                }
 
                $candidateSpns += ,@($spn,$spnHost)
            }
        }
 
        # Skip DNS check entirely if no interesting SPNs
        if ($candidateSpns.Count -eq 0) {
            continue
        }
 
        # Now ensure the computer itself resolves
        if($checkComputer)
		{
		try {
            Resolve-DnsName -Name $computerName -QuickTimeout -ErrorAction Stop | Out-Null
        } catch {
            continue
        }
        }
        # process each candidate SPN
        foreach ($pair in $candidateSpns) {
            $spn = $pair[0]
            $spnHost = $pair[1]
 
            if ($checkedHosts.ContainsKey($spnHost)) {
                continue
            }
            $checkedHosts[$spnHost] = $true
 
            Write-Host "Checking host: $spnHost"
 
            try {
                Resolve-DnsName -Name $spnHost -QuickTimeout -ErrorAction Stop | Out-Null
            } catch {
                $unresolvedHosts += $spnHost
                $unresolvedSpns  += $spn
            }
        }
 
        if ($unresolvedHosts.Count -gt 0) {
            $results += [PSCustomObject]@{
                Computer        = $computerName
                UnresolvedSpns  = $unresolvedSpns
                UnresolvedHosts = $unresolvedHosts
            }
        }
    }
 
    return $results
}
