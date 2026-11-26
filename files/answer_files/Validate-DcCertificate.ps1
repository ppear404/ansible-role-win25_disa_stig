try {
    $ErrorActionPreference = 'Stop'
    $hostName = [string]([ADSI]'LDAP://localhost/RootDSE').dnsHostName.Value
    if (-not $hostName) { throw 'DC DNS name unavailable' }
    $now = Get-Date
    $certificates = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object {
        $_.HasPrivateKey -and $_.NotBefore -le $now -and $_.NotAfter -gt $now -and
        $hostName -in @($_.DnsNameList | ForEach-Object { $_.Unicode })
    })
    return @{Valid=($certificates.Count -gt 0); Results="Currently valid personal certificates with the DC DNS name and a private key: $($certificates.Count)"}
} catch {
    return @{Valid=$false; Results="DC certificate verification incomplete: $($_.Exception.Message)"}
}
