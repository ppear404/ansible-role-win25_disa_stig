$connection = $null
try {
    $ErrorActionPreference = 'Stop'
    Add-Type -AssemblyName System.DirectoryServices.Protocols
    $root = [ADSI]'LDAP://localhost/RootDSE'
    $base = [string]$root.defaultNamingContext.Value
    if (-not $base) { throw 'Domain naming context unavailable' }
    $connection = [System.DirectoryServices.Protocols.LdapConnection]::new('localhost')
    $connection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Anonymous
    $connection.SessionOptions.ProtocolVersion = 3
    $connection.Bind()
    $request = [System.DirectoryServices.Protocols.SearchRequest]::new(
        $base, '(objectClass=*)', [System.DirectoryServices.Protocols.SearchScope]::Base, @('distinguishedName'))
    try {
        $null = $connection.SendRequest($request)
        return @{Valid=$false; Results='Anonymous search of the domain naming context succeeded.'}
    } catch [System.DirectoryServices.Protocols.DirectoryOperationException] {
        $response = $_.Exception.Response
        $denied = $response.ResultCode -eq 'InsufficientAccessRights' -or
            ($response.ResultCode -eq 'OperationsError' -and $response.ErrorMessage -match '000004DC')
        return @{Valid=[bool]$denied; Results="Anonymous domain search returned $($response.ResultCode): $($response.ErrorMessage)"}
    }
} catch {
    return @{Valid=$false; Results="Anonymous LDAP verification incomplete: $($_.Exception.Message)"}
} finally {
    if ($connection) { $connection.Dispose() }
}
