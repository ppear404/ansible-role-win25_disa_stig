# The generated answer supplies the relative DN and required inheritance scope.
try {
    $ErrorActionPreference = 'Stop'
    $domain = [string]([ADSI]'LDAP://localhost/RootDSE').defaultNamingContext.Value
    if (-not $domain) { throw 'Domain naming context unavailable' }
    $dn = if ($relativeDn) { "$relativeDn,$domain" } else { $domain }
    $entry = [ADSI]("LDAP://localhost/" + $dn)
    $entry.psbase.Options.SecurityMasks = [DirectoryServices.SecurityMasks]::Sacl
    $entry.psbase.RefreshCache(@('nTSecurityDescriptor'))
    $acl = $entry.psbase.ObjectSecurity
    $rules = @($acl.GetAuditRules($true, $false, [Security.Principal.SecurityIdentifier]))
    $full = [int][DirectoryServices.ActiveDirectoryRights]::GenericAll
    $rights = 0
    foreach ($ace in $rules) {
        if ($ace.IdentityReference.Value -ne 'S-1-1-0' -or
            -not ($ace.AuditFlags -band [Security.AccessControl.AuditFlags]::Failure) -or
            $ace.ObjectType -ne [Guid]::Empty -or $ace.InheritedObjectType -ne [Guid]::Empty) { continue }
        if ($ace.InheritanceType -eq 'All' -or
            (-not $allDescendants -and $ace.InheritanceType -in @('None', 'SelfAndChildren'))) {
            $rights = $rights -bor [int]$ace.ActiveDirectoryRights
        }
    }
    if (($rights -band $full) -eq $full) {
        return @{Valid=$true; Results="Everyone failure auditing covers full control on $dn. Review the required success entries."}
    }
    # Split, object-specific or complementary inheritance entries can need manual interpretation.
    $failureEntries = @($rules | Where-Object {
        $_.IdentityReference.Value -eq 'S-1-1-0' -and ($_.AuditFlags -band [Security.AccessControl.AuditFlags]::Failure)
    })
    return @{Valid=($failureEntries.Count -gt 0); Results="Explicit Everyone failure audit entries on $dn : $($failureEntries.Count). Review scope and success entries when present."}
} catch {
    return @{Valid=$true; Results="Manual audit review required: $($_.Exception.Message)"}
}
