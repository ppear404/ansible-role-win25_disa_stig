# V-278207: validate the approved notice, tolerating whitespace differences only.
function Test-StigLegalNotice {
    param([AllowNull()][object]$ActualText, [string]$RegistryKind)
    $approved = @'
You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.
'@
    $expected = [regex]::Replace($approved, '\s+', ' ').Trim()
    $actual = if ($ActualText -is [string]) {
        [regex]::Replace($ActualText, '\s+', ' ').Trim()
    } else { '' }
    $valid = $RegistryKind -ceq 'String' -and $ActualText -is [string] -and $actual -ceq $expected
    $hash = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = [BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($actual))).Replace('-', '')
    } finally { $hash.Dispose() }
    return @{
        Valid = [bool]$valid
        Results = "V-278207 independent validation: RegistryKind=$RegistryKind; ApprovedNoticeMatches=$valid; " +
            "NormalizedTextSHA256=$digest. Only whitespace is normalized; words, case and punctuation must match " +
            'the Windows Server 2025 V1R4 approved long-form USG notice.'
    }
}
try {
    $key = Get-Item -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop
    $kind = $key.GetValueKind('LegalNoticeText').ToString()
    $text = $key.GetValue('LegalNoticeText', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    return Test-StigLegalNotice -ActualText $text -RegistryKind $kind
} catch {
    return @{ Valid = $false; Results = 'V-278207 independent validation failed: ' + $_.Exception.Message }
}
