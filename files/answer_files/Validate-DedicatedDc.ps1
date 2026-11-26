try {
    $ErrorActionPreference = 'Stop'
    $roles = @(Get-WindowsFeature | Where-Object { $_.Installed -and $_.FeatureType -eq 'Role' } | Select-Object -ExpandProperty Name)
    $extraRoles = @($roles | Where-Object { $_ -notin @('AD-Domain-Services', 'DNS', 'FileAndStorage-Services') })
    $software = foreach ($view in 'Registry64', 'Registry32') {
        $hive = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', $view)
        try {
            $uninstall = $hive.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
            if (-not $uninstall) { throw "Missing uninstall inventory in $view" }
            foreach ($name in $uninstall.GetSubKeyNames()) {
                $key = $uninstall.OpenSubKey($name)
                try {
                    $display = $key.GetValue('DisplayName')
                    if ($display) { [string]$display }
                } finally { $key.Dispose() }
            }
        } finally { $hive.Dispose() }
    }
    $required = @()
    if (Get-CimInstance Win32_PnPEntity | Where-Object {
        $_.Status -eq 'OK' -and $_.PNPDeviceID -like 'PCI\VEN_1AF4*'
    }) { $required += 'Virtio-win-guest-tools' }
    $extraApps = @($software | Where-Object { $_ -notin $required } | Sort-Object -Unique)
    $valid = 'AD-Domain-Services' -in $roles -and $extraRoles.Count -eq 0 -and $extraApps.Count -eq 0
    return @{Valid=$valid; Results="Installed roles: $($roles -join ', '); installed applications: $($software -join ', '); additional applications requiring review: $($extraApps -join ', ')"}
} catch {
    return @{Valid=$false; Results="Dedicated domain controller review incomplete: $($_.Exception.Message)"}
}
