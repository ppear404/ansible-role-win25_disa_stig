# Windows Server 2025 V1R4: read-only evidence collection and testable decisions.
# The answer-file builder embeds this source and the per-host policy register.
function Test-ManualControlEvidence {
    param([string]$Control, [hashtable]$Evidence, [hashtable]$Policy)
    $valid = $false
    switch ($Control) {
        'V-277982' { $valid = $Evidence.AutoUpdateEnabled -and $Evidence.RecentPatch }
        'V-277983' { $valid = $Evidence.HardwareInventoried -and $Policy.hardware_control_procedure }
        'V-277985' { $valid = $Evidence.AdminsApproved -and $Policy.separate_admin_accounts }
        'V-277987' { $valid = $Evidence.NonInternetFacingDeclaration -or $Evidence.AdminInternetBlocked }
        'V-277989' { $valid = $Policy.service_password_minimum -ge 15 -and $Policy.service_password_provisioning_check }
        'V-277990' { $valid = $Evidence.ServicePasswordsCurrent -and $Policy.rotate_on_departure }
        'V-277991' { $valid = $Policy.shared_accounts_used -eq $false -and -not $Evidence.ContradictoryAccount }
        'V-277992' { $valid = $Evidence.AllowlistEnforced }
        'V-277996' { $valid = $Evidence.HostIDPSActive }
        'V-278006' { $valid = $Evidence.FIMBaselineAndWeeklyComparison }
        'V-278009' { $valid = $Evidence.DatastoreEncryptionDeclaration }
        'V-278010' { $valid = $Evidence.DocumentedProtectedTransferPaths }
        'V-278011' { $valid = $Evidence.FeaturesMatchRegister }
        'V-278013' { $valid = $Policy.temporary_accounts_used -eq $false -and -not $Evidence.ContradictoryAccount }
        'V-278014' { $valid = $Policy.emergency_accounts_used -eq $false -and -not $Evidence.ContradictoryAccount }
        'V-278029' { $valid = $Evidence.ApprovedTimeSource }
        'V-278041' { $valid = $Evidence.UniversalForwarderInstalled }
        'V-278042' { $valid = $Evidence.UniversalForwarderInstalled }
        'V-278106' { $valid = $Evidence.SecurityEventsForwarded }
        'V-278177' { $valid = $Evidence.AdminsApproved }
        'V-278240' { $valid = $Evidence.AllProfilesPreserveZone }
        default { throw "Unsupported manual control $Control" }
    }
    return @{ Valid = [bool]$valid; Results = "$Control custom review: " + ($Evidence | ConvertTo-Json -Compress -Depth 8) }
}

function Get-ApprovedAdminEvidence {
    param([hashtable]$Policy)
    $members = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)
    $sids = @($members | ForEach-Object { $_.SID.Value })
    return @{AdminsApproved=($sids.Count -gt 0 -and @($sids | Where-Object { $_ -notin $Policy.approved_admin_sids }).Count -eq 0);
        AdminSIDs=$sids}
}

function Get-UniversalForwarderEvidence {
    $service = Get-CimInstance Win32_Service -Filter "Name='SplunkForwarder'" -ErrorAction Stop
    $paths = @('C:\Program Files\SplunkUniversalForwarder')
    if ($service -and $service.PathName -match '^"?(.+?\\bin\\splunkd\.exe)"?(?:\s|$)') {
        $paths += Split-Path (Split-Path $Matches[1] -Parent) -Parent
    }
    $root = $null
    foreach ($path in ($paths | Select-Object -Unique)) {
        $exe = Join-Path $path 'bin\splunk.exe'
        if (Test-Path -LiteralPath $exe) {
            $version = (Get-Item -LiteralPath $exe).VersionInfo
            # Service identity and installation location distinguish Universal Forwarder from Enterprise.
            if ($service -or $path -match 'SplunkUniversalForwarder$') { $root = $path; break }
        }
    }
    $data = @{UniversalForwarderInstalled=($null -ne $root); ServiceState='Absent'; SecurityEventsForwarded=$false}
    if ($service) { $data.ServiceState = $service.State }
    if (-not $root) { return $data }
    $data.InstallationPath = $root
    $data.Version = $version.ProductVersion
    # Never execute splunk.exe or accept a license; inspect merged config files without exposing secrets.
    # Presence alone satisfies the owner's explicit V-278041/042 criterion. V-278106 requires more.
    $inputs = @{}; $outputs = @{}
    foreach ($kind in @('inputs', 'outputs')) {
        $merged = @{}
        $files = @()
        $files += Join-Path $root "etc\system\default\$kind.conf"
        $files += @(Get-ChildItem (Join-Path $root 'etc\apps') -Directory -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending | ForEach-Object { Join-Path $_.FullName "default\$kind.conf" })
        $files += @(Get-ChildItem (Join-Path $root 'etc\apps') -Directory -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending | ForEach-Object { Join-Path $_.FullName "local\$kind.conf" })
        $files += Join-Path $root "etc\system\local\$kind.conf"
        foreach ($file in $files) {
            if (-not (Test-Path -LiteralPath $file)) { continue }
            $section = 'default'
            foreach ($line in (Get-Content -LiteralPath $file -ErrorAction Stop)) {
                if ($line -match '^\s*\[([^]]+)\]\s*$') { $section = $Matches[1].Trim(); continue }
                if ($line -match '^\s*(disabled|server|defaultGroup|current_only)\s*=\s*(.*?)\s*$') {
                    $name=$Matches[1]; $value=$Matches[2]
                    if (-not $merged.ContainsKey($section)) { $merged[$section]=@{} }
                    $merged[$section][$name]=$value
                }
            }
        }
        if ($kind -eq 'inputs') { $inputs=$merged } else { $outputs=$merged }
    }
    $security = $inputs['WinEventLog://Security']
    $securityEnabled = $security -and $security['disabled'] -match '^(0|false)$' -and
        $security['current_only'] -notmatch '^(1|true)$'
    $targets = @()
    $groupNames = @()
    if ($outputs['tcpout']) { $groupNames = @($outputs['tcpout']['defaultGroup'] -split ',' | ForEach-Object { $_.Trim() }) }
    foreach ($name in $groupNames) {
        $group=$outputs["tcpout:$name"]
        if ($group -and $group['disabled'] -notmatch '^(1|true)$' -and
            $outputs['tcpout']['disabled'] -notmatch '^(1|true)$') {
            $targets += @($group['server'] -split ',' | Where-Object { $_.Trim() })
        }
    }
    $localNames = @('localhost','127.0.0.1','::1',$env:COMPUTERNAME)
    $localNames += @(Get-NetIPAddress -ErrorAction Stop | Select-Object -ExpandProperty IPAddress)
    $remote = @($targets | Where-Object {
        $hostPart = ($_ -replace ':\d+$','').Trim(' ', '[', ']')
        $hostPart -notin $localNames
    })
    $data.SecurityInputEnabled = [bool]$securityEnabled
    $data.RemoteDestinationCount = $remote.Count
    $data.SecurityEventsForwarded = ($data.ServiceState -eq 'Running' -and $securityEnabled -and $remote.Count -gt 0)
    return $data
}

function Test-ConfiguredTimeSource {
    param([string]$Type, [string]$Peers, [string[]]$ApprovedSources,
        [bool]$DomainJoined, [int]$DomainRole, [bool]$ServiceRunning)
    if (-not $ServiceRunning) { return $false }
    if ($DomainJoined -and $DomainRole -lt 4 -and $Type -eq 'NT5DS') { return $true }
    if ($Type -ne 'NTP') { return $false }
    $names=@($Peers -split '\s+' | Where-Object { $_ } | ForEach-Object { ($_ -split ',')[0] })
    return ($names.Count -gt 0 -and @($names | Where-Object { $_ -notin $ApprovedSources }).Count -eq 0)
}

function Get-ManualControlEvidence {
    param([string]$Control, [hashtable]$Policy)
    switch ($Control) {
        'V-277982' {
            # Modern Server builds may expose empty legacy COM AU settings/results.
            # Read effective policy and actual installed-update dates instead.
            $au=Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue
            if (-not $au -or $null -eq $au.AUOptions) {
                $au=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -ErrorAction SilentlyContinue
            }
            $patches=@(Get-HotFix -ErrorAction Stop | Where-Object InstalledOn | Sort-Object InstalledOn -Descending)
            $last=$null; $recent=$false
            if ($patches.Count -gt 0) {
                $last=$patches[0].InstalledOn
                $days=((Get-Date)-$last).TotalDays
                $recent=$days -ge 0 -and $days -le 30
            }
            $service=Get-CimInstance Win32_Service -Filter "Name='wuauserv'" -ErrorAction Stop
            return @{AutoUpdateEnabled=($au.NoAutoUpdate -ne 1 -and $au.AUOptions -in @(2,3,4) -and
                    $service -and $service.StartMode -ne 'Disabled'); RecentPatch=[bool]$recent;
                LastInstalledUpdate=$last; AUOptions=$au.AUOptions;
                RecentHotfixes=@($patches | Select-Object -First 5 HotFixID,InstalledOn);
                ReviewBasis='PATCH-01 30-day installation procedure, enabled update configuration and installed-update date evidence'}
        }
        'V-277983' {
            $hardware = @(Get-CimInstance Win32_ComputerSystemProduct -ErrorAction Stop | Select-Object Vendor,Name,UUID)
            return @{HardwareInventoried=($hardware.Count -gt 0); Hardware=$hardware;
                ReviewBasis='HW-01 security-plan procedure and captured VM identity; not a hypervisor configuration attestation'}
        }
        { $_ -in @('V-277985','V-278177') } { return Get-ApprovedAdminEvidence -Policy $Policy }
        'V-277987' {
            if ($Policy.ContainsKey('internet_facing') -and $Policy.internet_facing -eq $false) {
                return @{NonInternetFacingDeclaration=$true; ReviewBasis='System-owner declaration: non-Internet-facing server; AC-02 operating policy. No AppLocker/egress enforcement attestation.'}
            }
            [xml]$xml = Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop
            $denies = @($xml.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -eq 'Exe' -and $_.EnforcementMode -eq 'Enabled' } |
                ForEach-Object { $_.FilePathRule } | Where-Object { $_.Action -eq 'Deny' -and $_.UserOrGroupSid -eq 'S-1-5-32-544' })
            $patterns = @($denies | ForEach-Object { $_.Conditions.FilePathCondition.Path })
            $names = @('msedge.exe','chrome.exe','firefox.exe','iexplore.exe','outlook.exe','thunderbird.exe')
            $missing = @($names | Where-Object {
                $name=$_; @($patterns | Where-Object { $_ -eq '*' -or $_ -ieq "*\$name" }).Count -eq 0
            })
            return @{AdminInternetBlocked=($missing.Count -eq 0 -and (Get-Service AppIDSvc).Status -eq 'Running');
                MissingBrowserMailDenyRules=$missing; Basis='Conservative AppLocker administrator browser/mail deny-path check; alternative solutions require reviewed evidence'}
        }
        'V-277989' {
            return @{ReviewBasis='SA-01 documented provisioning and rotation length-validation procedure; existing password values are not inspected'}
        }
        'V-277990' {
            $principals = @($Policy.manually_managed_accounts)
            $principals += @(Get-CimInstance Win32_Service | Select-Object -ExpandProperty StartName)
            $principals += @(Get-ScheduledTask | ForEach-Object { if ($_.Principal.LogonType -eq 'Password') { $_.Principal.UserId } })
            $principals = @($principals | Where-Object {
                $_ -and $_ -notmatch '^(LocalSystem|LocalService|NetworkService|NT AUTHORITY\\|NT SERVICE\\|SYSTEM$)' -and $_ -notmatch '\$$'
            } | Select-Object -Unique)
            $ages = @(); $current = $true
            foreach ($principal in $principals) {
                $name = ($principal -split '\\')[-1]
                $account = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
                if (-not $account -or -not $account.PasswordLastSet) { $current=$false; $ages += @{Name=$name;AgeDays='unverified'}; continue }
                $days = ((Get-Date) - $account.PasswordLastSet).TotalDays
                $ages += @{Name=$name;AgeDays=[Math]::Floor($days)}
                if ($days -lt 0 -or $days -gt 365) { $current=$false }
            }
            return @{ServicePasswordsCurrent=$current; Accounts=$ages; PersonnelChanges='SA-02 requires immediate rotation on administrator departure'}
        }
        { $_ -in @('V-277991','V-278013','V-278014') } {
            $pattern = switch ($Control) { 'V-277991' {'\bshared\b'} 'V-278013' {'\btemp(orary)?\b'} default {'\bemergency\b|\bbreak.?glass\b'} }
            $conflicts = @(Get-LocalUser | Where-Object { $_.Enabled -and ($_.Name -match $pattern -or $_.Description -match $pattern) } |
                Select-Object -ExpandProperty Name)
            return @{ContradictoryAccount=($conflicts.Count -gt 0); ContradictoryNames=$conflicts;
                ReviewBasis='System-owner declaration; name/description checks only detect obvious contradictions, not account purpose'}
        }
        'V-277992' {
            [xml]$xml = Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop
            $enabled = @($xml.AppLockerPolicy.RuleCollection | Where-Object { $_.EnforcementMode -eq 'Enabled' -and $_.ChildNodes.Count -gt 0 } |
                Select-Object -ExpandProperty Type)
            return @{AllowlistEnforced=('Exe' -in $enabled -and 'Appx' -in $enabled -and (Get-Service AppIDSvc).Status -eq 'Running');
                EnforcedCollections=$enabled; Basis='Native AppLocker evidence; alternative allowlisting requires site validation'}
        }
        'V-277996' {
            $sense = Get-Service Sense -ErrorAction SilentlyContinue
            $onboard = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' -ErrorAction SilentlyContinue
            $mp = Get-MpComputerStatus -ErrorAction Stop
            return @{HostIDPSActive=($sense.Status -eq 'Running' -and $onboard.OnboardingState -eq 1 -and $mp.RealTimeProtectionEnabled);
                SenseRunning=($sense.Status -eq 'Running'); MDEOnboarded=($onboard.OnboardingState -eq 1);
                PreventionEnabled=[bool]$mp.RealTimeProtectionEnabled; Basis='MDE sensor plus Defender prevention; antivirus alone does not pass'}
        }
        'V-278006' { return @{FIMBaselineAndWeeklyComparison=$false; Reason='No approved file-integrity baseline, full system-file coverage and weekly comparison evidence registered. See FIM-01.'} }
        'V-278009' {
            return @{DatastoreEncryptionDeclaration=($Policy.datastore_encryption_used -eq $true);
                ReviewBasis='System-owner confirmed datastore encryption; DAR-01 documents the benchmark infrastructure-encryption exception. No hypervisor inspection claimed.'}
        }
        'V-278010' { return @{DocumentedProtectedTransferPaths=$false; Reason='No data-owner transfer-path register or approved end-to-end protection evidence supplied. SSH administration alone is insufficient. See DIT-01.'} }
        'V-278011' {
            $features = @(Get-WindowsFeature -ErrorAction Stop | Where-Object Installed | Select-Object -ExpandProperty Name)
            $unexpected = @($features | Where-Object { $_ -notin $Policy.required_features })
            return @{FeaturesMatchRegister=($features.Count -gt 0 -and $unexpected.Count -eq 0); Installed=$features; Unregistered=$unexpected}
        }
        'V-278029' {
            $computer=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
            $key=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' -ErrorAction Stop
            $policyKey=Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\W32Time\Parameters' -ErrorAction SilentlyContinue
            $type=$key.Type; $peers=$key.NtpServer
            if ($policyKey.Type) { $type=$policyKey.Type }
            if ($policyKey.NtpServer) { $peers=$policyKey.NtpServer }
            $running=(Get-Service W32Time).Status -eq 'Running'
            $approved=Test-ConfiguredTimeSource -Type $type -Peers $peers -ApprovedSources @($Policy.approved_ntp_sources) `
                -DomainJoined $computer.PartOfDomain -DomainRole $computer.DomainRole -ServiceRunning $running
            return @{ApprovedTimeSource=[bool]$approved; Type=$type; Peers=$peers;
                ApprovedStandaloneSources=@($Policy.approved_ntp_sources); ServiceRunning=$running}
        }
        { $_ -in @('V-278041','V-278042','V-278106') } { return Get-UniversalForwarderEvidence }
        'V-278240' { return Get-ZonePreservationEvidence }
        default { throw "Unsupported control $Control" }
    }
}

function Get-ZonePreservationEvidence {
    $profiles = @(Get-CimInstance Win32_UserProfile -ErrorAction Stop | Where-Object { -not $_.Special })
    $paths = @($profiles | ForEach-Object { @{SID=$_.SID; File=(Join-Path $_.LocalPath 'NTUSER.DAT')} })
    $paths += @{SID='DefaultProfile';File=(Join-Path $env:SystemDrive 'Users\Default\NTUSER.DAT')}
    $checked=@(); $valid=$true
    foreach ($profile in $paths) {
        $mount=$profile.SID; $temporary=$false; $copy=$null
        try {
            if (-not (Test-Path "Registry::HKEY_USERS\$mount")) {
                if (-not (Test-Path -LiteralPath $profile.File)) { throw "Existing profile hive missing: $($profile.SID)" }
                $mount='WIN25_REVIEW_'+[guid]::NewGuid().ToString('N')
                $copy=Join-Path $env:TEMP "$mount.dat"
                Copy-Item -LiteralPath $profile.File -Destination $copy -ErrorAction Stop
                & reg.exe load "HKU\$mount" $copy *> $null
                if ($LASTEXITCODE -ne 0) { throw "Cannot read copied profile hive: $($profile.SID)" }
                $temporary=$true
            }
            $key=[Microsoft.Win32.Registry]::Users.OpenSubKey("$mount\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments")
            $value=$null; $kind=$null
            if ($key) {
                try {
                    if ('SaveZoneInformation' -in $key.GetValueNames()) {
                        $kind=$key.GetValueKind('SaveZoneInformation').ToString()
                        $value=$key.GetValue('SaveZoneInformation')
                    }
                } finally { $key.Dispose() }
            }
            if ($null -ne $value -and ($kind -ne 'DWord' -or $value -ne 2)) { $valid=$false }
            $checked+=@{SID=$profile.SID;Value=$value;Kind=$kind}
        } catch { $valid=$false; $checked+=@{SID=$profile.SID;Error=$_.Exception.Message} }
        finally {
            if ($temporary) {
                [GC]::Collect(); [GC]::WaitForPendingFinalizers()
                & reg.exe unload "HKU\$mount" *> $null
                if ($LASTEXITCODE -ne 0) { $valid=$false; $checked+=@{SID=$profile.SID;Error='Temporary hive unload failed'} }
            }
            if ($copy) { Remove-Item -LiteralPath $copy -Force -ErrorAction SilentlyContinue }
        }
    }
    return @{AllProfilesPreserveZone=$valid; Profiles=$checked; Basis='All non-system profiles and the default profile; missing value is the compliant Windows default'}
}

function Invoke-ScopedManualReview {
    param([string]$Control, [hashtable]$Policy)
    try {
        $ErrorActionPreference='Stop'
        if ($env:COMPUTERNAME -ine $Policy.computer_name) { throw 'No per-host policy register for this computer.' }
        $sid=(Get-LocalUser | Where-Object { $_.SID.Value -match '-500$' }).SID.Value -replace '-500$', ''
        if ($sid -ne $Policy.machine_sid) { throw 'Per-host machine SID mismatch.' }
        $evidence=Get-ManualControlEvidence -Control $Control -Policy $Policy
        return Test-ManualControlEvidence -Control $Control -Evidence $evidence -Policy $Policy
    } catch {
        return @{Valid=$false;Results='Custom review failed closed: '+$_.Exception.Message}
    }
}
