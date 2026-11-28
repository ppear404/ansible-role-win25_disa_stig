# Windows Server 2025 V1R4 control map

This map lists remediation coverage for all 291 benchmark controls.
`automated` identifies controls with a role task. `manual` identifies controls
that require remediation outside the role when applicable. Use Evaluate-STIG
and the responsible reviewers to assess the effective configuration and any
administrative requirements.

| Control | Category | Implementation | Requirement |
| --- | --- | --- | --- |
| V-277982 | II | manual | Windows Server 2025 must install security-relevant software updates within 30 days unless the time period is directed by an authoritative source (e.g., IAVM, CTOs, DTMs, STIGs). |
| V-277983 | II | manual | Windows Server 2025 must prohibit the use or connection of unauthorized hardware components. |
| V-277985 | II | manual | Windows Server 2025 users with administrative privileges must have separate accounts for administrative duties and normal operational tasks. |
| V-277986 | II | manual | Windows Server 2025 passwords for the built-in Administrator account must be changed at least every 180 days. |
| V-277987 | I | manual | Windows Server 2025 administrative accounts must not be used with applications that access the internet, such as web browsers, or with potential internet sources, such as email. |
| V-277988 | II | manual | Windows Server 2025 members of the Backup Operators group must have separate accounts for backup duties and normal operational tasks. |
| V-277989 | II | manual | Windows Server 2025 manually managed application account passwords must be at least 15 characters in length. |
| V-277990 | II | manual | Windows Server 2025 manually managed application account passwords must be changed at least annually or when a system administrator with knowledge of the password leaves the organization. |
| V-277991 | II | manual | Windows Server 2025 shared user accounts must not be permitted. |
| V-277992 | II | manual | Windows Server 2025 must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs. |
| V-277993 | II | manual | Windows Server 2025 systems must have a Trusted Platform Module (TPM) enabled and ready for use. |
| [V-277995](../tasks/V-277995.yml) | II | automated | Windows Server 2025 must use an antivirus program. |
| V-277996 | II | manual | Windows Server 2025 must have a host-based intrusion detection and prevention service (IDPS) installed. |
| V-277997 | I | manual | Windows Server 2025 local volumes must use a format that supports New Technology File System (NTFS) attributes. |
| V-277998 | II | manual | Windows Server 2025 permissions for the system drive root directory (usually C:\) must conform to minimum requirements. |
| V-277999 | II | manual | Windows Server 2025 permissions for program file directories must conform to minimum requirements. |
| V-278000 | II | manual | Windows Server 2025 permissions for the Windows installation directory must conform to minimum requirements. |
| V-278001 | II | manual | Windows Server 2025 default permissions for the HKEY_LOCAL_MACHINE registry hive must be maintained. |
| V-278002 | III | manual | Windows Server 2025 nonadministrative accounts or groups must only have print permissions on printer shares. |
| V-278003 | II | manual | Outdated or unused accounts on Windows Server 2025 must be removed or disabled. |
| [V-278004](../tasks/V-278004.yml) | II | automated | Windows Server 2025 accounts must require passwords. |
| [V-278005](../tasks/V-278005.yml) | II | automated | Windows Server 2025 passwords must be configured to expire. |
| V-278006 | II | manual | Windows Server 2025 system files must be monitored for unauthorized changes. |
| V-278007 | II | manual | Windows Server 2025 nonsystem-created file shares must limit access to groups that require it. |
| V-278008 | II | manual | Windows Server 2025 must have software certificate installation files removed. |
| V-278009 | I | manual | Windows Server 2025 systems requiring data-at-rest protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest. |
| V-278010 | II | manual | Windows Server 2025 must implement protection methods such as TLS, encrypted VPNs, or IPsec if the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. |
| V-278011 | II | manual | Windows Server 2025 must have the roles and features required by the system documented. |
| [V-278012](../tasks/V-278012.yml) | II | automated | Windows Server 2025 must have a host-based firewall installed and enabled. |
| V-278013 | II | manual | Windows Server 2025 must automatically remove or disable temporary user accounts after 72 hours. |
| V-278014 | II | manual | Windows Server 2025 must automatically remove or disable emergency accounts after the crisis is resolved or within 72 hours. |
| [V-278015](../tasks/V-278015.yml) | II | automated | Windows Server 2025 must not have the Fax Server role installed. |
| [V-278016](../tasks/V-278016.yml) | II | automated | Windows Server 2025 must not have the Microsoft FTP service installed unless required by the organization. |
| V-278017 | II | manual | Windows Server 2025 must not have Wi-Fi enabled unless required by the organization. |
| [V-278018](../tasks/V-278018.yml) | II | automated | Windows Server 2025 must not have Bluetooth enabled unless required by the organization. |
| [V-278019](../tasks/V-278019.yml) | II | automated | Windows Server 2025 must not have the Peer Name Resolution Protocol installed. |
| [V-278020](../tasks/V-278020.yml) | II | automated | Windows Server 2025 must not have Simple TCP/IP Services installed. |
| [V-278021](../tasks/V-278021.yml) | II | automated | Windows Server 2025 must not have the Telnet Client installed. |
| [V-278022](../tasks/V-278022.yml) | II | automated | Windows Server 2025 must not have the TFTP Client installed. |
| [V-278023](../tasks/V-278023.yml) | II | automated | Windows Server 2025 must not have the Server Message Block (SMB) v1 protocol installed. |
| [V-278024](../tasks/V-278024.yml) | II | automated | Windows Server 2025 must have the Server Message Block (SMB) v1 protocol disabled on the SMB server. |
| [V-278025](../tasks/V-278025.yml) | II | automated | Windows Server 2025 must have the Server Message Block (SMB) v1 protocol disabled on the SMB client. |
| [V-278026](../tasks/V-278026.yml) | II | automated | Windows Server 2025 must not have Windows PowerShell 2.0 installed. |
| V-278027 | II | manual | Windows Server 2025 FTP servers must be configured to prevent anonymous logons. |
| V-278028 | II | manual | Windows Server 2025 FTP servers must be configured to prevent access to the system drive. |
| [V-278029](../tasks/V-278029.yml) | III | automated | The Windows Server 2025 time service must synchronize with an appropriate DoW time source. |
| V-278030 | II | manual | Windows Server 2025 must have orphaned security identifiers (SIDs) removed from user rights. |
| V-278031 | II | manual | Windows Server 2025 systems must have Unified Extensible Firmware Interface (UEFI) firmware and be configured to run in UEFI mode, not Legacy BIOS. |
| V-278032 | II | manual | Windows Server 2025 must have Secure Boot enabled. |
| [V-278033](../tasks/V-278033.yml) | II | automated | Windows Server 2025 account lockout duration must be configured to 15 minutes or greater. |
| [V-278034](../tasks/V-278034.yml) | II | automated | Windows Server 2025 must have the number of allowed bad logon attempts configured to three or less. |
| [V-278035](../tasks/V-278035.yml) | II | automated | Windows Server 2025 must have the period of time before the bad logon counter is reset configured to 15 minutes or greater. |
| [V-278036](../tasks/V-278036.yml) | II | automated | Windows Server 2025 password history must be configured to 24 passwords remembered. |
| [V-278037](../tasks/V-278037.yml) | II | automated | Windows Server 2025 maximum password age must be configured to 180 days or less. |
| [V-278038](../tasks/V-278038.yml) | II | automated | Windows Server 2025 minimum password age must be configured to at least one day. |
| [V-278039](../tasks/V-278039.yml) | II | automated | Windows Server 2025 must have the built-in Windows password complexity policy enabled. |
| [V-278040](../tasks/V-278040.yml) | I | automated | Windows Server 2025 reversible password encryption must be disabled. |
| V-278041 | II | manual | Windows Server 2025 audit records must be backed up to a different system or media than the system being audited. |
| V-278042 | II | manual | Windows Server 2025 must, at a minimum, off-load audit records of interconnected systems in real time and off-load stand-alone or nondomain-joined systems weekly. |
| V-278043 | II | manual | Windows Server 2025 permissions for the Application event log must prevent access by nonprivileged accounts. |
| V-278044 | II | manual | Windows Server 2025 permissions for the Security event log must prevent access by nonprivileged accounts. |
| V-278045 | II | manual | Windows Server 2025 permissions for the System event log must prevent access by nonprivileged accounts. |
| V-278046 | II | manual | Windows Server 2025 Event Viewer must be protected from unauthorized modification and deletion. |
| [V-278047](../tasks/V-278047.yml) | II | automated | Windows Server 2025 must be configured to audit Account Logon - Credential Validation successes. |
| [V-278048](../tasks/V-278048.yml) | II | automated | Windows Server 2025 must be configured to audit Account Logon - Credential Validation failures. |
| [V-278049](../tasks/V-278049.yml) | II | automated | Windows Server 2025 must be configured to audit Account Management - Other Account Management Events successes. |
| [V-278050](../tasks/V-278050.yml) | II | automated | Windows Server 2025 must be configured to audit Account Management - Security Group Management successes. |
| [V-278051](../tasks/V-278051.yml) | II | automated | Windows Server 2025 must be configured to audit Account Management - User Account Management successes. |
| [V-278052](../tasks/V-278052.yml) | II | automated | Windows Server 2025 must be configured to audit Account Management - User Account Management failures. |
| [V-278053](../tasks/V-278053.yml) | II | automated | Windows Server 2025 must be configured to audit Detailed Tracking - Plug and Play Events successes. |
| [V-278054](../tasks/V-278054.yml) | II | automated | Windows Server 2025 must be configured to audit Detailed Tracking - Process Creation successes. |
| [V-278055](../tasks/V-278055.yml) | II | automated | Windows Server 2025 must be configured to audit Logon/Logoff - Account Lockout successes. |
| [V-278056](../tasks/V-278056.yml) | II | automated | Windows Server 2025 must be configured to audit Logon/Logoff - Account Lockout failures. |
| [V-278057](../tasks/V-278057.yml) | II | automated | Windows Server 2025 must be configured to audit Logon/Logoff - Group Membership successes. |
| [V-278058](../tasks/V-278058.yml) | II | automated | Windows Server 2025 must be configured to audit logoff successes. |
| [V-278059](../tasks/V-278059.yml) | II | automated | Windows Server 2025 must be configured to audit logon successes. |
| [V-278060](../tasks/V-278060.yml) | II | automated | Windows Server 2025 must be configured to audit logon failures. |
| [V-278061](../tasks/V-278061.yml) | II | automated | Windows Server 2025 must be configured to audit Logon/Logoff - Special Logon successes. |
| [V-278062](../tasks/V-278062.yml) | II | automated | Windows Server 2025 must be configured to audit Object Access - Other Object Access Events successes. |
| [V-278063](../tasks/V-278063.yml) | II | automated | Windows Server 2025 must be configured to audit Object Access - Other Object Access Events failures. |
| [V-278064](../tasks/V-278064.yml) | II | automated | Windows Server 2025 must be configured to audit Object Access - Removable Storage successes. |
| [V-278065](../tasks/V-278065.yml) | II | automated | Windows Server 2025 must be configured to audit Object Access - Removable Storage failures. |
| [V-278066](../tasks/V-278066.yml) | II | automated | Windows Server 2025 must be configured to audit Policy Change - Audit Policy Change successes. |
| [V-278067](../tasks/V-278067.yml) | II | automated | Windows Server 2025 must be configured to audit Policy Change - Audit Policy Change failures. |
| [V-278068](../tasks/V-278068.yml) | II | automated | Windows Server 2025 must be configured to audit Policy Change - Authentication Policy Change successes. |
| [V-278069](../tasks/V-278069.yml) | II | automated | Windows Server 2025 must be configured to audit Policy Change - Authorization Policy Change successes. |
| [V-278070](../tasks/V-278070.yml) | II | automated | Windows Server 2025 must be configured to audit Privilege Use - Sensitive Privilege Use successes. |
| [V-278071](../tasks/V-278071.yml) | II | automated | Windows Server 2025 must be configured to audit Privilege Use - Sensitive Privilege Use failures. |
| [V-278072](../tasks/V-278072.yml) | II | automated | Windows Server 2025 must be configured to audit System - IPsec Driver successes. |
| [V-278073](../tasks/V-278073.yml) | II | automated | Windows Server 2025 must be configured to audit System - IPsec Driver failures. |
| [V-278074](../tasks/V-278074.yml) | II | automated | Windows Server 2025 must be configured to audit System - Other System Events successes. |
| [V-278075](../tasks/V-278075.yml) | II | automated | Windows Server 2025 must be configured to audit System - Other System Events failures. |
| [V-278076](../tasks/V-278076.yml) | II | automated | Windows Server 2025 must be configured to audit System - Security State Change successes. |
| [V-278077](../tasks/V-278077.yml) | II | automated | Windows Server 2025 must be configured to audit System - Security System Extension successes. |
| [V-278078](../tasks/V-278078.yml) | II | automated | Windows Server 2025 must be configured to audit System - System Integrity successes. |
| [V-278079](../tasks/V-278079.yml) | II | automated | Windows Server 2025 must be configured to audit System - System Integrity failures. |
| [V-278080](../tasks/V-278080.yml) | II | automated | Windows Server 2025 must prevent the display of slide shows on the lock screen. |
| [V-278082](../tasks/V-278082.yml) | III | automated | Windows Server 2025 Internet Protocol version 6 (IPv6) source routing must be configured to the highest protection level to prevent IP source routing. |
| [V-278083](../tasks/V-278083.yml) | III | automated | Windows Server 2025 source routing must be configured to the highest protection level to prevent Internet Protocol (IP) source routing. |
| [V-278084](../tasks/V-278084.yml) | III | automated | Windows Server 2025 must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF)-generated routes. |
| [V-278085](../tasks/V-278085.yml) | III | automated | Windows Server 2025 must be configured to ignore NetBIOS name release requests except from WINS servers. |
| [V-278086](../tasks/V-278086.yml) | II | automated | Windows Server 2025 insecure logons to an SMB server must be disabled. |
| [V-278087](../tasks/V-278087.yml) | II | automated | Windows Server 2025 hardened Universal Naming Convention (UNC) paths must be defined to require mutual authentication and integrity for at least the \\*\SYSVOL and \\*\NETLOGON shares. |
| [V-278088](../tasks/V-278088.yml) | II | automated | Windows Server 2025 command line data must be included in process creation events. |
| [V-278089](../tasks/V-278089.yml) | II | automated | Windows Server 2025 must be configured to enable Remote host allows delegation of nonexportable credentials. |
| [V-278090](../tasks/V-278090.yml) | II | automated | Windows Server 2025 virtualization-based security must be enabled with the platform security level configured to Secure Boot or Secure Boot with DMA Protection. |
| [V-278091](../tasks/V-278091.yml) | II | automated | Windows Server 2025 Early Launch Antimalware, Boot-Start Driver Initialization Policy must prevent boot drivers identified as bad. |
| [V-278092](../tasks/V-278092.yml) | II | automated | Windows Server 2025 group policy objects must be reprocessed even if they have not changed. |
| [V-278093](../tasks/V-278093.yml) | II | automated | Windows Server 2025 downloading print driver packages over HTTP must be turned off. |
| [V-278094](../tasks/V-278094.yml) | II | automated | Windows Server 2025 printing over HTTP must be turned off. |
| [V-278095](../tasks/V-278095.yml) | II | automated | Windows Server 2025 network selection user interface (UI) must not be displayed on the logon screen. |
| [V-278096](../tasks/V-278096.yml) | II | automated | Windows Server 2025 users must be prompted to authenticate when the system wakes from sleep (on battery). |
| [V-278097](../tasks/V-278097.yml) | II | automated | Windows Server 2025 users must be prompted to authenticate when the system wakes from sleep (plugged in). |
| [V-278098](../tasks/V-278098.yml) | III | automated | Windows Server 2025 Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft. |
| [V-278099](../tasks/V-278099.yml) | I | automated | Windows Server 2025 AutoPlay must be turned off for nonvolume devices. |
| [V-278100](../tasks/V-278100.yml) | I | automated | Windows Server 2025 default AutoRun behavior must be configured to prevent AutoRun commands. |
| [V-278101](../tasks/V-278101.yml) | I | automated | Windows Server 2025 AutoPlay must be disabled for all drives. |
| [V-278102](../tasks/V-278102.yml) | II | automated | Windows Server 2025 administrator accounts must not be enumerated during elevation. |
| [V-278103](../tasks/V-278103.yml) | II | automated | Windows Server 2025 Telemetry must be configured to limit diagnostic data sent to Microsoft. |
| [V-278104](../tasks/V-278104.yml) | III | automated | Windows Server 2025 Windows Update must not obtain updates from other PCs on the internet. |
| [V-278105](../tasks/V-278105.yml) | II | automated | Windows Server 2025 Application event log size must be configured to 32768 KB or greater. |
| [V-278106](../tasks/V-278106.yml) | II | automated | Windows Server 2025 Security event log size must be configured to a value that holds at least one week of audit records. |
| [V-278107](../tasks/V-278107.yml) | II | automated | Windows Server 2025 System event log size must be configured to 32768 KB or greater. |
| [V-278108](../tasks/V-278108.yml) | II | automated | Windows Server 2025 Microsoft Defender antivirus SmartScreen must be enabled. |
| [V-278109](../tasks/V-278109.yml) | II | automated | Windows Server 2025 Explorer Data Execution Prevention must be enabled. |
| [V-278110](../tasks/V-278110.yml) | III | automated | Windows Server 2025 Turning off File Explorer heap termination on corruption must be disabled. |
| [V-278111](../tasks/V-278111.yml) | II | automated | Windows Server 2025 File Explorer shell protocol must run in protected mode. |
| [V-278112](../tasks/V-278112.yml) | II | automated | Windows Server 2025 must not save passwords in the Remote Desktop Client. |
| [V-278113](../tasks/V-278113.yml) | II | automated | Windows Server 2025 Remote Desktop Services must prevent drive redirection. |
| [V-278114](../tasks/V-278114.yml) | II | automated | Windows Server 2025 Remote Desktop Services must always prompt a client for passwords upon connection. |
| [V-278115](../tasks/V-278115.yml) | II | automated | Windows Server 2025 Remote Desktop Services must require secure Remote Procedure Call (RPC) communications. |
| [V-278116](../tasks/V-278116.yml) | II | automated | Windows Server 2025 Remote Desktop Services must be configured with the client connection encryption set to High Level. |
| [V-278117](../tasks/V-278117.yml) | II | automated | Windows Server 2025 must prevent attachments from being downloaded from RSS feeds. |
| [V-278118](../tasks/V-278118.yml) | II | automated | Windows Server 2025 must disable Basic authentication for RSS feeds over HTTP. |
| [V-278119](../tasks/V-278119.yml) | II | automated | Windows Server 2025 must prevent Indexing of encrypted files. |
| [V-278120](../tasks/V-278120.yml) | II | automated | Windows Server 2025 must prevent users from changing installation options. |
| [V-278121](../tasks/V-278121.yml) | I | automated | Windows Server 2025 must disable the Windows Installer Always install with elevated privileges option. |
| [V-278122](../tasks/V-278122.yml) | II | automated | Windows Server 2025 users must be notified if a web-based program attempts to install software. |
| [V-278123](../tasks/V-278123.yml) | II | automated | Windows Server 2025 must disable automatically signing in the last interactive user after a system-initiated restart. |
| [V-278124](../tasks/V-278124.yml) | II | automated | Windows Server 2025 PowerShell script block logging must be enabled. |
| [V-278125](../tasks/V-278125.yml) | I | automated | Windows Server 2025 Windows Remote Management (WinRM) client must not use Basic authentication. |
| [V-278126](../tasks/V-278126.yml) | II | automated | Windows Server 2025 Windows Remote Management (WinRM) client must not allow unencrypted traffic. |
| [V-278127](../tasks/V-278127.yml) | II | automated | Windows Server 2025 Windows Remote Management (WinRM) client must not use Digest authentication. |
| [V-278128](../tasks/V-278128.yml) | I | automated | Windows Server 2025 Windows Remote Management (WinRM) service must not use Basic authentication. |
| [V-278129](../tasks/V-278129.yml) | II | automated | Windows Server 2025 Windows Remote Management (WinRM) service must not allow unencrypted traffic. |
| [V-278130](../tasks/V-278130.yml) | II | automated | Windows Server 2025 Windows Remote Management (WinRM) service must not store RunAs credentials. |
| [V-278131](../tasks/V-278131.yml) | II | automated | Windows Server 2025 must have PowerShell Transcription enabled. |
| V-278132 | I | manual | Windows Server 2025 must only allow administrators responsible for the domain controller to have Administrator rights on the system. |
| V-278133 | II | manual | Windows Server 2025 Kerberos user logon restrictions must be enforced. |
| V-278134 | II | manual | Windows Server 2025 Kerberos service ticket maximum lifetime must be limited to 600 minutes or less. |
| V-278135 | II | manual | Windows Server 2025 Kerberos user ticket lifetime must be limited to 10 hours or less. |
| V-278136 | II | manual | Windows Server 2025 Kerberos policy user ticket renewal maximum lifetime must be limited to seven days or less. |
| V-278137 | II | manual | Windows Server 2025 computer clock synchronization tolerance must be limited to five minutes or less. |
| V-278138 | I | manual | Windows Server 2025 permissions on the Active Directory data files must only allow system administrators (SAs) access. |
| V-278139 | I | manual | Windows Server 2025 Active Directory SYSVOL directory must have the proper access control permissions. |
| V-278140 | I | manual | Windows Server 2025 Active Directory (AD) Group Policy Objects (GPOs) must have proper access control permissions. |
| V-278141 | I | manual | Windows Server 2025 Active Directory Domain Controllers Organizational Unit (OU) object must have the proper access control permissions. |
| V-278142 | I | manual | Windows Server 2025 organization created Active Directory Organizational Unit (OU) objects must have proper access control permissions. |
| V-278143 | II | manual | Windows Server 2025 data files owned by users must be on a different logical partition from the directory server data files. |
| V-278144 | II | manual | Windows Server 2025 domain controllers must run on a machine dedicated to that function. |
| V-278145 | II | manual | Windows Server 2025 must use separate, NSA-approved (Type 1) cryptography to protect the directory data in transit for directory service implementations at a classified confidentiality level when replication data traverses a network cleared to a lower level than the data. |
| V-278146 | I | manual | Windows Server 2025 directory data (outside the root DSE) of a nonpublic directory must be configured to prevent anonymous access. |
| [V-278147](../tasks/V-278147.yml) | III | automated | Windows Server 2025 directory service must be configured to terminate LDAP-based network connections to the directory server after five minutes of inactivity. |
| V-278148 | II | manual | Windows Server 2025 Active Directory Group Policy Objects (GPOs) must be configured with proper audit settings. |
| V-278149 | II | manual | Windows Server 2025 Active Directory (AD) Domain object must be configured with proper audit settings. |
| V-278150 | II | manual | Windows Server 2025 Active Directory (AD) Infrastructure object must be configured with proper audit settings. |
| V-278151 | II | manual | Windows Server 2025 Active Directory (AD) Domain Controllers Organizational Unit (OU) object must be configured with proper audit settings. |
| V-278152 | II | manual | Windows Server 2025 Active Directory (AD) AdminSDHolder object must be configured with proper audit settings. |
| V-278153 | II | manual | Windows Server 2025 Active Directory (AD) RID Manager$ object must be configured with proper audit settings. |
| [V-278154](../tasks/V-278154.yml) | II | automated | Windows Server 2025 must be configured to audit Account Management - Computer Account Management successes. |
| [V-278155](../tasks/V-278155.yml) | II | automated | Windows Server 2025 must be configured to audit DS Access - Directory Service Access successes. |
| [V-278156](../tasks/V-278156.yml) | II | automated | Windows Server 2025 must be configured to audit DS Access - Directory Service Access failures. |
| [V-278157](../tasks/V-278157.yml) | II | automated | Windows Server 2025 must be configured to audit DS Access - Directory Service Changes successes. |
| [V-278158](../tasks/V-278158.yml) | II | automated | Windows Server 2025 must be configured to audit DS Access - Directory Service Changes failures. |
| V-278159 | II | manual | Windows Server 2025 domain controllers must have a PKI server certificate. |
| V-278160 | I | manual | Windows Server 2025 domain Controller PKI certificates must be issued by the DoW PKI or an approved External Certificate Authority (ECA). |
| V-278161 | I | manual | Windows Server 2025 PKI certificates associated with user accounts must be issued by a DoW PKI or an approved External Certificate Authority (ECA). |
| V-278162 | II | manual | Windows Server 2025 Active Directory (AD) user accounts, including administrators, must be configured to require the use of a common access card (CAC), Personal Identity Verification (PIV)-compliant hardware token, or Alternate Logon Token (ALT) for user authentication. |
| [V-278163](../tasks/V-278163.yml) | II | automated | Windows Server 2025 domain controllers must require LDAP access signing. |
| [V-278164](../tasks/V-278164.yml) | II | automated | Windows Server 2025 domain controllers must be configured to allow reset of machine account passwords. |
| [V-278165](../tasks/V-278165.yml) | II | automated | The Windows Server 2025 "Access this computer from the network" user right must only be assigned to the Administrators, Authenticated Users, and Enterprise Domain Controllers groups on domain controllers. |
| [V-278166](../tasks/V-278166.yml) | II | automated | The Windows Server 2025 "Add workstations to domain" user right must only be assigned to the Administrators group on domain controllers. |
| [V-278167](../tasks/V-278167.yml) | II | automated | The Windows Server 2025 "Allow log on through Remote Desktop Services" user right must only be assigned to the Administrators group on domain controllers. |
| [V-278168](../tasks/V-278168.yml) | II | automated | The Windows Server 2025 "Deny access to this computer from the network" user right on domain controllers must be configured to prevent unauthenticated access. |
| [V-278169](../tasks/V-278169.yml) | II | automated | The Windows Server 2025 "Deny log on as a batch job" user right on domain controllers must be configured to prevent unauthenticated access. |
| [V-278170](../tasks/V-278170.yml) | II | automated | The Windows Server 2025 "Deny log on as a service" user right must be configured to include no accounts or groups (blank) on domain controllers. |
| [V-278171](../tasks/V-278171.yml) | II | automated | The Windows Server 2025 "Deny log on locally" user right on domain controllers must be configured to prevent unauthenticated access. |
| [V-278173](../tasks/V-278173.yml) | II | automated | Windows Server 2025 must be configured for name-based strong mappings for certificates. |
| [V-278174](../tasks/V-278174.yml) | II | automated | The Windows Server 2025 "Deny log on through Remote Desktop Services" user right on domain controllers must be configured to prevent unauthenticated access. |
| [V-278175](../tasks/V-278175.yml) | II | automated | The Windows Server 2025 "Enable computer and user accounts to be trusted for delegation" user right must only be assigned to the Administrators group on domain controllers. |
| V-278176 | II | manual | The password for the krbtgt account on a domain must be reset at least every 180 days. |
| V-278177 | I | manual | Windows Server 2025 must only allow administrators responsible for the member server or stand-alone or nondomain-joined system to have Administrator rights on the system. |
| [V-278178](../tasks/V-278178.yml) | II | automated | Windows Server 2025 local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain-joined member servers. |
| [V-278179](../tasks/V-278179.yml) | II | automated | Windows Server 2025 local users on domain-joined member servers must not be enumerated. |
| [V-278180](../tasks/V-278180.yml) | II | automated | Windows Server 2025 must restrict unauthenticated Remote Procedure Call (RPC) clients from connecting to the RPC server on domain-joined member servers and stand-alone or nondomain-joined systems. |
| [V-278181](../tasks/V-278181.yml) | II | automated | Windows Server 2025 must limit the caching of logon credentials to four or less on domain-joined member servers. |
| [V-278182](../tasks/V-278182.yml) | II | automated | Windows Server 2025 must restrict remote calls to the Security Account Manager (SAM) to Administrators on domain-joined member servers and stand-alone or nondomain-joined systems. |
| [V-278183](../tasks/V-278183.yml) | II | automated | Windows Server 2025 "Access this computer from the network" user right must only be assigned to the Administrators and Authenticated Users groups on domain-joined member servers and stand-alone or nondomain-joined systems. |
| [V-278184](../tasks/V-278184.yml) | II | automated | The Windows Server 2025 "Deny access to this computer from the network" user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and local accounts and from unauthenticated access on all systems. |
| [V-278185](../tasks/V-278185.yml) | II | automated | Windows Server 2025 Deny log on as a batch job user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and from unauthenticated access on all systems. |
| [V-278186](../tasks/V-278186.yml) | II | automated | The Windows Server 2025 "Deny log on as a service" user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts. No other groups or accounts must be assigned this right. |
| [V-278187](../tasks/V-278187.yml) | II | automated | The Windows Server 2025 "Deny log on locally" user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and from unauthenticated access on all systems. |
| [V-278188](../tasks/V-278188.yml) | II | automated | The Windows Server 2025 "Deny log on through Remote Desktop Services" user right on domain-joined member servers must be configured to prevent access from highly privileged domain accounts and all local accounts and from unauthenticated access on all systems. |
| [V-278189](../tasks/V-278189.yml) | II | automated | The Windows Server 2025 "Enable computer and user accounts to be trusted for delegation" user right must not be assigned to any groups or accounts on domain-joined member servers and stand-alone or nondomain-joined systems. |
| [V-278190](../tasks/V-278190.yml) | I | automated | Windows Server 2025 must be running Credential Guard on domain-joined member servers. |
| [V-278192](../tasks/V-278192.yml) | II | automated | Windows Server 2025 must have the DoW Root Certificate Authority (CA) certificates installed in the Trusted Root Store. |
| [V-278193](../tasks/V-278193.yml) | II | automated | Windows Server 2025 must have the DoW Interoperability Root Certificate Authority (CA) cross-certificates installed in the Untrusted Certificates Store on unclassified systems. |
| [V-278194](../tasks/V-278194.yml) | II | automated | Windows Server 2025 must have the US DoW CCEB Interoperability Root CA cross-certificates in the Untrusted Certificates Store on unclassified systems. |
| [V-278195](../tasks/V-278195.yml) | II | automated | Windows Server 2025 must have the built-in guest account disabled. |
| [V-278196](../tasks/V-278196.yml) | I | automated | Windows Server 2025 must prevent local accounts with blank passwords from being used from the network. |
| [V-278197](../tasks/V-278197.yml) | II | automated | The Windows Server 2025 built-in administrator account must be renamed. |
| [V-278198](../tasks/V-278198.yml) | II | automated | The Windows Server 2025 built-in guest account must be renamed. |
| [V-278199](../tasks/V-278199.yml) | II | automated | Windows Server 2025 must force audit policy subcategory settings to override audit policy category settings. |
| [V-278200](../tasks/V-278200.yml) | II | automated | The Windows Server 2025 setting Domain member: Digitally encrypt or sign secure channel data (always) must be configured to Enabled. |
| [V-278201](../tasks/V-278201.yml) | II | automated | Windows Server 2025 setting Domain member: Digitally encrypt secure channel data (when possible) must be configured to Enabled. |
| [V-278202](../tasks/V-278202.yml) | II | automated | The Windows Server 2025 setting Domain member: Digitally sign secure channel data (when possible) must be configured to Enabled. |
| [V-278203](../tasks/V-278203.yml) | II | automated | Windows Server 2025 computer account password must not be prevented from being reset. |
| [V-278204](../tasks/V-278204.yml) | II | automated | Windows Server 2025 maximum age for machine account passwords must be configured to 30 days or less. |
| [V-278205](../tasks/V-278205.yml) | II | automated | Windows Server 2025 must be configured to require a strong session key. |
| [V-278206](../tasks/V-278206.yml) | II | automated | Windows Server 2025 machine inactivity limit must be set to 15 minutes or less, locking the system with the screen saver. |
| [V-278207](../tasks/V-278207.yml) | II | automated | The Windows Server 2025 required legal notice must be configured to display before console logon. |
| [V-278209](../tasks/V-278209.yml) | II | automated | The Windows Server 2025 Smart Card removal option must be configured to Force Logoff or Lock Workstation. |
| [V-278210](../tasks/V-278210.yml) | II | automated | The Windows Server 2025 setting Microsoft network client: Digitally sign communications (always) must be configured to Enabled. |
| [V-278211](../tasks/V-278211.yml) | II | automated | The Windows Server 2025 setting Microsoft network client: Digitally sign communications (if server agrees) must be configured to Enabled. |
| [V-278212](../tasks/V-278212.yml) | II | automated | Windows Server 2025 unencrypted passwords must not be sent to third-party Server Message Block (SMB) servers. |
| [V-278213](../tasks/V-278213.yml) | II | automated | The Windows Server 2025 setting Microsoft network server: Digitally sign communications (always) must be configured to Enabled. |
| [V-278214](../tasks/V-278214.yml) | II | automated | The Windows Server 2025 setting Microsoft network server: Digitally sign communications (if client agrees) must be configured to Enabled. |
| [V-278215](../tasks/V-278215.yml) | I | automated | Windows Server 2025 must not allow anonymous SID/Name translation. |
| [V-278216](../tasks/V-278216.yml) | I | automated | Windows Server 2025 must not allow anonymous enumeration of Security Account Manager (SAM) accounts. |
| [V-278217](../tasks/V-278217.yml) | I | automated | Windows Server 2025 must not allow anonymous enumeration of shares. |
| [V-278218](../tasks/V-278218.yml) | II | automated | Windows Server 2025 must be configured to prevent anonymous users from having the same permissions as the Everyone group. |
| [V-278219](../tasks/V-278219.yml) | I | automated | Windows Server 2025 must restrict anonymous access to Named Pipes and Shares. |
| [V-278220](../tasks/V-278220.yml) | II | automated | Windows Server 2025 services using Local System that use Negotiate when reverting to NTLM authentication must use the computer identity instead of authenticating anonymously. |
| [V-278221](../tasks/V-278221.yml) | II | automated | Windows Server 2025 must prevent NTLM from falling back to a Null session. |
| [V-278222](../tasks/V-278222.yml) | II | automated | Windows Server 2025 must prevent PKU2U authentication using online identities. |
| [V-278223](../tasks/V-278223.yml) | II | automated | Windows Server 2025 Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites. |
| [V-278225](../tasks/V-278225.yml) | I | automated | Windows Server 2025 LAN Manager authentication level must be configured to send NTLMv2 response only and to refuse LM and NTLM. |
| [V-278226](../tasks/V-278226.yml) | II | automated | Windows Server 2025 must be configured to at least negotiate signing for LDAP client signing. |
| [V-278227](../tasks/V-278227.yml) | II | automated | Windows Server 2025 session security for NTLM SSP-based clients must be configured to require NTLMv2 session security and 128-bit encryption. |
| [V-278228](../tasks/V-278228.yml) | II | automated | Windows Server 2025 session security for NTLM SSP-based servers must be configured to require NTLMv2 session security and 128-bit encryption. |
| [V-278229](../tasks/V-278229.yml) | II | automated | Windows Server 2025 users must be required to enter a password to access private keys stored on the computer. |
| [V-278230](../tasks/V-278230.yml) | II | automated | Windows Server 2025 must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing. |
| [V-278231](../tasks/V-278231.yml) | III | automated | Windows Server 2025 default permissions of global system objects must be strengthened. |
| [V-278232](../tasks/V-278232.yml) | II | automated | Windows Server 2025 User Account Control (UAC) approval mode for the built-in Administrator must be enabled. |
| [V-278233](../tasks/V-278233.yml) | II | automated | Windows Server 2025 UIAccess applications must not be allowed to prompt for elevation without using the secure desktop. |
| [V-278234](../tasks/V-278234.yml) | II | automated | Windows Server 2025 User Account Control (UAC) must, at a minimum, prompt administrators for consent on the secure desktop. |
| [V-278235](../tasks/V-278235.yml) | II | automated | Windows Server 2025 User Account Control (UAC) must automatically deny standard user requests for elevation. |
| [V-278236](../tasks/V-278236.yml) | II | automated | Windows Server 2025 User Account Control (UAC) must be configured to detect application installations and prompt for elevation. |
| [V-278237](../tasks/V-278237.yml) | II | automated | Windows Server 2025 User Account Control (UAC) must only elevate UIAccess applications that are installed in secure locations. |
| [V-278238](../tasks/V-278238.yml) | II | automated | Windows Server 2025 User Account Control (UAC) must run all administrators in Admin Approval Mode, enabling UAC. |
| [V-278239](../tasks/V-278239.yml) | II | automated | Windows Server 2025 User Account Control (UAC) must virtualize file and registry write failures to per-user locations. |
| V-278240 | II | manual | Windows Server 2025 must preserve zone information when saving attachments. |
| [V-278241](../tasks/V-278241.yml) | II | automated | The Windows Server 2025 "Access Credential Manager as a trusted caller" user right must not be assigned to any groups or accounts. |
| [V-278242](../tasks/V-278242.yml) | I | automated | The Windows Server 2025 "Act as part of the operating system" user right must not be assigned to any groups or accounts. |
| [V-278243](../tasks/V-278243.yml) | II | automated | The Windows Server 2025 "Allow log on locally" user right must only be assigned to the Administrators group. |
| [V-278244](../tasks/V-278244.yml) | II | automated | The Windows Server 2025 "Back up files and directories" user right must only be assigned to the Administrators group. |
| [V-278245](../tasks/V-278245.yml) | II | automated | The Windows Server 2025 "Create a pagefile" user right must only be assigned to the Administrators group. |
| [V-278246](../tasks/V-278246.yml) | I | automated | The Windows Server 2025 "Create a token object" user right must not be assigned to any groups or accounts. |
| [V-278247](../tasks/V-278247.yml) | II | automated | The Windows Server 2025 "Create global objects" user right must only be assigned to Administrators, Service, Local Service, and Network Service. |
| [V-278248](../tasks/V-278248.yml) | II | automated | The Windows Server 2025 "Create permanent shared objects" user right must not be assigned to any groups or accounts. |
| [V-278249](../tasks/V-278249.yml) | II | automated | The Windows Server 2025 "Create symbolic links" user right must only be assigned to the Administrators group. |
| [V-278250](../tasks/V-278250.yml) | I | automated | The Windows Server 2025 "Debug programs" user right must only be assigned to the Administrators group. |
| [V-278251](../tasks/V-278251.yml) | II | automated | The Windows Server 2025 "Force shutdown from a remote system" user right must only be assigned to the Administrators group. |
| [V-278252](../tasks/V-278252.yml) | II | automated | The Windows Server 2025 "Generate security audits" user right must only be assigned to Local Service and Network Service. |
| [V-278253](../tasks/V-278253.yml) | II | automated | The Windows Server 2025 "Impersonate a client after authentication" user right must only be assigned to Administrators, Service, Local Service, and Network Service. |
| [V-278254](../tasks/V-278254.yml) | II | automated | The Windows Server 2025 "Increase scheduling priority" user right must only be assigned to the Administrators group. |
| [V-278255](../tasks/V-278255.yml) | II | automated | The Windows Server 2025 "Load and unload device drivers" user right must only be assigned to the Administrators group. |
| [V-278256](../tasks/V-278256.yml) | II | automated | The Windows Server 2025 "Lock pages in memory" user right must not be assigned to any groups or accounts. |
| [V-278257](../tasks/V-278257.yml) | II | automated | The Windows Server 2025 "Manage auditing and security log" user right must only be assigned to the Administrators group. |
| [V-278258](../tasks/V-278258.yml) | II | automated | The Windows Server 2025 "Modify firmware environment values" user right must only be assigned to the Administrators group. |
| [V-278259](../tasks/V-278259.yml) | II | automated | The Windows Server 2025 "Perform volume maintenance tasks" user right must only be assigned to the Administrators group. |
| [V-278260](../tasks/V-278260.yml) | II | automated | The Windows Server 2025 "Profile single process" user right must only be assigned to the Administrators group. |
| [V-278261](../tasks/V-278261.yml) | II | automated | The Windows Server 2025 "Restore files and directories" user right must only be assigned to the Administrators group. |
| [V-278262](../tasks/V-278262.yml) | II | automated | The Windows Server 2025 "Take ownership of files or other objects" user right must only be assigned to the Administrators group. |
| [V-279918](../tasks/V-279918.yml) | II | automated | Windows Server 2025 must be configured to audit handle manipulation failures. |
| [V-279920](../tasks/V-279920.yml) | II | automated | Windows Server 2025 must be configured to audit registry failures. |
| [V-279921](../tasks/V-279921.yml) | II | automated | Windows Server 2025 must be configured to audit registry successes. |
| [V-279922](../tasks/V-279922.yml) | II | automated | Windows Server 2025 must be configured to audit sensitive privilege use successes. |
| [V-279923](../tasks/V-279923.yml) | II | automated | Windows Server 2025 must be configured to audit sensitive privilege use failures. |
| [V-285313](../tasks/V-285313.yml) | II | automated | Windows Server 2025 networked systems must have and implement OpenSSH to protect the confidentiality and integrity of transmitted and received information, as well as information during preparation for transmission. |
| [V-285314](../tasks/V-285314.yml) | II | automated | Windows Server 2025 OpenSSH must display the Standard Mandatory DoW Notice and Consent Banner before granting remote access to the system via an OpenSSH logon. |
| [V-285315](../tasks/V-285315.yml) | II | automated | Windows Server 2025 OpenSSH must accept public key authentication. |
| [V-285316](../tasks/V-285316.yml) | I | automated | Windows Server 2025 OpenSSH must not allow blank passwords. |
| [V-285317](../tasks/V-285317.yml) | II | automated | Windows Server 2025 OpenSSH must force a frequent session key renegotiation for SSH connections to the server. |
| [V-285318](../tasks/V-285318.yml) | II | automated | Windows Server 2025 OpenSSH must be configured so that all network connections associated with SSH traffic terminate after becoming unresponsive. |
| [V-285319](../tasks/V-285319.yml) | II | automated | Windows Server 2025 OpenSSH must be configured so that all network connections associated with SSH traffic are terminated after 10 minutes of becoming unresponsive. |
| [V-285320](../tasks/V-285320.yml) | II | automated | The Windows Server 2025 OpenSSH configuration file must conform to minimum requirements. |
| [V-285321](../tasks/V-285321.yml) | II | automated | Windows Server 2025 OpenSSH private host key files must conform to minimum requirements. |
| [V-285322](../tasks/V-285322.yml) | II | automated | Windows Server 2025 OpenSSH public host key files must conform to minimum requirements. |
| [V-285323](../tasks/V-285323.yml) | II | automated | Windows Server 2025 OpenSSH must not allow GSSAPI authentication. |
| V-289259 | II | manual | Windows Server 2025 must be maintained at a supported servicing level. |
