# Windows Server 2025 development-server security-plan procedures

Scope: WIN25-CORE-V0, machine SID S-1-5-21-2982072508-2365857290-1453907225.

Temporary, emergency and shared-account non-use is the system-owner declaration from this task. Other procedures are created under AGENTS.MD for inclusion in the security plan. Technical protections are checked independently; documenting a procedure does not establish that an absent protection is installed.

## V-277982 — SV-277982r1181944_rule

PATCH-01: The server owner checks patch-management compliance weekly. Install security-relevant OS updates within 30 days, or sooner when required by IAVM/CTO/DTM. Record source, scan date, installation date and exceptions in the patch register; escalate overdue updates to the ISSO.

Source: `vars/control_manifest.yml` and `files/disa_stigs/U_MS_Windows_Server_2025_V1R4_STIG.zip`; native evaluator `Scan-WindowsServer2025_Checks.psm1`, function `Get-V277982` when present; otherwise a manual benchmark check.

## V-277983 — SV-277983r1180655_rule

HW-01: Maintain a hardware inventory for this VM and its attached devices. Only documented components approved by the ISSO/ISSM may be attached. Review inventory monthly and before changes; disable or remove unapproved devices. Hypervisor administrators must restrict console, virtual media and device passthrough changes to authorized administrators and record approvals.

Source: `vars/control_manifest.yml` and `files/disa_stigs/U_MS_Windows_Server_2025_V1R4_STIG.zip`; native evaluator `Scan-WindowsServer2025_Checks.psm1`, function `Get-V277983` when present; otherwise a manual benchmark check.

## V-277985 — SV-277985r1268251_rule

AC-01: Assign each human administrator a unique privileged account separate from their ordinary user account. Use ordinary accounts for routine work. The ansible identity is dedicated to managed automation and is not a shared interactive user account; the built-in administrator is restricted to system administration. Review account ownership and privileged membership monthly, and revoke access on role change or departure.

Source: `vars/control_manifest.yml` and `files/disa_stigs/U_MS_Windows_Server_2025_V1R4_STIG.zip`; native evaluator `Scan-WindowsServer2025_Checks.psm1`, function `Get-V277985` when present; otherwise a manual benchmark check.

## V-277987 — SV-277987r1268251_rule

AC-02: System-owner declaration: this server is not Internet facing. Public Internet browsing and email are not authorized administrative functions on this system. Administrative identities are restricted by site operating policy to server administration; local service-administration exceptions must identify the required tools/endpoints. Record this deployment scope in the security plan and reassess this determination if Internet exposure, public-network access or workloads change. This is an owner-attested policy determination, not a claim that AppLocker or an egress firewall was inspected.

Source: `vars/control_manifest.yml` and `files/disa_stigs/U_MS_Windows_Server_2025_V1R4_STIG.zip`; native evaluator `Scan-WindowsServer2025_Checks.psm1`, function `Get-V277987` when present; otherwise a manual benchmark check.

## V-277989 — SV-277989r1181947_rule

SA-01: Manually managed application/service account passwords must contain at least 15 characters. Provisioning and rotation procedures must validate the length before accepting a credential; reject shorter passwords. Use managed service accounts where supported. Store credentials in the approved secret store, restrict access, and review service account compliance quarterly. Password values must never be recorded in assessment evidence.

Source: `vars/control_manifest.yml` and `files/disa_stigs/U_MS_Windows_Server_2025_V1R4_STIG.zip`; native evaluator `Scan-WindowsServer2025_Checks.psm1`, function `Get-V277989` when present; otherwise a manual benchmark check.

## V-277990 — SV-277990r1268251_rule

SA-02: Inventory manually managed application/service accounts and their owners. Change passwords at least annually and immediately when an administrator with knowledge of the password leaves or loses authorization. Record rotation and personnel-change completion dates without recording secrets. Review password ages monthly; prefer system-managed service accounts.

Source: `vars/control_manifest.yml` and `files/disa_stigs/U_MS_Windows_Server_2025_V1R4_STIG.zip`; native evaluator `Scan-WindowsServer2025_Checks.psm1`, function `Get-V277990` when present; otherwise a manual benchmark check.

## V-277991 — SV-277991r1181778_rule

AC-03: Shared user accounts are prohibited and are not used on this system, as confirmed by the system owner. Every human user must have an individually attributable account. Do not create shared user accounts or grant shared interactive access to automation identities. Review accounts monthly and remove any unapproved shared account immediately. Any future exception requires an ISSO-approved reason, named authorized users, mitigations and activity monitoring, and reassessment of this control.

Source: `vars/control_manifest.yml` and `files/disa_stigs/U_MS_Windows_Server_2025_V1R4_STIG.zip`; native evaluator `Scan-WindowsServer2025_Checks.psm1`, function `Get-V277991` when present; otherwise a manual benchmark check.

## V-277992 — SV-277992r1182016_rule

APP-01: Execute only explicitly authorized software under an enforced deny-by-default application allowlist. Review the effective policy, enforcement service and approved rules monthly and before software changes. Audit-only policy is insufficient. Validate SSH administration and recovery access before enforcing any revised policy.

Source: `vars/control_manifest.yml` and `files/disa_stigs/U_MS_Windows_Server_2025_V1R4_STIG.zip`; native evaluator `Scan-WindowsServer2025_Checks.psm1`, function `Get-V277992` when present; otherwise a manual benchmark check.

## V-277996 — SV-277996r1268251_rule

IDPS-01: Maintain an installed, healthy and actively reporting host-based intrusion detection and prevention solution. Security operations reviews sensor health daily and investigates alerts. Antivirus or a log forwarder alone is not evidence of host-based IDPS. Resolve missing, stopped or unconfigured sensors and retain management-console evidence.

Source: `vars/control_manifest.yml` and `files/disa_stigs/U_MS_Windows_Server_2025_V1R4_STIG.zip`; native evaluator `Scan-WindowsServer2025_Checks.psm1`, function `Get-V277996` when present; otherwise a manual benchmark check.

## V-278006 — SV-278006r1182237_rule

FIM-01: Maintain approved baselines covering every system-file location, including executable, batch, command and DLL files. Compare files against the baseline at least weekly, investigate unauthorized changes, and retain comparison results. Refresh baselines only after approved changes; document coverage, schedule, alert routing and reviewer.

Source: `vars/control_manifest.yml` and `files/disa_stigs/U_MS_Windows_Server_2025_V1R4_STIG.zip`; native evaluator `Scan-WindowsServer2025_Checks.psm1`, function `Get-V278006` when present; otherwise a manual benchmark check.

## V-278009 — SV-278009r1211149_rule

DAR-01: The system owner confirms that datastore encryption provides data-at-rest protection for this virtual server. Operating-system-level encryption is omitted because the underlying encrypted datastore protects the VM operating-system/configuration data and persistent virtual disks. This is the documented infrastructure-encryption exception allowed by the V-278009 Check. The storage owner must retain datastore coverage, FIPS-compliant algorithm, key-management and recovery evidence, and reassess after VM/storage moves, unencrypted disk additions or encryption changes. This assessment records the owner declaration; it does not claim a hypervisor encryption inspection.

Source: `vars/control_manifest.yml` and `files/disa_stigs/U_MS_Windows_Server_2025_V1R4_STIG.zip`; native evaluator `Scan-WindowsServer2025_Checks.psm1`, function `Get-V278009` when present; otherwise a manual benchmark check.

## V-278010 — SV-278010r1180736_rule

DIT-01: The data owner documents confidentiality/integrity requirements and all transfer paths. Where end-to-end protection is required, use TLS, encrypted VPN or IPsec across every application hop; use SSH for administration. Record endpoints, protocols, certificate validation and any terminators. Review after topology changes. SSH presence alone does not prove protection of every application flow.

Source: `vars/control_manifest.yml` and `files/disa_stigs/U_MS_Windows_Server_2025_V1R4_STIG.zip`; native evaluator `Scan-WindowsServer2025_Checks.psm1`, function `Get-V278010` when present; otherwise a manual benchmark check.

## V-278011 — SV-278011r1182239_rule

ROLE-01: Maintain the per-host required Windows roles/features register with a purpose for each entry. Compare installed features to the register monthly and after changes. Remove unnecessary features through change control; preserve required PowerShell, OpenSSH and administration dependencies. An unregistered feature requires review and fails the custom check.

Source: `vars/control_manifest.yml` and `files/disa_stigs/U_MS_Windows_Server_2025_V1R4_STIG.zip`; native evaluator `Scan-WindowsServer2025_Checks.psm1`, function `Get-V278011` when present; otherwise a manual benchmark check.

## V-278013 — SV-278013r1268212_rule

AC-04: Temporary user accounts are not used on this system, as confirmed by the system owner. Provisioning procedures prohibit their creation. Review the account inventory monthly. If temporary accounts are introduced, configure automatic expiration within 72 hours, delete unneeded accounts and reassess this control before use.

Source: `vars/control_manifest.yml` and `files/disa_stigs/U_MS_Windows_Server_2025_V1R4_STIG.zip`; native evaluator `Scan-WindowsServer2025_Checks.psm1`, function `Get-V278013` when present; otherwise a manual benchmark check.

## V-278014 — SV-278014r1182263_rule

AC-05: Emergency accounts are not used on this system, as confirmed by the system owner. Provisioning procedures prohibit their creation. Review accounts monthly. If emergency access is introduced, disable/remove the account when the crisis ends or automatically expire it within 72 hours; document any ongoing crisis and reassess before use.

Source: `vars/control_manifest.yml` and `files/disa_stigs/U_MS_Windows_Server_2025_V1R4_STIG.zip`; native evaluator `Scan-WindowsServer2025_Checks.psm1`, function `Get-V278014` when present; otherwise a manual benchmark check.

## V-278029 — SV-278029r1256714_rule

TIME-01: win25_stig_time_source identifies the approved environment time source, designated by the system owner as the authorized upstream time hierarchy. When nonempty, the role configures Windows Time to use that source and enables the NTP client. The custom check returns Not a Finding only when all configured NTP peers match the approved source and Windows Time is running. A blank variable does not approve the existing public time source. Domain members may use NT5DS through their domain time hierarchy. Review synchronization health weekly and reassess when the approved source changes.

Source: `vars/control_manifest.yml` and `files/disa_stigs/U_MS_Windows_Server_2025_V1R4_STIG.zip`; native evaluator `Scan-WindowsServer2025_Checks.psm1`, function `Get-V278029` when present; otherwise a manual benchmark check.

## V-278041 — SV-278041r1180829_rule

LOG-01: Splunk Universal Forwarder is the site-approved audit backup mechanism. Per the system owner's assessment criterion, verify its installation for this control. Forward Windows Security, System and Application audit events to a separate Splunk system; retain them under the audit retention policy. Check forwarding and destination retention daily and test retrieval monthly. Investigate missing events or failed delivery.

Source: `vars/control_manifest.yml` and `files/disa_stigs/U_MS_Windows_Server_2025_V1R4_STIG.zip`; native evaluator `Scan-WindowsServer2025_Checks.psm1`, function `Get-V278041` when present; otherwise a manual benchmark check.

## V-278042 — SV-278042r1182270_rule

LOG-02: Splunk Universal Forwarder is the site-approved audit offload mechanism. Per the system owner's assessment criterion, verify its installation for this control. Configure real-time Windows event forwarding for interconnected systems; for isolated/non-domain systems offload no less often than weekly. Monitor forwarder/destination health daily, alert on delivery interruption, and retain evidence of offload and review.

Source: `vars/control_manifest.yml` and `files/disa_stigs/U_MS_Windows_Server_2025_V1R4_STIG.zip`; native evaluator `Scan-WindowsServer2025_Checks.psm1`, function `Get-V278042` when present; otherwise a manual benchmark check.

## V-278106 — SV-278106r1211154_rule

LOG-03: When Security events are forwarded directly to a separate audit server, the local one-week sizing requirement is not applicable. Verify an enabled Security input, a running forwarder and a separate configured destination. Otherwise retain at least one week locally, review actual event volume weekly and increase capacity before retention falls below seven days. A 5 GB setting alone is not proof of a week of retention.

Source: `vars/control_manifest.yml` and `files/disa_stigs/U_MS_Windows_Server_2025_V1R4_STIG.zip`; native evaluator `Scan-WindowsServer2025_Checks.psm1`, function `Get-V278106` when present; otherwise a manual benchmark check.

## V-278177 — SV-278177r1182280_rule

AC-06: Only accounts responsible for administration may belong to local Administrators. The approved development-server identities are the dedicated ansible automation identity and the built-in administrative identity, identified by SID in the per-host register. No ordinary user accounts are allowed. Review membership monthly and at personnel changes; domain members must replace broad Domain Admins membership with a server-specific group.

Source: `vars/control_manifest.yml` and `files/disa_stigs/U_MS_Windows_Server_2025_V1R4_STIG.zip`; native evaluator `Scan-WindowsServer2025_Checks.psm1`, function `Get-V278177` when present; otherwise a manual benchmark check.

## V-278240 — SV-278240r1268251_rule

ATT-01: Preserve attachment zone information in every interactive user profile. Leave SaveZoneInformation absent (Windows default) or set REG_DWORD 2. Check loaded and unloaded profiles and the default profile on provisioning and monthly. A value of 1 or an unreadable existing profile is a finding. Service-only identities do not create an exception for human interactive users.

Source: `vars/control_manifest.yml` and `files/disa_stigs/U_MS_Windows_Server_2025_V1R4_STIG.zip`; native evaluator `Scan-WindowsServer2025_Checks.psm1`, function `Get-V278240` when present; otherwise a manual benchmark check.

## Per-host register

```json
{
  "computer_name": "WIN25-CORE-V0",
  "machine_sid": "S-1-5-21-2982072508-2365857290-1453907225",
  "approved_admin_sids": [
    "S-1-5-21-2982072508-2365857290-1453907225-1000",
    "S-1-5-21-2982072508-2365857290-1453907225-500"
  ],
  "hardware_control_procedure": true,
  "separate_admin_accounts": true,
  "service_password_minimum": 15,
  "service_password_provisioning_check": true,
  "rotate_on_departure": true,
  "shared_accounts_used": false,
  "temporary_accounts_used": false,
  "emergency_accounts_used": false,
  "manually_managed_accounts": [
    "ansible"
  ],
  "approved_ntp_sources": [],
  "required_features": [
    "FileAndStorage-Services",
    "Storage-Services",
    "NET-Framework-45-Features",
    "NET-Framework-45-Core",
    "NET-WCF-Services45",
    "NET-WCF-TCP-PortSharing45",
    "Windows-Defender",
    "System-DataArchiver",
    "PowerShellRoot",
    "PowerShell",
    "WoW64-Support"
  ],
  "internet_facing": false,
  "datastore_encryption_used": true
}
```

Required feature purposes: file/storage roles support the OS storage stack; .NET 4.8/WCF/TCP Port Sharing support the documented installed framework; Defender provides antivirus; System Data Archiver supports system data collection; Windows PowerShell supports administration and Ansible; WoW64 supports installed 32-bit compatibility. Review this register when changing the server workload.
