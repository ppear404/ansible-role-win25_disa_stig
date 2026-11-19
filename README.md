# Windows Server 2025 DISA STIG

> Public release preparation: use the clean snapshot described in [PUBLICATION.md](PUBLICATION.md). The development Git history contains private assessment artifacts and must not be pushed to a public remote.

Ansible role based on the **Windows Server 2025 V1R4** manual XCCDF supplied in
`files/disa_stigs`. It follows the neighboring roles' category and vulnerability
file structure. Every one of the benchmark's 291 controls has a task file, a
boolean switch, severity tags, and a manifest entry containing its original check
and fix text.

220 controls have automated remediation, including conditional and opt-in actions.
71 controls record required manual or site remediation. A completed play is **not**
a declaration that all 291 controls pass. Policy, PKI, application allowlisting,
backup, firmware, and Active Directory design requirements need site evidence.

## Requirements and use

Use ansible-core 2.18 or later and install collections:

```bash
ansible-galaxy collection install -r requirements.yml
ansible-playbook tests/test.yml -i inventory_win25/inventory --ask-pass --check --diff
ansible-playbook tests/test.yml -i inventory_win25/inventory --ask-pass
```

The example play targets the inventory group `win25`. The role requires an elevated
administrator session on Windows Server 2025 (build 26100). SSH with PowerShell is
supported; WinRM can also be configured in inventory. Store passwords in Ansible
Vault or supply `--ask-pass`; the inventory's password comment is not an Ansible
variable. Local development credentials are never copied into role defaults.

From another project, put this directory on `roles_path` and use:

```yaml
- name: Harden Windows servers
  hosts: windows
  gather_facts: false
  roles:
    - win25_disa_stig
```

## Structure and selection

- `tasks/main.yml`: preflight, dependency imports, category imports, handlers, and reporting.
- `tasks/security_policy.yml`: security-policy imports run before registry and audit
  remediation so a later `secedit` import cannot overwrite those settings.
- `tasks/cat1.yml`, `cat2.yml`, `cat3.yml`: severity selection. Category 2 is divided
  into smaller index files, which import the individual controls.
- `tasks/V-*.yml`: individual remediation or explicit pending-review entries.
- `vars/control_manifest.yml`: complete source checks, fixes, and applicability.
- `defaults/main.yml`: settings and individual control switches.
- `tests/validate_controls.py`: benchmark coverage and interacting-policy checks.

Select `--tags CAT1`, `--tags CAT2`, `--tags CAT3`, or a vulnerability such as
`--tags V-278225`. Preflight and reporting always run. Disable a category using
`win25_stig_cat1: false` (likewise cat2/cat3), or a control using, for example,
`win25_stig_v_278225: false`. Disabling a control does not undo existing settings.
Paired audit-success/failure controls set the combined benchmark flags for their
subcategory; running one of those controls can enable both flags.

Document a site exception with its reason:

```yaml
win25_stig_exceptions:
  V-278016: 'FTP required by approved application; ISSO approval ABC-123.'
```

Exceptions skip remediation and remain visible in the report. They do not mark a
control compliant. Keep approvals and review dates in the exception text.

## Site settings and applicability

Review defaults before production use. Normal remediation enables the Windows
firewall and Defender, removes prohibited features, renames the built-in accounts,
and configures security policies. Existing firewall rules and SSH authorization
are preserved. Before enabling the firewall, the role allows the configured Ansible
management port using the `Ansible STIG management connection` rule. Limit its source addresses
with `win25_stig_management_remote_addresses` (default: `any`). The built-in Administrator becomes `stig_local_admin` and Guest
becomes `stig_guest_disabled`; override those names to match site policy.

- Domain controllers and member/standalone systems receive different user-right
  settings. Domain-controller account/Kerberos policies and directory ACLs remain
  pending until managed through the authoritative domain GPO. The role does not
  create or overwrite domain GPOs. Domain GPO refresh can override local settings;
  assess the effective policy after deployment.
- Domain-member deny rights require `win25_stig_domain_sid` and
  `win25_stig_forest_root_sid` (domain SIDs without the group RID). Missing SIDs
  leave those controls pending. Standalone systems receive the benchmark's Guests
  deny assignments. Domain Admins/Enterprise Admins deny assignments may affect
  administration workflows; use a suitable delegated management account.
- `win25_stig_manage_local_password_flags` defaults to false. Enable it after
  reviewing service-account exceptions in `win25_stig_password_exempt_accounts`.
  Account disablement/deletion, administrator-password rotation, and krbtgt resets
  require a site account lifecycle process.
- `win25_stig_manage_defender` defaults to true. Disable it when an approved
  third-party product is deployed and retain its evidence for V-277995.
- `win25_stig_ftp_required` and `win25_stig_bluetooth_required` default to false.
  Required FTP isolation/authentication and approved Bluetooth/Wi-Fi use need
  site review. An absent feature name is skipped on images that no longer ship it.
- `win25_stig_enable_virtualization_security` and
  `win25_stig_enable_credential_guard_uefi_lock` default to false. Enabling them
  configures the benchmark registry policies only. Verify firmware, Secure Boot,
  hardware support, and the **running** Device Guard state separately. Credential
  Guard's UEFI lock requires physical-console recovery to reverse. Exchange servers
  are excluded when `win25_stig_exchange_server: true`.
- `win25_stig_enforce_remote_uac` defaults to true. Plan an elevated management
  connection before enforcing restrictions on remote local-administrator tokens.
- PowerShell transcripts default to `C:\ProgramData\PS_Transcript`. Existing
  transcript ACLs are normalized to administrator/SYSTEM full control and standard
  user write/append access. Use a local directory for this implementation; a remote
  collector needs separately managed share and NTFS ACLs.
- SSH settings are applied globally before the first `Match` block, preserving all
  existing Match blocks. Inspect conditional overrides as part of effective-policy
  assessment. SSH configuration is validated before restarting the service. The restart runs
  asynchronously and verifies a fresh management connection before continuing.

## Reboots and verification

Automatic reboot defaults to off (`win25_stig_reboot: false`). Registry or feature
changes conservatively mark a restart as required. Handlers run before the final
report. Restart in an approved window, then reassess effective policy, antivirus
health, firmware controls, and domain GPO precedence.

```bash
python tests/validate_controls.py
ansible-playbook tests/test.yml --syntax-check
ansible-lint --offline tasks handlers defaults vars meta tests/test.yml
ansible-playbook tests/validate-powershell.yml --limit win25-1 --ask-pass
ansible-playbook tests/test.yml --ask-pass
ansible-playbook tests/test.yml --ask-pass  # second pass checks idempotence
ansible-playbook tests/test.yml --ask-pass --check --diff
```

The final report lists pending manual/site controls, documented exceptions, and
restart requirements. Explicitly disabled controls and categories must also be
included in the site's compliance assessment. Hardware-dependent registry policy
application is not proof the underlying protection is running. Use an independent
STIG assessment after configuration; retain evidence and approved exceptions.

The benchmark source is distributed in `files`; its original notices remain in
those documents. Role implementation files use SPDX MIT-0 headers.

## Run Evaluate-STIG and fetch results

`tests/evaluate.yml` uses the supplied `files/evaluate-stig-1.2610.1.tar.gz`, selects
`WinServer2025` (V1R4), and requests CKLB, CSV, XCCDF, and Summary output. It fetches
individual checklists and an archive of all reports/logs into
`.files/<inventory-host>/<UTC-run-timestamp>/`, as required by `AGENTS.MD`.
It uses `files/answer_files/WinServer2025_AnswerFile.xml` through `-AFPath`
and `-AnswerKey DEFAULT`. The pinned V-278207 legal-notice rule and the 21 scoped manual-review rules are
eligible for conditional status changes. See [answer-file scope and procedures](files/answer_files/README.md). Independent validation permits whitespace
formatting differences and requires REG_SZ and the complete approved notice;
missing or changed wording and incorrect types remain Open. The exact answer file
is archived with each assessment. New manual-review entries match native Not Reviewed only and preserve native Open results. Use the dev-host limit explicitly:

```bash
ansible-playbook tests/evaluate.yml -i inventory_win25/inventory --limit win25-1 --list-hosts
ansible-playbook tests/evaluate.yml -i inventory_win25/inventory --limit win25-1 --ask-pass
```

If using WinRM instead of SSH, install the controller's `pywinrm` dependency and
supply the connection settings through inventory or extra variables, including
`ansible_connection: winrm`, `ansible_shell_type: cmd`, and the appropriate WinRM
port, scheme, and transport. Assessment artifacts describe the observed host state;
review Open and Not Reviewed items before making a compliance assertion.

Transcript and SSH ACL comparisons preserve the required ownership and access
rights while ignoring Windows' automatic inheritance bookkeeping. The transcript
regression fixture verifies that inherited write-only permissions are accepted and
that standard-user read permissions are still rejected.

The legal-notice answer file is pinned to `SV-278207r1268215_rule` (Windows Server
2025 V1R4). Review it when updating the benchmark. Run its positive, negative,
and live-registry tests with `tests/validate-answer-file.yml`. The validator
source is also available as `files/answer_files/Validate-LegalNotice.ps1`.

Certificate controls V-278192, V-278193 and V-278194 use pinned, validated public payloads. See [certificate provenance and store behavior](files/certificates/README.md). Set `win25_stig_unclassified: false` on classified systems; the public DoD trust controls then skip and require site-approved NSS configuration. Certificate store changes support check mode; public staging and read-only payload validation still run during a dry run.

The role deploys security-plan procedures and runs custom evidence checks for the 21 manual-review controls in the November 19 baseline. Account non-use declarations follow the system owner's policy; absent technical protections become Open. See [the procedure document](files/answer_files/manual/SecurityPlanProcedures.md) and run `tests/validate-manual-controls.yml` for decision fixtures.

For V-278029, set `win25_stig_time_source` to the environment NTP hostname/IP in inventory or extra variables for both remediation and evaluation. Any nonempty value is owner-designated approved; blank leaves Windows Time unchanged. The role configures the source and enables the NTP client; the answer checks matching configured peers and a running service. V-277987 records the owner's non-Internet-facing policy determination; V-278009 records datastore encryption as the benchmark's infrastructure-encryption exception (Not Applicable).
