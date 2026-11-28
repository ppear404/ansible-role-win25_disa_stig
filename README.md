# Windows Server 2025 DISA STIG remediation

This Ansible role applies technical controls from the Windows Server 2025
V1R4 benchmark. It implements 223 of the benchmark's 291 controls, including
conditional and opt-in remediation. The control manifest retains the original
benchmark check and fix text. A successful play establishes which Ansible tasks
ran. Run the unmodified upstream Evaluate-STIG separately to assess the
effective Windows configuration. The role's output reports configured
remediation exceptions and whether a restart is required.

## Requirements and use

Use ansible-core 2.18 or later and install the collections from
`requirements.yml`. The role requires an elevated administrator connection to
Windows Server 2025 build 26100. Server Core and Desktop Experience use the same
tasks. The role supports standalone servers, domain members, and domain
controllers. Preflight detects domain membership and role from the Windows host.

Use SSH with `ansible_connection: ssh` and `ansible_shell_type: powershell`, or
configure `ansible_connection: winrm` and the appropriate WinRM authentication
and certificate settings. For WinRM, install `pywinrm` on the controller.
Supply connection credentials through Ansible Vault or the appropriate
connection option.

Put this role directory on the calling project's `roles_path` and include it in
a play:

```yaml
- name: Harden Windows servers
  hosts: win25
  gather_facts: false
  roles:
    - win25_disa_stig
```

The role's `tests/test.yml` is an example play with that group. Inspect the
explicitly authorized target before running check mode or applying changes.
See [the two-host inventory example](examples/inventory/hosts.yml) for the
inventory layout:

```bash
ansible-playbook -i inventory/hosts.yml tests/test.yml --limit server01 --list-hosts
ansible-playbook -i inventory/hosts.yml tests/test.yml --limit server01 --check
ansible-playbook -i inventory/hosts.yml tests/test.yml --limit server01
```

## Control selection and exceptions

The severity tags are `CAT1`, `CAT2`, and `CAT3`. Each remediation retains its
vulnerability ID tag, such as `V-278225`. The matching
`win25_stig_cat1`, `win25_stig_cat2`, `win25_stig_cat3`, and
`win25_stig_v_<id>` switches default to true. The switches for controls with
only manual benchmark procedures remain defined for inventory compatibility.
Paired audit-success and audit-failure controls set the combined flags required
for their shared subcategory.

Set `win25_stig_exceptions` to a mapping from a benchmark vulnerability ID
to a nonempty reason. Remediation skips those controls and prints the configured
exceptions at the end of the play. Evaluate-STIG determines finding statuses
independently.

## Inventory inputs

No role variable is mandatory for a basic run. Set technical inputs in the
calling project's group or host variables using standard Ansible precedence.
For example, use a group variable for a shared management network:

```yaml
# inventory/group_vars/win25.yml
win25_stig_management_remote_addresses: '192.0.2.0/24'
```

Use host variables for server-specific settings or exceptions:

```yaml
# inventory/host_vars/server01.yml
win25_stig_time_source: 'ntp.example.invalid'
win25_stig_exceptions:
  V-278016: 'FTP required for an approved application. Approval ABC-123.'
```

Replace example values with owner-approved settings for the target environment.
The available inputs and defaults are in [defaults/main.yml](defaults/main.yml).

| Input | Use |
| --- | --- |
| `win25_stig_management_remote_addresses` | Source IP addresses or CIDRs for Ansible management firewall rules. Defaults to `any`. |
| `win25_stig_time_source` | Single NTP hostname or IP for standalone servers and the PDC emulator. A blank value leaves their time settings alone. Other domain-joined systems use NT5DS. |
| `win25_stig_domain_sid`, `win25_stig_forest_root_sid` | Domain and forest-root SIDs without the group RID. Domain-member deny rights that reference these domains require both values. |
| `win25_stig_administrator_name`, `win25_stig_guest_name` | Built-in account names. Defaults are `stig_local_admin` and `stig_guest_disabled`. |
| `win25_stig_manage_defender` | Defaults to true. Set false where an approved third-party product handles this control. |
| `win25_stig_ftp_required`, `win25_stig_bluetooth_required` | Retain features needed by the host. Both default to false. |
| `win25_stig_enable_virtualization_security`, `win25_stig_enable_credential_guard_uefi_lock`, `win25_stig_exchange_server` | Opt in to registry configuration for virtualization security and UEFI lock, or identify an Exchange server. All default to false. |
| `win25_stig_enforce_remote_uac` | Apply remote UAC restrictions. Defaults to true. |
| `win25_stig_transcript_directory` | Local PowerShell transcript directory, defaulting to `C:\ProgramData\PS_Transcript`. |
| `win25_stig_unclassified`, `win25_stig_certificate_directory` | Control installation and staging of public DoD certificates for unclassified systems. |
| `win25_stig_legal_notice` | Text applied to the legal-notice registry value. The V1R4 wording is the default. |
| `win25_stig_reboot` | Permit a reboot when remediation marks a restart required. Defaults to false. |

## Scoped account, directory, and platform controls

Inventory variables configure the role from an external project. The per-control
switches and documented exceptions apply to each remediation path.

| Variable | Default | Scope and effect |
| --- | --- | --- |
| `win25_stig_manage_local_password_flags` | `false` | V-278004 for enabled local users on standalone servers and domain members. |
| `win25_stig_manage_domain_password_flags` | `false` | V-278004 for enabled AD users on DCs. Updates are directed to the domain PDC emulator. |
| `win25_stig_password_exempt_accounts` | `[]` | Local names or domain SAM account names for V-278004. Document exceptions separately. Evaluate-STIG still assesses these accounts. |
| `win25_stig_manage_domain_account_policy` | `false` | V-278033/034/035/036/038. Applies 15-minute duration, threshold 1–3, 15-minute reset, history 24, and minimum age of at least one day to the AD default domain password policy through the PDC emulator. Local policy remains managed on non-DC hosts. |
| `win25_stig_manage_forest_ldap_policy` | `false` | V-278147. On a writable DC, sets the forest default query policy idle limit to 300 seconds when missing or out of range. |
| `win25_stig_kdc_strong_name_mappings` | `[]` | V-278173. Supply one owner-approved tuple string per issuer thumbprint to manage the effective KDC registry policy on DCs. An empty list skips remediation. |
| `win25_stig_vbs_platform_security` | `1` | V-278090. Use `1` for Secure Boot or `3` for Secure Boot with DMA protection. Requires the existing `win25_stig_enable_virtualization_security` opt-in and domain membership. |

For example, a project can opt domain members into local password flag
remediation through group vars. A separately approved writable development DC
can opt into the shared directory operations through host vars.

```yaml
# group_vars/windows_members.yml
win25_stig_manage_local_password_flags: true
```

```yaml
# host_vars/dev_dc.yml
win25_stig_manage_domain_password_flags: true
win25_stig_manage_domain_account_policy: true
win25_stig_manage_forest_ldap_policy: true
win25_stig_enable_virtualization_security: true
win25_stig_vbs_platform_security: 3
```

A mapping tuple uses the syntax
`thumbprint; policyOID[, policyOID]; IssuerSubject[, UpnSuffix=domain.example]`.
Have the PKI owner supply and approve every tuple, then confirm the DC's
effective settings and certificate sign-in. Domain GPO can supersede direct
policy changes. Coordinate ownership with the Group Policy administrator and
use the authoritative GPO if required. Fine-grained password policies and
custom LDAP query policies require separate review.

Run shared-directory changes against one approved writable DC per scope.
Targeting the domain PDC emulator directly also avoids relying on remoting
credential delegation. Review the effective lockout settings before applying
them. Windows requires the reset interval to be at most the lockout duration.
If the reset interval currently exceeds 15 minutes, apply V-278035 first,
then apply V-278033. Validate VBS using the Device Guard CIM runtime state after
any owner-approved maintenance reboot. Registry policy alone does not establish
that VBS is running.

## Effective settings and operational limits

- Local security settings apply to the target host. The opt-in domain and forest
  settings have a wider scope and require approval from the directory owner.
  Use the authoritative GPO where it manages these settings.
- Allow the Ansible management port and source network before enabling firewall
  enforcement. The role preserves existing SSH `Match` blocks. Its OpenSSH
  restart handler validates the configuration and verifies reconnection.
- Hardware-dependent controls require supported hardware, firmware and the
  running Windows security feature. Owner decisions such as credential rotation,
  service-account lifecycle, and operational exceptions belong in the existing
  system administration process.
- Run check mode first on an authorized host. Hardware, domain policy, and
  dependent feature changes can affect results. Restart in an approved window
  when the play reports a restart requirement.

## Independent assessment and migration

Use the upstream checks for the applicable benchmark revision and review the
resulting CKLB. The optional bundled answer file adds a V-278207 legal-notice
comment and can resolve native Open when the registry type and approved wording
are verified. Keep the native CKLB and the answer-file CKLB as separate artifacts.
System owners and reviewers handle declarations and administrative determinations
through their existing assessment process. See the [answer-file instructions](files/answer_files/README.md)
for running Evaluate-STIG directly or with the separate development playbook.

When upgrading from the role-managed assessment workflow, update the calling
project as follows. The upgrade removes the role's evidence collection and
reporting tasks, administrative policy inputs, and answer-file generation.

1. Remove references to `tasks_from: assessment`, `tests/evaluate.yml`, and
   the old answer-file generator at `tests/build_answer_file.py`. Retire the
   per-host static register and any XML generated from it.
2. Remove the legacy inputs `win25_stig_organizational_policy`,
   `win25_stig_host_policy`, `win25_stig_administrative_evidence`,
   `win25_stig_evidence_root`, `win25_stig_assessment_archive_root`,
   `win25_stig_evaluator_version`, `win25_stig_evaluator_archive`, and
   `win25_stig_role_revision`. Continue supplying remediation inputs such as
   `win25_stig_time_source` and `win25_stig_exceptions` through inventory.
3. Run the native evaluator using a fresh upstream extraction. Install the
   bundled XML if you want the supplemental legal-notice comparison. Have the
   responsible reviewers revisit prior declarations or overrides against the
   current benchmark.

See the [control map](tests/control-map.md) for remediation coverage.

## Development checks

Install PyYAML, Jinja2, and lxml for the Python checks. Place the upstream
Evaluate-STIG archive containing V1R4 under the role's `files/` directory or
the development repository's top-level `files/` directory. Run these commands
from the role directory.

```bash
python tests/validate_controls.py
python -m unittest discover -s tests -p 'validate*.py'
ansible-playbook -i examples/inventory/hosts.yml tests/test.yml --syntax-check
ansible-lint --offline tasks handlers defaults vars meta tests/test.yml
```

The live regression sequence is check mode, remediation, a second remediation
run to verify idempotence, and an independently executed Evaluate-STIG scan.
Use an explicit limit for each live run.

### Validation status for the scoped changes

The controller-side control validator passed 15 tests and full discovery
passed 17. The remediation test play and the repository assessment play passed
Ansible syntax checks. The answer file passed the upstream XML schema check.
PowerShell parsed the changed scripts, and the legal-notice validator passed
three positive and eight negative fixtures. Ansible lint passed for the
changed YAML with `var-naming[no-role-prefix]` excluded for the existing
`win25_stig_` namespace.

The saved PDC baseline contains 13 Open findings, including all ten scoped
controls, and 35 Not Reviewed findings. Live deployment, a second remediation
run, and a fresh Evaluate-STIG assessment remain pending. The inventory lists
`pdc` and `sdc`, and `--list-hosts --limit pdc` selected only `pdc`. The
system owner still needs to designate an authorized development host, approve
the shared directory changes, and supply the KDC mapping tuples.
