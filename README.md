# Windows Server 2025 DISA STIG remediation

This Ansible role applies technical controls from the Windows Server 2025
V1R4 benchmark. It implements 221 of the benchmark's 291 controls, including
conditional and opt-in remediation. The control manifest retains the original
benchmark check and fix text. A successful play establishes which Ansible tasks
ran. Evaluate-STIG independently assesses the effective Windows configuration.

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
| `win25_stig_manage_local_password_flags`, `win25_stig_password_exempt_accounts` | Opt in to local password-flag remediation and identify accounts excluded from it. |
| `win25_stig_manage_defender` | Defaults to true. Set false where an approved third-party product handles this control. |
| `win25_stig_ftp_required`, `win25_stig_bluetooth_required` | Retain features needed by the host. Both default to false. |
| `win25_stig_enable_virtualization_security`, `win25_stig_enable_credential_guard_uefi_lock`, `win25_stig_exchange_server` | Opt in to registry configuration for virtualization security and UEFI lock, or identify an Exchange server. All default to false. |
| `win25_stig_enforce_remote_uac` | Apply remote UAC restrictions. Defaults to true. |
| `win25_stig_transcript_directory` | Local PowerShell transcript directory, defaulting to `C:\ProgramData\PS_Transcript`. |
| `win25_stig_unclassified`, `win25_stig_certificate_directory` | Control installation and staging of public DoD certificates for unclassified systems. |
| `win25_stig_legal_notice` | Text applied to the legal-notice registry value. The V1R4 wording is the default. |
| `win25_stig_reboot` | Permit a reboot when remediation marks a restart required. Defaults to false. |

## Effective settings and operational limits

- The role applies local security settings. Manage domain account and Kerberos
  policy and directory ACLs through the authoritative domain administration
  process. Domain GPO refresh can override settings applied locally.
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

Run the upstream evaluator separately after remediation. Use the
[answer-file instructions](files/answer_files/README.md) for installation,
assessment execution, and the custom legal-notice validation.

Remove calls to `include_role` with `tasks_from: assessment`. Remove
`win25_stig_organizational_policy`, `win25_stig_host_policy`,
`win25_stig_administrative_evidence`, `win25_stig_evidence_root`,
`win25_stig_assessment_archive_root`, `win25_stig_evaluator_version`,
`win25_stig_evaluator_archive`, and `win25_stig_role_revision` from the
calling project. Retain technical inputs such as
`win25_stig_time_source` and `win25_stig_exceptions`. Replace the previous
generated Windows Server 2025 answer file with the bundled XML where the
legal-notice check is wanted. Route declarations and controls requiring human
judgment through your existing owner and reviewer process.

## Development checks

Install PyYAML, Jinja2, and lxml for the Python checks. With an upstream
package for V1R4 available under `files/`, run:

```bash
python tests/validate_controls.py
python -m unittest discover -s tests -p 'validate*.py'
ansible-playbook -i examples/inventory.yml tests/test.yml --syntax-check
ansible-lint --offline tasks handlers defaults vars meta tests/test.yml
```

The live regression sequence is check mode, remediation, a second remediation
run to verify idempotence, and an independently executed Evaluate-STIG scan.
Use an explicit limit for each live run.
