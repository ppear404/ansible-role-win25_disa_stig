# Conditional Windows Server 2025 answer validation

`WinServer2025_AnswerFile.xml` uses answer key `DEFAULT`, pinned to the Windows Server 2025 V1R4 rule revisions. Native finding details remain intact; comments include validation evidence and the security-plan procedure.

V-278207 retains its existing exact wording/type check with whitespace normalization only. Its native Open/Not a Finding entries return Not a Finding only when independent legal-notice validation passes. `Validate-LegalNotice.ps1` remains the source for this check.

The 21 Not Reviewed controls in `files/cklbs/WIN25-CORE-V0_WinServer2025_V1R4_20261119-015833.cklb` have entries matching **only native NR**. They cannot mask a native Open result. New checks are scoped to the computer name and machine SID in `manual/site-register.json`; a different host or missing/failed evidence fails closed to Open. Account non-use determinations are the system owner's explicit declarations, with checks for obvious contradictory local account descriptions/names; these checks do not infer account purpose from names alone.

`manual/SecurityPlanProcedures.md` contains the procedures for inclusion in the security plan, reproduced in full in each answer's comments. Hardware control, administrative account separation and service password provisioning include procedural determinations; their comments identify the policy basis. Technical requirements such as application control, IDPS, encryption and file-integrity monitoring are not passed by merely writing a procedure. Where no registered solution or data-owner evidence exists, the control becomes Open with an explanation.

V-278041/042 follow the owner's explicit criterion: an installed Splunk Universal Forwarder closes them, with backup/offload operating procedures in the comments. Its absence does not pass. V-278106 is separately gated on a running forwarder, an enabled Security input and a configured remote destination; forwarder installation alone does not waive local retention. This configuration check does not attest to downstream receipt or retention; LOG-01/02 require those operational reviews.

`manual/ManualChecks.ps1` implements the read-only collectors and separately testable decisions. `tests/build_answer_file.py` embeds only the required collector/helper functions and the per-host register into every answer so the evaluator requires no external script dependency. Generated code includes the source hash and stays below a conservative encoded subprocess argument limit. It also generates `manual/checks.json` and the procedure document. Regenerate after editing source, register or policy:

```bash
python tests/build_answer_file.py
python -m unittest discover -s tests -p 'validate*.py'
ansible-playbook tests/validate-manual-controls.yml --limit win25-1 --ask-pass
ansible-playbook tests/validate-answer-file.yml --limit win25-1 --ask-pass
```

The role runs the same checks through `tasks/manual_reviews.yml` and deploys the procedure document/register to `C:\ProgramData\win25-stig\Policy`. Individual control files retain unmet controls in the pending report. Check mode predicts document changes and runs the independent checks. Unloaded attachment-policy hives are inspected through temporary copies and unloaded in `finally`; original hives are not modified. No SSH configuration, application allowlist, account credential or encryption setting is changed by the review tasks.

`tests/evaluate.yml` deploys the answer file, passes `-AFPath` and `-AnswerKey DEFAULT`, and archives the exact answer snapshot with the fetched CKLB and reports under `.files/<inventory-host>/<UTC-run-timestamp>/`. Review the policy register and rule revisions before using this answer key on a different host or benchmark release.

Windows tests parse all 21 generated scripts, reproduce the evaluator's child-PowerShell invocation, and exercise 24 positive and 52 negative cases, including wrong-host/SID rejection. The staged fixture file is removed after successful validation.

V-277987 now records the owner's non-Internet-facing declaration and administrative-use policy as Not a Finding. This is a policy determination, not proof of AppLocker or egress filtering. V-278009 records the owner's datastore-encryption declaration as Not Applicable under the benchmark's explicit infrastructure-encryption exception. These declarations and reassessment procedures are in the security-plan document.

For a standalone server or the PDC emulator, set `win25_stig_time_source` in inventory or with `-e` to the approved environment NTP hostname or IP. The answer checks that the configured peers match and Windows Time is running. A blank value leaves external NTP configuration unchanged. Use the same variable for role execution and `tests/evaluate.yml`. The evaluator renders `templates/WinServer2025_AnswerFile.xml.j2` with that value and archives the rendered file. Other domain-joined servers use `NT5DS`, which Evaluate-STIG checks natively on a running Windows Time service.

```bash
ansible-playbook tests/test.yml --limit win25-1 --tags V-278029 -e win25_stig_time_source=ntp.example.internal --ask-pass
ansible-playbook tests/evaluate.yml --limit win25-1 -e win25_stig_time_source=ntp.example.internal --ask-pass
```

### Domain controller reviews

The V1R4 answer file handles native Not Reviewed results for V-278144, V-278146, and V-278159. The role runs the same read-only checks on domain controllers. V-278144 reviews installed server roles and machine-wide installed programs. It recognizes VirtIO guest tools when the DC has a working VirtIO PCI device. Additional workloads require review. V-278146 binds anonymously and searches the domain naming context on the local LDAP server. It requires an explicit access denial. V-278159 checks the local machine personal store for a currently valid certificate with the DC DNS name and a private key. V-278160 separately assesses issuer authorization.

The role installs Group Policy Management on DCs selected for V-278140 or V-278148. The evaluator uses Get-GPO to enumerate policy objects for the permissions and auditing reviews. Review the resulting access and audit entries against the benchmark.

Use this role's generated WinServer2025_AnswerFile.xml for these reviews. A separately maintained copy used by another assessment playbook needs the same updates.

For V-278149 through V-278153, the answer file reads each directory object's audit settings. It marks the control Open when the required explicit Everyone failure-audit entry is absent. Other cases retain Not Reviewed for verification of success auditing, inheritance, and object-specific permissions. The check runs read-only and records collection errors for review.
