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

Set `win25_stig_time_source` in inventory/group/host variables or with `-e` to an environment NTP hostname or IP. Per the owner, any nonempty value is designated approved; no separate DoW-hostname allowlist is required. The role configures the NTP client and restarts Windows Time only when configuration changes. Matching peers and a running service produce Not a Finding. Blank leaves configuration unchanged and does not approve an existing source. Use the same variable for both role execution and `tests/evaluate.yml`. The evaluator renders `templates/WinServer2025_AnswerFile.xml.j2` with that value and archives the exact rendered file; the checked-in XML is the blank-variable reference.

```bash
ansible-playbook tests/test.yml --limit win25-1 --tags V-278029 -e win25_stig_time_source=ntp.example.internal --ask-pass
ansible-playbook tests/evaluate.yml --limit win25-1 -e win25_stig_time_source=ntp.example.internal --ask-pass
```
