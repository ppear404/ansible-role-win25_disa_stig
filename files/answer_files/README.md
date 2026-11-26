# Windows Server 2025 V1R4 Evaluate-STIG answer file

[WinServer2025_AnswerFile.xml](WinServer2025_AnswerFile.xml) is the optional
custom answer file for unmodified upstream Evaluate-STIG. It supplements the
native V-278207 legal-notice check by comparing the `LegalNoticeText` registry
value with the approved benchmark wording and checking that its type is
`REG_SZ`. The comparison normalizes whitespace and checks the remaining text,
including case and punctuation.

The answer file adds a validation comment for native Open and Not a Finding
results and preserves both statuses. Not Applicable and Not Reviewed findings
have no matching answer entry.

## Deploy and run

1. Extract an upstream Evaluate-STIG distribution that contains the Windows
   Server 2025 V1R4 checks. The bundled answer file was validated against
   Evaluate-STIG 1.2610.1.
2. For a native baseline, use the upstream contents of
   `Src\Evaluate-STIG\AnswerFiles`. For the optional legal-notice check, copy
   `WinServer2025_AnswerFile.xml` into that directory. Use one Windows Server
   2025 answer file per extraction so the evaluator selects the intended file.
3. Run the following from an elevated PowerShell session.

```powershell
Set-Location C:\Tools\Evaluate-STIG\Src\Evaluate-STIG
$output = 'C:\STIG\Results'
New-Item -ItemType Directory -Force -Path $output | Out-Null
.\Evaluate-STIG.ps1 -Output CKLB -OutputPath $output
```

Review the evaluator log and CKLB. Route Open and Not Reviewed findings to the
responsible reviewers under the existing assessment process. System owners
review declarations against the applicable benchmark requirements.

Use the checked-in XML as the input. Validate any edited copy against the
upstream `xml\Schema_AnswerFile.xsd` and the exact benchmark rule revision.
When the benchmark version changes, review the rule ID and wording before
reuse. The XML compares against the V1R4 benchmark text even if your inventory
sets a different `win25_stig_legal_notice` for remediation.

## Repository playbook

In this development repository, `playbooks/run_eval_stig.yml` extracts and
runs the upstream evaluator in a fresh workspace on each host. Run it from
the repository root with the upstream archive at
`files/evaluate-stig-1.2610.1.tar.gz`. Supply an explicit limit for the
authorized host and a private controller results directory. Replace
`server01` and `windows_servers` with the host and group from your inventory.

```bash
ansible-playbook -i inventory/hosts.yml playbooks/run_eval_stig.yml \
  --limit server01 -e eval_stig_hosts=windows_servers --list-hosts

ansible-playbook -i inventory/hosts.yml playbooks/run_eval_stig.yml \
  --limit server01 -e eval_stig_hosts=windows_servers \
  -e "eval_stig_results=/path/to/private/results" \
  -e "eval_stig_windows_answer_file=$PWD/roles/win25_disa_stig/files/answer_files/WinServer2025_AnswerFile.xml"
```

For a native baseline, omit `eval_stig_windows_answer_file` from the
assessment invocation. The playbook fetches the CKLB and any evaluator log or
summaries it finds. Use a separate results directory for each comparison run.

## Migrate from the static register

Use a fresh upstream extraction for the next assessment. Add the checked-in
XML if you want the legal-notice comparison. Follow the
[role migration steps](../../README.md#independent-assessment-and-migration)
to retire the static register and removed role settings.
