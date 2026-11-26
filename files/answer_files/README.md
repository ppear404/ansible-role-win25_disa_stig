# Windows Server 2025 V1R4 Evaluate-STIG answer file

`WinServer2025_AnswerFile.xml` is a ready-to-use custom answer file for
Evaluate-STIG. It supplements the native V-278207 legal-notice check with a
comparison of the configured `REG_SZ` value and the approved benchmark wording.
The comparison collapses whitespace and checks the remaining text, including
case and punctuation. The validation result contributes a comment when the
native result is Open or Not a Finding. Both status override fields are empty.
Evaluate-STIG preserves Open, Not a Finding, Not Applicable, and Not Reviewed
statuses.

## Deploy and run

1. Extract an upstream Evaluate-STIG distribution that contains the Windows
   Server 2025 V1R4 checks. The bundled answer file was validated against
   Evaluate-STIG 1.2610.1.
2. For a native baseline, use a fresh extraction with the upstream contents of
   `Src\Evaluate-STIG\AnswerFiles`. For the optional legal-notice check, copy
   `WinServer2025_AnswerFile.xml` into that directory. Use one Windows Server 2025
   answer file per extraction so the evaluator selects the intended file.
3. From an elevated PowerShell session, create a results directory and run
   Evaluate-STIG using its documented parameters.

```powershell
Set-Location C:\Tools\Evaluate-STIG\Src\Evaluate-STIG
$output = 'C:\STIG\Results'
New-Item -ItemType Directory -Force -Path $output | Out-Null
.\Evaluate-STIG.ps1 -Output CKLB -OutputPath $output
```

Review the evaluator log and CKLB locally. Open and Not Reviewed findings go to
the responsible technical or administrative reviewer under the existing
assessment process. An owner declaration requires owner review.

The remediation role has no answer-file generation step. Use the checked-in
XML as the input, and validate any edited copy against the upstream
`xml\Schema_AnswerFile.xsd` and the exact benchmark rule revision. When the
benchmark version changes, review the rule ID and wording before reuse.

## Repository playbook

In this development repository, `playbooks/run_eval_stig.yml` runs the upstream
evaluator independently of remediation. Supply an explicit inventory limit
and a private controller results directory. For the optional answer, pass its
absolute path through `eval_stig_windows_answer_file`.

```bash
ansible-playbook -i inventory/hosts.yml playbooks/run_eval_stig.yml \
  --limit sdc -e eval_stig_hosts=windows_servers \
  -e "eval_stig_results=/path/to/private/results" \
  -e "eval_stig_windows_answer_file=$PWD/roles/win25_disa_stig/files/answer_files/WinServer2025_AnswerFile.xml"
```

The playbook retrieves the native CKLB, evaluator log, and summaries when
present. Keep those results in the approved location for the system under
assessment.

## Migrate from the static register

Use a fresh upstream extraction for the next assessment, with this XML if the
legal-notice comparison is wanted. Retire earlier generated XML, per-host
static register entries, and the role assessment entry point from active
configuration. Review previous declarations or overrides with the system
owner against the current benchmark before using them in a current assessment.
