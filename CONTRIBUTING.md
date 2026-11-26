# Contributing

Keep changes scoped to the applicable vulnerability task and preserve its
benchmark check/fix references. Use SSH with PowerShell for the documented
Windows development workflow. Never submit inventory credentials or assessment
artifacts.

For behavior changes, record the benchmark revision and rule ID, add meaningful
regression coverage, run syntax/lint checks, inspect check-mode predictions,
apply only to an authorized development host with an explicit inventory limit,
and repeat to verify idempotence. Assess the effective configuration with the
unmodified upstream Evaluate-STIG and review its findings. Follow the
[answer-file instructions](files/answer_files/README.md) when testing the
optional legal-notice comparison.

Some validation tools require locally supplied Windows Server 2025 V1R4 XCCDF
and Evaluate-STIG 1.2610.1 reference distributions. These packages and host
assessments are not included in the public snapshot. List unavailable checks
explicitly instead of reporting them as passed.
