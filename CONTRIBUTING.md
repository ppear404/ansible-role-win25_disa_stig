# Contributing

Keep changes scoped to the applicable vulnerability task and preserve its
benchmark check/fix references. Use SSH with PowerShell for the documented
Windows development workflow. Never submit inventory credentials or assessment
artifacts.

For behavior changes, record the benchmark revision and rule ID, add meaningful
regression coverage, run syntax/lint checks, inspect check-mode predictions,
apply only to an authorized development host, repeat to verify idempotence,
and reassess effective state. Keep private integration evidence outside Git.

Some validation tools require locally supplied Windows Server 2025 V1R4 XCCDF
and Evaluate-STIG 1.2610.1 reference distributions. These packages and host
assessments are not included in the public snapshot. List unavailable checks
explicitly instead of reporting them as passed.
