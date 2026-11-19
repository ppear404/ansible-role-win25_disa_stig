# Source material and third-party notices

The MIT-0 license covers this repository's role implementation and supporting
original material. It does not replace notices attached to upstream content.

- Windows Server 2025 DISA STIG V1R4 supplies vulnerability identifiers and the
  check/fix reference text preserved in `vars/control_manifest.yml`.
- Evaluate-STIG 1.2610.1 is an external assessment prerequisite, not bundled in
  the public snapshot. Obtain its distribution and retain its accompanying
  notices when using it locally.
- Public DoD certificates are included under `files/certificates`. Their
  official source URLs, fingerprints and validation provenance are documented
  in that directory's README. They contain public certificates, not private keys.
- Ansible collections are declared in `requirements.yml` and retain their own
  licenses.

No host assessment reports, inventories, passwords or private keys are included
in the prepared public snapshot. This project does not claim official DISA,
DoD or Microsoft endorsement.
