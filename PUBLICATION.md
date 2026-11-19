# Public publication preparation

The existing development Git history is not the public release history: it
contains historical host assessments. Adding ignore rules or deleting files
in the working tree does not remove those objects from Git history.

Use the prepared `.release/win25_disa_stig-public.tar.gz` snapshot to initialize
a new Git repository for public publication. It contains no `.git` directory,
private inventory, assessment evidence or upstream evaluator distribution.
Do not push this development repository's branches or tags to the public remote.
The development role's implementation files are unchanged by this preparation.

The snapshot replaces per-host answer configuration with conspicuous example
identifiers and conservative declarations. Generated answer data is sanitized
consistently. Configure and validate a private site-specific copy before use.
Local baseline-dependent development utilities are excluded from the public
snapshot; the publication manifest lists these exclusions.

The user-removed benchmark/evaluator files remain removed. Full benchmark and
integration tests require local reference packages and authorized Windows hosts;
publication preparation does not claim to rerun those tests.

After extracting the snapshot:

```bash
cd win25_disa_stig
git init -b main
git add .
git commit -m "Initial public release"
# Create the public GitHub repository, then add its remote and push main.
```

Review `PUBLICATION_MANIFEST.json` in the snapshot for included-file hashes,
sanitized data files and excluded development material. Publishing to GitHub
is a separate action; no remote repository or push is performed here.
