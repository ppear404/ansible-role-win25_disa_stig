# Public publication preparation

The existing development Git history is not the public release history: it
contains historical host assessments. Adding ignore rules or deleting files
in the working tree does not remove those objects from Git history.

Prepare a fresh snapshot of the current role files to initialize a new Git
repository for public publication. Exclude `.git`, private inventories, host
assessment artifacts, and the upstream evaluator distribution. Do not push
this development repository's branches or tags to the public remote.

Include the checked-in V1R4 legal-notice answer file and its instructions.
Review the snapshot for leftover generated answer files, per-host registers,
and private assessment outputs before publication.

Full benchmark and integration tests require local reference packages and
authorized Windows hosts.

After extracting the snapshot:

```bash
cd win25_disa_stig
git init -b main
git add .
git commit -m "Initial public release"
# Create the public GitHub repository, then add its remote and push main.
```

Record the included-file hashes and exclusions in the publication manifest
before publishing.
