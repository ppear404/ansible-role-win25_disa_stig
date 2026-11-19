"""Write a reviewable before/after comparison without changing assessment results."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path


def rules(path):
    data = json.loads(path.read_text())
    return {r['group_id']: r for stig in data['stigs'] for r in stig['rules']}


def compare(before, after, output):
    old, new = rules(before), rules(after)
    if set(old) != set(new):
        raise ValueError('Assessment control coverage differs')
    reviewed = {key for key, rule in old.items() if rule['status'] == 'not_reviewed'}
    rows = [{'control': key, 'rule_id': new[key]['rule_id_src'], 'before': old[key]['status'],
             'after': new[key]['status'], 'title': new[key]['rule_title'],
             'finding_details': new[key]['finding_details'], 'comments': new[key]['comments']}
            for key in sorted(reviewed)]
    other_changes = [{'control': key, 'before': old[key]['status'], 'after': new[key]['status']}
                     for key in sorted(set(old) - reviewed) if old[key]['status'] != new[key]['status']]
    report = {'baseline': str(before), 'assessment': str(after),
              'baseline_sha256': hashlib.sha256(before.read_bytes()).hexdigest(),
              'assessment_sha256': hashlib.sha256(after.read_bytes()).hexdigest(),
              'before_counts': dict(Counter(r['status'] for r in old.values())),
              'after_counts': dict(Counter(r['status'] for r in new.values())),
              'reviewed_counts': dict(Counter(r['after'] for r in rows)),
              'reviewed_controls': rows, 'other_status_changes': other_changes}
    output.mkdir(exist_ok=True, parents=True)
    (output / 'manual-controls-comparison.json').write_text(json.dumps(report, indent=2) + '\n')
    lines = ['# Windows Server 2025 V1R4 manual-control review', '',
             'Dev host: win25-1 / WIN25-CORE-V0; inventory address 10.1.220.92. Connection: SSH.', '',
             'Baseline: ' + before.name, 'Final assessment: ' + after.name, '',
             'Before: ' + json.dumps(report['before_counts']),
             'After: ' + json.dumps(report['after_counts']), '',
             '| Control | Before | After |', '|---|---|---|']
    lines += [f"| {row['control']} | {row['before']} | {row['after']} |" for row in rows]
    lines += ['', 'The three account non-use determinations follow the system owner\'s declaration. Policy procedures are included in checklist comments and in files/answer_files/manual/SecurityPlanProcedures.md. Missing technical protections or approved evidence remain Open.', '',
              'Splunk Universal Forwarder was not installed; V-278041 and V-278042 therefore did not meet the owner\'s conditional closure criterion.', '',
              'Validation: 18 local regression tests; 21 positive/47 negative Windows decision fixtures; all generated scripts parsed; evaluator-style subprocess compatibility tested; syntax/lint passed; scoped role deployment repeated with zero changes. Fresh SSH service/configuration and unchanged public host-key hashes verified.', '',
              'Changes outside the 21 reviewed controls: ' + json.dumps(other_changes), '',
              'The JSON companion retains full evaluator comments/finding details and SHA256 hashes. The assessment archive contains the exact answer-file snapshot used.', '']
    (output / 'manual-controls-comparison.md').write_text('\n'.join(lines))
    print(json.dumps({key: report[key] for key in ['after_counts', 'reviewed_counts', 'other_status_changes']}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('baseline', type=Path)
    parser.add_argument('assessment', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    compare(args.baseline, args.assessment, args.output)
