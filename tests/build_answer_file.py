"""Build deterministic, self-contained manual review entries alongside the legal-notice check."""
from pathlib import Path
import json
import re
import tarfile
import hashlib
import base64
from lxml import etree as ET

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'files/answer_files'



def scoped_source(source, control):
    starts = list(re.finditer(r'(?m)^function ([\w-]+) \{', source))
    functions = {m[1]: source[m.start():starts[i + 1].start() if i + 1 < len(starts) else len(source)].strip()
                 for i, m in enumerate(starts)}
    collector = functions['Get-ManualControlEvidence']
    cases = list(re.finditer(r"(?m)^        (?:'V-\d+'|\{ \$_ -in @\([^\n]*\) \}|default) \{", collector))
    selected = [collector[m.start():cases[i + 1].start()] for i, m in enumerate(cases[:-1])
                if "'" + control + "'" in m[0]]
    assert len(selected) == 1, control
    collector = ("function Get-ManualControlEvidence {\n    param([string]$Control, [hashtable]$Policy)\n"
                 "    switch ($Control) {\n" + selected[0] + "        default { throw 'Unsupported control' }\n    }\n}")
    names = ['Test-ManualControlEvidence', 'Invoke-ScopedManualReview']
    if control in ['V-277985', 'V-278177']:
        names.append('Get-ApprovedAdminEvidence')
    if control in ['V-278041', 'V-278042', 'V-278106']:
        names.append('Get-UniversalForwarderEvidence')
    if control == 'V-278029':
        names.append('Test-ConfiguredTimeSource')
    if control == 'V-278240':
        names.append('Get-ZonePreservationEvidence')
    header = '# ManualChecks.ps1 SHA256: ' + hashlib.sha256(source.encode()).hexdigest() + '\n'
    return header + '\n\n'.join(functions[n] for n in names) + '\n\n' + collector


def domain_answer(rule, script, passed, failed):
    vuln = ET.Element('Vuln', ID=rule)
    key = ET.SubElement(vuln, 'AnswerKey', Name='DEFAULT')
    answer = ET.SubElement(key, 'Answer', Index='1', ExpectedStatus='NR')
    ET.SubElement(answer, 'ValidationCode').text = ET.CDATA((BASE / script).read_text())
    ET.SubElement(answer, 'ValidTrueStatus').text = 'NF'
    ET.SubElement(answer, 'ValidTrueComment').text = passed
    ET.SubElement(answer, 'ValidFalseStatus').text = 'O'
    ET.SubElement(answer, 'ValidFalseComment').text = failed
    return vuln


def evaluator_archive():
    filename = 'evaluate-stig-1.2610.1.tar.gz'
    return next(directory / filename for directory in (ROOT / 'files', ROOT.parent.parent / 'files')
                   if (directory / filename).is_file())


def standalone_rules(policies):
    checklist = ROOT / 'files/cklbs/WIN25-CORE-V0_WinServer2025_V1R4_20261119-015833.cklb'
    if checklist.exists():
        rules = json.loads(checklist.read_text())['stigs'][0]['rules']
        return {r['group_id']: r for r in rules if r['status'] == 'not_reviewed'}
    with tarfile.open(evaluator_archive()) as package:
        member = next(m for m in package.getmembers()
                      if m.name.endswith('/U_MS_Windows_Server_2025_STIG_V1R4_Manual-xccdf.xml'))
        xml = ET.parse(package.extractfile(member))
    return {g.get('id'): {'rule_id_src': g.find('{*}Rule').get('id')}
            for g in xml.findall('{*}Group') if g.get('id') in policies}


def build():
    tree = ET.parse(str(BASE / 'WinServer2025_AnswerFile.xml'))
    root = tree.getroot()
    for node in list(root):
        if isinstance(node.tag, str) and node.attrib.get('ID') != 'SV-278207r1268215_rule':
            root.remove(node)
    source = (BASE / 'manual/ManualChecks.ps1').read_text().strip()
    register = (BASE / 'manual/site-register.json').read_text().strip()
    policies = json.loads((BASE / 'manual/policies.json').read_text())
    selected = standalone_rules(policies)
    assert set(selected) == set(policies)
    scripts = {}
    for control, policy in policies.items():
        rule = selected[control]
        code = scoped_source(source, control) + "\n\ntry {\n    $ErrorActionPreference = 'Stop'\n    $Policy = @{}\n    $register = @'\n" + register + "\n'@\n"
        code += "    ($register | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $Policy[$_.Name] = $_.Value }\n"
        code += f"    return Invoke-ScopedManualReview -Control '{control}' -Policy $Policy\n"
        code += "} catch {\n    return @{ Valid = $false; Results = 'Custom review failed closed: ' + $_.Exception.Message }\n}\n"
        assert len(base64.b64encode(code.encode('utf-16-le'))) < 28000, control
        scripts[control] = code
        vuln = ET.SubElement(root, 'Vuln', ID=rule['rule_id_src'])
        key = ET.SubElement(vuln, 'AnswerKey', Name='DEFAULT')
        answer = ET.SubElement(key, 'Answer', Index='1', ExpectedStatus='NR')
        ET.SubElement(answer, 'ValidationCode').text = ET.CDATA(code)
        ET.SubElement(answer, 'ValidTrueStatus').text = policy['pass_status']
        ET.SubElement(answer, 'ValidTrueComment').text = policy['procedure']
        ET.SubElement(answer, 'ValidFalseStatus').text = 'O'
        ET.SubElement(answer, 'ValidFalseComment').text = ('Required evidence did not pass; this is Open, not an approved exception. ' + policy['procedure'])
    root.append(domain_answer('SV-278144r1182094_rule', 'Validate-DedicatedDc.ps1',
                              'Review installed roles and applications after software changes. VirtIO guest tools support active virtual devices on this DC.',
                              'Review additional roles and applications for operational necessity and remove unrelated workloads.'))
    root.append(domain_answer('SV-278146r1268251_rule', 'Validate-AnonymousLdap.ps1',
                              'Verify anonymous bind and rejection of domain naming context searches after directory access policy changes.',
                              'Review anonymous access and repeat the domain naming context search.'))
    root.append(domain_answer('SV-278159r1182124_rule', 'Validate-DcCertificate.ps1',
                              'Verify that the personal certificate identifies the controller and renew it before expiration.',
                              'Inspect the machine personal store and provision a valid certificate for this controller.'))
    directory_objects = {
        'SV-278149r1182104_rule': '',
        'SV-278150r1211157_rule': 'CN=Infrastructure',
        'SV-278151r1182108_rule': 'OU=Domain Controllers',
        'SV-278152r1211160_rule': 'CN=AdminSDHolder,CN=System',
        'SV-278153r1182112_rule': 'CN=RID Manager$,CN=System',
    }
    for rule, relative_dn in directory_objects.items():
        node = domain_answer(rule, 'Review-DirectoryAudit.ps1',
                             'Review the explicit and inherited audit entries against the object-specific benchmark requirements.',
                             'Add the required explicit Everyone failure auditing entry through directory change control.')
        answer = node.find('AnswerKey/Answer')
        answer.find('ValidTrueStatus').text = 'NR'
        descendants = '$true' if rule.startswith('SV-278151') else '$false'
        code = answer.find('ValidationCode')
        code.text = ET.CDATA(f"$relativeDn = '{relative_dn}'\n$allDescendants = {descendants}\n" + code.text)
        root.append(node)
    for comment in tree.xpath('//comment()'):
        comment.text = ' Windows Server 2025 V1R4: conditional legal-notice check and scoped manual-control reviews. '
    tree.write(str(BASE / 'WinServer2025_AnswerFile.xml'), encoding='utf-8', xml_declaration=True, pretty_print=True)
    templates = ROOT / 'templates'
    templates.mkdir(exist_ok=True)
    template = (BASE / 'WinServer2025_AnswerFile.xml').read_text().replace(
        '"approved_ntp_sources": []',
        '"approved_ntp_sources": {{ ([win25_stig_time_source] if win25_stig_time_source | default("") | length > 0 else []) | to_json }}')
    (templates / 'WinServer2025_AnswerFile.xml.j2').write_text(template)
    (BASE / 'manual/checks.json').write_text(json.dumps(scripts, indent=2) + '\n')
    lines = ['# Windows Server 2025 development-server security-plan procedures', '',
             'Scope: WIN25-CORE-V0, machine SID ' + json.loads(register)['machine_sid'] + '.', '',
             'Temporary, emergency and shared-account non-use is the system-owner declaration from this task. Other procedures are created under AGENTS.MD for inclusion in the security plan. Technical protections are checked independently; documenting a procedure does not establish that an absent protection is installed.', '']
    for control, policy in policies.items():
        lines += ['## ' + control + ' — ' + selected[control]['rule_id_src'], '', policy['procedure'], '',
                  'Source: `vars/control_manifest.yml` and `files/disa_stigs/U_MS_Windows_Server_2025_V1R4_STIG.zip`; native evaluator `Scan-WindowsServer2025_Checks.psm1`, function `Get-' + control.replace('-', '') + '` when present; otherwise a manual benchmark check.', '']
    lines += ['## Per-host register', '', '```json', register, '```', '',
              'Required feature purposes: file/storage roles support the OS storage stack; .NET 4.8/WCF/TCP Port Sharing support the documented installed framework; Defender provides antivirus; System Data Archiver supports system data collection; Windows PowerShell supports administration and Ansible; WoW64 supports installed 32-bit compatibility. Review this register when changing the server workload.', '']
    (BASE / 'manual/SecurityPlanProcedures.md').write_text('\n'.join(lines))


if __name__ == '__main__':
    build()
