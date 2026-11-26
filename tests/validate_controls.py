"""Verify benchmark coverage and policies which can silently undo other controls."""
from pathlib import Path
import re
import json
import os
import subprocess
import tarfile

from jinja2 import Environment
import unittest
import xml.etree.ElementTree as ET

import yaml

ROOT = Path(__file__).resolve().parents[1]
NS = {'x': 'http://checklists.nist.gov/xccdf/1.1'}
DOMAIN_CONDITIONS = {'win25_stig_domain_joined', 'win25_stig_is_dc'}


def load(path):
    return yaml.safe_load((ROOT / path).read_text())


class BenchmarkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.archive = next((ROOT / 'files').glob('evaluate-stig-*.tar.gz'), None)
        if cls.archive is None:
            cls.archive = next((ROOT.parent.parent / 'files').glob('evaluate-stig-*.tar.gz'))
        xml = next((ROOT / 'files').rglob('*xccdf.xml'), None)
        if xml is None:
            with tarfile.open(cls.archive, 'r:gz') as package:
                member = next(m for m in package.getmembers()
                              if m.name.endswith('/U_MS_Windows_Server_2025_STIG_V1R4_Manual-xccdf.xml'))
                cls.xml = ET.parse(package.extractfile(member))
        else:
            cls.xml = ET.parse(xml)
        cls.groups = {g.attrib['id']: g for g in cls.xml.findall('x:Group', NS)}
        cls.manifest = load('vars/control_manifest.yml')['win25_stig_control_manifest']
        cls.defaults = load('defaults/main.yml')

    def test_complete_benchmark_coverage(self):
        self.assertEqual(set(self.groups), set(self.manifest))
        self.assertEqual(set(self.groups), {p.stem for p in (ROOT / 'tasks').glob('V-*.yml')})
        for control, group in self.groups.items():
            with self.subTest(control=control):
                rule = group.find('x:Rule', NS)
                self.assertEqual(rule.findtext('x:check/x:check-content', namespaces=NS),
                                 self.manifest[control]['check'])
                self.assertEqual(rule.findtext('x:fixtext', namespaces=NS), self.manifest[control]['fix'])
                self.assertIn('win25_stig_' + control.lower().replace('-', '_'), self.defaults)

    def test_each_control_imported_once_in_correct_category(self):
        def verify_imports(path, joined_gate=False):
            for task in load('tasks/' + path):
                name = task.get('ansible.builtin.import_tasks')
                if not name:
                    continue
                if name.startswith('V-'):
                    control = name[:-4]
                    imports.append(control)
                    category = {'high': 'CAT1', 'medium': 'CAT2', 'low': 'CAT3'}
                    self.assertIn(category[self.manifest[control]['severity']], task['tags'])
                    conditions = load('tasks/' + name)[0]['when']
                    self.assertEqual(bool(DOMAIN_CONDITIONS.intersection(conditions)), joined_gate, control)
                else:
                    verify_imports(name, joined_gate or task.get('when') == 'win25_stig_domain_joined | bool')

        imports = []
        verify_imports('main.yml')
        self.assertCountEqual(imports, self.groups)

    def test_audit_controls_do_not_undo_each_other(self):
        policies = {}
        for p in (ROOT / 'tasks').glob('V-*.yml'):
            for task in yaml.safe_load(p.read_text())[0]['block']:
                policy = task.get('ansible.windows.win_audit_policy_system')
                if policy:
                    flags = set(policy['audit_type'])
                    subcategory = policy['subcategory']
                    if subcategory in policies:
                        self.assertEqual(policies[subcategory], flags, subcategory)
                    policies[subcategory] = flags
        self.assertEqual(policies['Audit Policy Change'], {'success', 'failure'})
        self.assertNotIn('Audit Audit Policy Change', policies)
        self.assertEqual(policies['Registry'], {'success', 'failure'})
        self.assertEqual(policies['Credential Validation'], {'success', 'failure'})

    def test_manual_controls_do_not_claim_compliance(self):
        for control, data in self.manifest.items():
            if data['implementation'] == 'manual':
                body = load('tasks/' + control + '.yml')[0]['block']
                self.assertTrue(all('ansible.builtin.set_fact' in task for task in body))
                self.assertIn(control, str(body))

    def test_default_notice_wording_matches_bundled_evaluator(self):
        with tarfile.open(self.archive, 'r:gz') as package:
            member = next(m for m in package.getmembers()
                          if m.name.endswith('/Scan-WindowsServer2025_Checks.psm1'))
            code = package.extractfile(member).read().decode('utf-8-sig')
        function = code.split('Function Get-V278207 {', 1)[1]
        expected = re.search(r'^\s*\$RegistryValue = "(.*)"\s+# Value expected', function, re.M).group(1)
        expected = expected.replace('`r`n', '\r\n')
        expression = load('tasks/V-278207.yml')[0]['block'][0]['ansible.windows.win_regedit']['data']
        actual = Environment().from_string(expression).render(**self.defaults)
        self.assertEqual(re.sub(r"\s+", " ", actual).strip(), re.sub(r"\s+", " ", expected).strip())

    def test_legal_notice_answer_file_is_scoped_and_conditional(self):
        tree = ET.parse(ROOT / 'files/answer_files/WinServer2025_AnswerFile.xml')
        root = tree.getroot()
        self.assertEqual(root.attrib['Name'], 'WinServer2025')
        rule_id = self.groups['V-278207'].find('x:Rule', NS).attrib['id']
        self.assertEqual(len([v for v in root.findall('Vuln') if v.attrib['ID'] == rule_id]), 1)
        answers = root.findall("Vuln[@ID='" + rule_id + "']/AnswerKey/Answer")
        self.assertEqual({a.attrib['ExpectedStatus'] for a in answers}, {'O', 'NF'})
        source = (ROOT / 'files/answer_files/Validate-LegalNotice.ps1').read_text().strip()
        for answer in answers:
            self.assertEqual(answer.findtext('ValidationCode').strip(), source)
            self.assertEqual(answer.findtext('ValidTrueStatus'), 'NF')
            self.assertEqual(answer.findtext('ValidFalseStatus'), 'O')
        approved = re.search(r"\$approved = @'\n(.*?)\n'@", source, re.S).group(1)
        self.assertEqual(approved, self.defaults['win25_stig_legal_notice'])

    def test_domain_member_settings_skip_standalone_servers(self):
        for control in ['V-278178', 'V-278179', 'V-278181']:
            self.assertIn('win25_stig_domain_joined', load('tasks/' + control + '.yml')[0]['when'])
            self.assertIn('win25_stig_domain_joined', self.manifest[control]['conditions'])

    def test_security_policy_and_advanced_audit_dependencies_precede_categories(self):
        imports = [task.get('ansible.builtin.import_tasks') for task in load('tasks/main.yml')]
        self.assertLess(imports.index('security_policy.yml'), imports.index('V-278199.yml'))
        self.assertLess(imports.index('V-278199.yml'), imports.index('cat1.yml'))
        self.assertLess(imports.index('V-278199.yml'), imports.index('cat2.yml'))

    def test_required_ssh_service_has_an_enabled_firewall_rule(self):
        body = load('tasks/V-285313.yml')[0]['block']
        rules = [t['ansible.windows.win_firewall_rule'] for t in body
                 if 'ansible.windows.win_firewall_rule' in t]
        self.assertEqual(len(rules), 1)
        self.assertEqual(str(rules[0]['localport']), '22')
        self.assertEqual(rules[0]['action'], 'allow')
        self.assertTrue(rules[0]['enabled'])

    def test_ssh_restart_validates_configuration_and_reconnects(self):
        handlers = load('handlers/main.yml')
        selected = [t for t in handlers if t.get('listen') == 'Validate and restart OpenSSH']
        self.assertIn('ansible.windows.win_command', selected[0])
        restart = next(t for t in selected if 'ansible.windows.win_service' in t)
        self.assertIn('async', restart)
        self.assertEqual(restart['poll'], 0)
        self.assertTrue(any('ansible.builtin.wait_for_connection' in t for t in selected))
        self.assertTrue(any('ansible.builtin.async_status' in t for t in selected))

    def test_windows_module_arguments_match_installed_collection(self):
        calls = []
        for path in (ROOT / 'tasks').glob('V-*.yml'):
            for task in yaml.safe_load(path.read_text())[0]['block']:
                for module, arguments in task.items():
                    if module.startswith(('ansible.windows.', 'community.windows.')):
                        calls.append((path.name, module, arguments))
        modules = sorted({module for _, module, _ in calls})
        environment = dict(os.environ, ANSIBLE_LOCAL_TEMP='/tmp/ansible-win25-tests')
        result = subprocess.run(['ansible-doc', '--json', *modules], env=environment,
                                capture_output=True, text=True, check=True)
        docs = json.loads(result.stdout)
        for filename, module, arguments in calls:
            options = docs[module]['doc']['options']
            accepted = set(options)
            for option in options.values():
                accepted.update(option.get('aliases', []))
            with self.subTest(file=filename, module=module):
                self.assertFalse(set(arguments) - accepted,
                                 f'Unsupported arguments: {set(arguments) - accepted}')

    def test_firewall_preserves_management_before_enablement(self):
        body = load('tasks/V-278012.yml')[0]['block']
        self.assertIn('ansible.windows.win_firewall_rule', body[0])
        self.assertIn('ansible.windows.win_firewall', body[1])

    def test_ssh_install_precedes_category_one_configuration(self):
        imports = [task.get('ansible.builtin.import_tasks') for task in load('tasks/main.yml')]
        self.assertLess(imports.index('V-285313.yml'), imports.index('cat1.yml'))

    def test_ssh_preserves_all_match_blocks(self):
        for p in (ROOT / 'tasks').glob('V-285*.yml'):
            for task in yaml.safe_load(p.read_text())[0]['block']:
                script = task.get('ansible.windows.win_powershell', {}).get('script', '')
                if '$parts' in script:
                    self.assertIn("[regex]::new('(?im)(?=^Match\\s)').Split($text, 2)", script)
                    self.assertIn('$updated += $parts[1]', script)
                    self.assertNotIn('[regex]::Split($text', script)


if __name__ == '__main__':
    unittest.main()
