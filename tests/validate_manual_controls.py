"""Scope, schema and source consistency for manual-control answer entries."""
from pathlib import Path
import json
import re
from jinja2 import Environment
import hashlib
import base64
import tarfile
import unittest
from lxml import etree as ET

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'files/answer_files'


class ManualAnswerTests(unittest.TestCase):
    def test_exact_scope_and_self_contained_sources(self):
        tree = ET.parse(str(BASE / 'WinServer2025_AnswerFile.xml'))
        checklist = json.loads((ROOT / 'files/cklbs/WIN25-CORE-V0_WinServer2025_V1R4_20261119-015833.cklb').read_text())
        expected = {r['rule_id_src']: r['group_id'] for r in checklist['stigs'][0]['rules'] if r['status'] == 'not_reviewed'}
        checks = json.loads((BASE / 'manual/checks.json').read_text())
        procedures = json.loads((BASE / 'manual/policies.json').read_text())
        nodes = {v.attrib['ID']: v for v in tree.findall('Vuln')}
        self.assertEqual(set(nodes), set(expected) | {'SV-278207r1268215_rule'})
        for rule, control in expected.items():
            answers = nodes[rule].findall('AnswerKey/Answer')
            self.assertEqual(len(answers), 1)
            answer = answers[0]
            self.assertEqual(answer.attrib['ExpectedStatus'], 'NR')
            self.assertEqual(answer.findtext('ValidationCode'), checks[control])
            self.assertIn(hashlib.sha256((BASE / 'manual/ManualChecks.ps1').read_text().strip().encode()).hexdigest(), checks[control])
            self.assertLess(len(base64.b64encode(checks[control].encode('utf-16-le'))), 28000)
            self.assertIn((BASE / 'manual/site-register.json').read_text().strip(), checks[control])
            self.assertIn('Per-host machine SID mismatch', checks[control])
            self.assertIn('No per-host policy register', checks[control])
            self.assertEqual(answer.findtext('ValidFalseStatus'), 'O')
            self.assertEqual(answer.findtext('ValidTrueComment'), procedures[control]['procedure'])
            self.assertEqual(answer.findtext('ValidTrueStatus'), procedures[control]['pass_status'])
        self.assertEqual({procedures[c]['pass_status'] for c in ['V-277991', 'V-278013', 'V-278014']}, {'NA'})

    def test_environment_time_source_template(self):
        environment = Environment()
        environment.filters['to_json'] = json.dumps
        template = environment.from_string((ROOT / 'templates/WinServer2025_AnswerFile.xml.j2').read_text())
        for value in ['', 'ntp.example.test', '10.1.2.3']:
            rendered = template.render(win25_stig_time_source=value)
            tree = ET.fromstring(rendered.encode())
            node = tree.find("Vuln[@ID='SV-278029r1256714_rule']/AnswerKey/Answer/ValidationCode")
            register = json.loads(re.search(r"\$register = @'\n(.*?)\n'@", node.text, re.S)[1])
            self.assertEqual(register['approved_ntp_sources'], [value] if value else [])
        tree = ET.fromstring(template.render().encode())
        node = tree.find("Vuln[@ID='SV-278029r1256714_rule']/AnswerKey/Answer/ValidationCode")
        self.assertIn('"approved_ntp_sources": []', node.text)

    def test_bundled_evaluator_schema(self):
        with tarfile.open(ROOT / 'files/evaluate-stig-1.2610.1.tar.gz') as archive:
            member = next(m for m in archive.getmembers() if m.name.endswith('/Schema_AnswerFile.xsd'))
            schema = ET.XMLSchema(ET.fromstring(archive.extractfile(member).read()))
        schema.assertValid(ET.parse(str(BASE / 'WinServer2025_AnswerFile.xml')))


if __name__ == '__main__':
    unittest.main()
