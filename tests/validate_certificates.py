"""Check pinned payloads, root PEM fidelity and cross-certificate separation."""
import hashlib
from pathlib import Path
import re
import subprocess
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]


class CertificateTests(unittest.TestCase):
    def test_payload_identity_and_constraints(self):
        entries = yaml.safe_load((ROOT / 'vars/certificates.yml').read_text())['win25_stig_certificates']
        self.assertEqual(len(entries), 8)
        pem = (ROOT / 'files/sssd_dod_roots.pem').read_bytes()
        self.assertNotIn(b'PRIVATE KEY', pem)
        blocks = re.findall(b'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', pem, re.S)
        self.assertEqual(len(blocks), 4)
        roots = {subprocess.check_output(['openssl', 'x509', '-outform', 'DER'], input=b) for b in blocks}
        root_keys = {}
        cross = []
        for item in entries:
            path = ROOT / 'files/certificates' / item['file']
            der = path.read_bytes()
            self.assertEqual(hashlib.sha256(der).hexdigest().upper(), item['sha256'])
            self.assertEqual(hashlib.sha1(der).hexdigest().upper(), item['thumbprint'])
            args = ['openssl', 'x509', '-inform', 'DER', '-in', str(path)]
            subprocess.run(args + ['-checkend', '0', '-noout'], check=True, capture_output=True)
            text = subprocess.check_output(args + ['-text', '-noout'], text=True)
            self.assertIn('CA:TRUE', text)
            self.assertIn('Certificate Sign', text)
            key = subprocess.check_output(args + ['-pubkey', '-noout'])
            if item['kind'] == 'root':
                self.assertIn(der, roots)
                self.assertEqual(item['subject_cn'], item['issuer_cn'])
                self.assertEqual(item['control'], 'V-278192')
                root_keys[item['subject_cn']] = key
            else:
                self.assertNotIn(der, roots)
                self.assertNotEqual(item['subject_cn'], item['issuer_cn'])
                self.assertIn('Interoperability', item['issuer_cn'])
                cross.append((item, key))
        self.assertEqual(len(root_keys), 4)
        for item, key in cross:
            self.assertEqual(key, root_keys[item['subject_cn']])

    def test_cross_certificates_only_imported_to_disallowed(self):
        for control in ['278193', '278194']:
            tasks = yaml.safe_load((ROOT / f'tasks/V-{control}.yml').read_text())[0]['block']
            stores = [t['ansible.windows.win_certificate_store'] for t in tasks
                      if 'ansible.windows.win_certificate_store' in t]
            self.assertEqual([s['state'] for s in stores], ['absent', 'present'])
            self.assertEqual(stores[-1]['store_name'], 'Disallowed')
            self.assertIn("['LocalMachine', 'CurrentUser']", tasks[-1]['loop'])


if __name__ == '__main__':
    unittest.main()
