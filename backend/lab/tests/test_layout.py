import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class ManagedLayoutTests(unittest.TestCase):
    def test_profiles_have_strict_proposals(self):
        for profile in range(1, 9):
            config = (ROOT / 'configs' / f'p{profile}.conf').read_text()
            for key in ('ike=', 'esp='):
                lines = [line.strip() for line in config.splitlines() if line.strip().startswith(key)]
                self.assertTrue(lines, (profile, key))
                self.assertTrue(all(line.endswith('!') for line in lines), (profile, key))

    def test_active_scripts_do_not_use_old_host_capture_interfaces(self):
        for script in (ROOT / 'scripts').glob('*.sh'):
            source = script.read_text()
            self.assertNotIn('engine/lab', source)
            self.assertNotIn('sudo ', source)
            self.assertNotIn('ipsec-pcap-lab/', source)

    def test_single_compose_entry(self):
        script = (ROOT / 'scripts' / 'managed.sh').read_text()
        self.assertIn('$ENGINE/compose.yaml', script)
        self.assertTrue((ROOT / 'compose.yaml').is_file())
        self.assertFalse((ROOT / 'engine').exists())

    def test_captures_reject_stale_files_and_failed_tcpdump(self):
        for name in ('one', 'anomaly', 'ood', 'protocol_validation'):
            script = (ROOT / 'scripts' / f'capture_{name}.sh').read_text()
            self.assertIn('docker exec managed-ipsec-left rm -f /tmp/managed-', script)
            self.assertIn('tcpdump -Z root', script)
            self.assertIn('kill -0', script)
            self.assertNotRegex(script, r'wait .*\|\| true')

    def test_required_configuration_axes_are_active(self):
        profiles = [(ROOT / 'configs' / f'p{profile}.conf').read_text() for profile in range(1, 9)]
        combined = '\n'.join(profiles)
        self.assertIn('type=tunnel', combined)
        self.assertIn('type=transport', combined)
        self.assertIn('aes128-', combined)
        self.assertIn('aes256', combined)
        self.assertIn('gcm16', combined)
        self.assertIn('rekey=yes', combined)
        self.assertTrue(any('left=fd00:31::2' in profile for profile in profiles))
