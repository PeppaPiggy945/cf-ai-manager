import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cfai import startup


@unittest.skipUnless(os.name == 'nt', 'Windows logon shortcut contract')
class StartupTests(unittest.TestCase):
    def test_shortcut_roundtrip_quotes_paths_and_can_be_disabled_without_touching_system_entries(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            executable = folder / '工具 $ and & spaces' / 'CFAI.exe'
            executable.parent.mkdir(); executable.write_bytes(b'fixture: never executed')
            data_dir = folder / 'profile data 中文'
            shortcut = folder / 'Startup' / 'CFAIManager.lnk'
            legacy = {'command': 'old exe --tray'}
            with patch('cfai.startup.shortcut_path', return_value=shortcut), \
                 patch('cfai.startup.legacy_command', side_effect=lambda: legacy['command']), \
                 patch('cfai.startup.remove_legacy', side_effect=lambda: legacy.update(command=None)), \
                 patch('cfai.startup.disabled', return_value=False):
                state = startup.configure(True, executable, data_dir)
                self.assertTrue(state['registered']); self.assertTrue(state['correct'])
                self.assertFalse(state['legacy'])
                info = startup.shortcut_info(shortcut)
                self.assertEqual(Path(info['target']), executable)
                self.assertEqual(Path(info['working_directory']), executable.parent)
                self.assertEqual(info['arguments'], startup.arguments(data_dir))
                self.assertIn('--autostart', info['arguments'])
                self.assertIn(str(data_dir), info['arguments'])
                state = startup.configure(False, executable, data_dir)
                self.assertFalse(shortcut.exists()); self.assertFalse(state['registered'])

    def test_failed_shortcut_verification_preserves_legacy_entry(self):
        with tempfile.TemporaryDirectory() as d:
            executable = Path(d) / 'CFAI.exe'; executable.touch()
            with patch('cfai.startup.shortcut_path', return_value=Path(d) / 'Startup/CFAIManager.lnk'), \
                 patch('cfai.startup.shortcut_info', return_value={}), \
                 patch('cfai.startup.remove_legacy') as remove:
                with self.assertRaises(ValueError): startup.configure(True, executable, Path(d))
                remove.assert_not_called()

    def test_windows_disabled_state_is_reported_instead_of_claiming_success(self):
        with tempfile.TemporaryDirectory() as d:
            executable = Path(d) / 'CFAI.exe'
            shortcut = Path(d) / 'CFAIManager.lnk'; shortcut.touch()
            with patch('cfai.startup.shortcut_path', return_value=shortcut), \
                 patch('cfai.startup.shortcut_info', return_value={'target': str(executable), 'arguments': startup.arguments(Path(d))}), \
                 patch('cfai.startup.legacy_command', return_value=None), \
                 patch('cfai.startup.disabled', return_value=True):
                state = startup.inspect(executable, Path(d))
            self.assertTrue(state['disabled'])
            self.assertIn('Windows 已禁用', startup.describe(state))

    def test_early_startup_failure_is_recorded_without_credentials(self):
        import app
        from cfai.config import read_json
        with tempfile.TemporaryDirectory() as d, patch.object(app, '_BOOT_ROOT', Path(d)), \
             patch.object(app, '_BOOT_STATE', {'started_at': 123, 'mode': 'autostart', 'pid': 1}):
            app.record_startup('starting')
            app.record_startup('failed', 'ImportError')
            report = read_json(Path(d) / 'last-startup.json')
            self.assertEqual(report['phase'], 'failed')
            self.assertEqual(report['error_type'], 'ImportError')
            self.assertEqual(report['mode'], 'autostart')


if __name__ == '__main__':
    unittest.main()
