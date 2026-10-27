import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QFontDatabase, QFont
from cfai.config import Profile, Store
from cfai.gui import Window


class GenerationUITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        font = Path(__file__).resolve().parents[1] / 'resources/fonts/NotoSansCJKsc-Regular.otf'
        if font.exists():
            font_id = QFontDatabase.addApplicationFont(str(font))
            cls.app.setFont(QFont(QFontDatabase.applicationFontFamilies(font_id)[0], 10))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        store = Store(Path(self.temp.name))
        self.profile = Profile('fixture', 'node.example.org', '11111111-2222-4333-8444-555555555555')
        store.save_profiles([self.profile])
        self.window = Window(store, demo=True)
        self.addCleanup(self.window.close)

    def test_generation_cancelled_does_not_touch_pool_and_chosen_path_is_forwarded(self):
        self.window.command = Mock()
        with patch('cfai.gui.QFileDialog.getSaveFileName', return_value=('', '')):
            self.window.generate()
        self.window.command.assert_not_called()
        destination = str(Path(self.temp.name) / '导入 Clash')
        with patch('cfai.gui.QFileDialog.getSaveFileName', return_value=(destination, '')):
            self.window.generate()
        self.window.command.assert_called_once_with('dynamic', destination + '.yaml')

    def test_generated_notice_does_not_automatically_launch_explorer(self):
        destination = str(Path(self.temp.name) / 'dynamic.yaml')
        with patch('cfai.gui.QMessageBox.exec', return_value=0), patch('cfai.gui.QDesktopServices.openUrl') as open_url:
            self.window.handle_event('generated', destination)
        open_url.assert_not_called()
        self.assertIn(destination, self.window.status.text())

    def test_hold_shows_live_metrics_and_distinguishes_probe_from_discovery(self):
        import time
        now=time.time();current='CF-104.16.1.1'
        state={'state':'hold','current':current,'healthy':3,'backups_ready':True,
               'last_probe_at':now,'last_scan_at':now-18000,'next_scan_at':now+68400,
               'message':'手动保持：继续监测，不自动切换',
               'stats':{current:{'median':200,'first_request':1100,'score':90,'fresh':True,'last_at':now,'samples':3}}}
        self.window.show_state(state)
        self.assertEqual(self.window.metrics['latency'].text(),'200 ms')
        self.assertEqual(self.window.metrics['first_request'].text(),'1100 ms')
        self.assertEqual(self.window.metrics['score'].text(),'90.0')
        self.assertEqual(self.window.metrics['healthy'].text(),'3')
        self.assertIn('最近探测',self.window.monitor_status.text())
        self.assertIn('上次完整优选',self.window.monitor_status.text())
        self.assertIn('下次自动优选',self.window.monitor_status.text())
        self.window.show_state(state)
        self.assertEqual(len(self.window.spark.values),1)
        state['stats'][current].update(fresh=False)
        self.window.show_state(state)
        self.assertEqual(self.window.metrics['latency'].text(),'待探测')

    def test_startup_check_reports_windows_block_without_reenabling_it(self):
        state={'registered':True,'correct':False,'legacy':True,'disabled':True,'path':'fixture.lnk'}
        self.window.preferences['startup']=True
        with patch.object(self.window,'demo',False), patch('cfai.gui.sys.frozen',True,create=True), \
             patch('cfai.startup.inspect',return_value=state), patch('cfai.startup.configure') as configure:
            self.window.refresh_startup(migrate=True)
        configure.assert_not_called()
        self.assertIn('Windows 已禁用',self.window.startup_status.text())

    def test_export_routing_controls_roundtrip(self):
        from cfai.gui import SettingsDialog
        dialog = SettingsDialog(self.window, self.profile.settings)
        self.addCleanup(dialog.close)
        dialog.controls['reject_foreign_quic'].setChecked(False)
        dialog.controls['extra_direct_domains'].setPlainText('game.example.com\ncdn.example.com')
        dialog.controls['extra_direct_processes'].setPlainText('国服.exe')
        dialog.save()
        self.assertIsNotNone(dialog.result_settings)
        self.assertFalse(dialog.result_settings.reject_foreign_quic)
        self.assertEqual(dialog.result_settings.extra_direct_domains, ['game.example.com', 'cdn.example.com'])
        self.assertEqual(dialog.result_settings.extra_direct_processes, ['国服.exe'])


if __name__ == '__main__':
    unittest.main()
