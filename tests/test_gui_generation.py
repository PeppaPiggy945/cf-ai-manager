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


if __name__ == '__main__':
    unittest.main()
