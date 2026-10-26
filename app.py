"""Desktop entry point. --self-test and --render-demo never start production monitoring."""
import argparse
import os
from pathlib import Path
import sys
import tempfile
import time


def main():
    parser=argparse.ArgumentParser(description='澄流 · CF AI Manager')
    parser.add_argument('--data-dir',type=Path)
    parser.add_argument('--tray',action='store_true')
    parser.add_argument('--self-test',action='store_true')
    parser.add_argument('--render-demo',type=Path)
    parser.add_argument('--theme',choices=['light','dark'],default='light')
    args=parser.parse_args()
    if args.self_test or args.render_demo:
        os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
    from PySide6.QtCore import QLockFile, QTimer, Qt
    from PySide6.QtWidgets import QApplication, QMessageBox
    from cfai.config import Store, Profile, atomic_json
    from cfai.scanner import check_config, core_path
    from cfai.export import static_config
    from cfai.gui import Window
    application=QApplication(sys.argv[:1])
    application.setApplicationName('CFAIManager')
    application.setOrganizationName('CFAIManager')
    application.setStyle('Fusion')
    from PySide6.QtGui import QFontDatabase, QFont
    resource_root=Path(getattr(sys,'_MEIPASS',Path(__file__).resolve().parent))
    font_path=resource_root/'resources'/'fonts'/'NotoSansCJKsc-Regular.otf'
    if font_path.exists():
        font_id=QFontDatabase.addApplicationFont(str(font_path))
        families=QFontDatabase.applicationFontFamilies(font_id)
        if families:
            application.setFont(QFont(families[0],10))
    temporary=None
    if args.self_test or args.render_demo:
        temporary=tempfile.TemporaryDirectory(prefix='cfai-smoke-')
        store=Store(Path(temporary.name))
    else:
        store=Store(args.data_dir)
        store.protect()
    lock=QLockFile(str(store.root/'application.lock'))
    lock.setStaleLockTime(30000)
    if not lock.tryLock(100):
        QMessageBox.information(None,'澄流','此数据目录已有澄流实例运行，请从系统托盘打开。')
        return 0
    if args.self_test or args.render_demo:
        p=Profile('我的 AI 线路','node.demo.invalid','11111111-2222-4333-8444-555555555555',managed=False)
        store.save_profiles([p])
        rows=[]
        for i,(ip,delay,score,bw) in enumerate([('104.16.1.73',182,94.2,7.1),('104.24.130.121',196,92.8,5.2),('188.114.98.121',218,91.6,4.8),('172.67.71.130',225,90.3,3.7)]):
            rows.append({'ip':ip,'accepted':True,'samples':[delay]*6,'validated_at':time.time(),
                         'median':delay,'score':score,'download':{'mbps':bw,'cv':.08},'network':['demo']})
        store.save_results(p,rows,['demo'])
        atomic_json(store.root/'preferences.json',{'theme':args.theme,'startup':False})
    try:
        window=Window(store,demo=bool(args.self_test or args.render_demo))
    except Exception as exc:
        lock.unlock()
        if args.self_test or args.render_demo:
            raise
        QMessageBox.critical(None,'澄流启动未完成',f'本机配置暂不可读，原文件已保留。\n{type(exc).__name__}\n数据目录：{store.root}')
        return 1
    if args.self_test:
        import ssl
        ssl.create_default_context()
        from cfai.gui import ProfileDialog, SettingsDialog, ExportDialog
        p=window.profiles[0]
        check_config(static_config(p,store.results(p)))
        # Exercise real widget construction and settings validation, without executing network tasks.
        settings=SettingsDialog(window,p.settings)
        settings.save()
        assert settings.result_settings is not None
        editor=ProfileDialog(window,p)
        editor.step=2
        editor.change(1)
        assert editor.result_profile is not None
        export=ExportDialog(window,p,store.results(p))
        assert len(export.checks)==4
        window.show()
        application.processEvents()
        assert window.result_table.rowCount()==4
        report={'ok':True,'version':'0.1.0','core_verified':True,'ui_pages':window.tabs.count(),
                'result_rows':window.result_table.rowCount(),'settings_roundtrip':True,'isolated_config_check':True}
        if args.data_dir:
            atomic_json(args.data_dir/'self-test.json',report)
        if sys.stdout:
            print(report)
        window.close()
        lock.unlock()
        return 0
    if args.render_demo:
        args.render_demo.mkdir(parents=True,exist_ok=True)
        window.show()
        window.states[p.id]={'id':p.id,'state':'cf','current':'CF-104.16.1.73','healthy':7,
            'stats':{'CF-104.16.1.73':{'median':182,'score':94.2}},'message':'演示数据 · 健康时保持线路，仅故障切换'}
        window.selection_changed()
        window.spark.values=[220,215,204,240,196,203,189,200,186,182,195,180,184,182]
        application.processEvents()
        for index,name in [(0,'overview'),(1,'servers'),(2,'results'),(3,'settings')]:
            window.tabs.setCurrentIndex(index)
            application.processEvents()
            window.grab().save(str(args.render_demo/f'{name}-{args.theme}.png'))
        from cfai.gui import ProfileDialog
        editor=ProfileDialog(window,p)
        editor.show()
        application.processEvents()
        editor.grab().save(str(args.render_demo/f'editor-{args.theme}.png'))
        editor.close()
        window.close()
        lock.unlock()
        return 0
    def exiting():
        if window.service:
            window.service.stop()
            if window.service.thread.is_alive():
                window.service.thread.join(timeout=45)
        lock.unlock()
    application.aboutToQuit.connect(exiting)
    if not args.tray or not window.tray:
        window.show()
    application.styleHints().colorSchemeChanged.connect(lambda *_: window.apply_theme())
    return application.exec()


if __name__=='__main__':
    raise SystemExit(main())
