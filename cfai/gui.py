from __future__ import annotations

import copy
from dataclasses import asdict, fields
import json
import os
from pathlib import Path
import sys
import time

from PySide6.QtCore import Qt, Signal, QObject, QTimer, QSize, QUrl, QStandardPaths
from PySide6.QtGui import QAction, QColor, QDesktopServices, QFont, QIcon, QPainter, QPainterPath, QPen, QPixmap
from PySide6.QtWidgets import (QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QDoubleSpinBox,
    QFileDialog, QFormLayout, QFrame, QGridLayout, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow,
    QMenu, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QScrollArea, QSpinBox, QStackedWidget,
    QSystemTrayIcon, QTabWidget, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)
import yaml

from . import __version__
from .config import Profile, Settings, Store, read_json, atomic_json
from .service import Service


def button(text, slot=None, role='secondary'):
    b = QPushButton(text)
    b.setProperty('role', role)
    b.setCursor(Qt.PointingHandCursor)
    if slot:
        b.clicked.connect(slot)
    return b


def label(text='', role='body'):
    widget = QLabel(text)
    widget.setProperty('role', role)
    widget.setWordWrap(True)
    return widget


def card():
    frame = QFrame()
    frame.setObjectName('card')
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(24, 22, 24, 22)
    layout.setSpacing(12)
    return frame, layout


def icon():
    pixmap = QPixmap(96, 96)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setBrush(QColor('#173e3c'))
    painter.setPen(Qt.NoPen)
    painter.drawRoundedRect(4, 4, 88, 88, 25, 25)
    painter.setPen(QPen(QColor('#9de6cf'), 7, Qt.SolidLine, Qt.RoundCap))
    for y, x in [(30, 25), (48, 37), (66, 25)]:
        painter.drawLine(x, y, x + 33, y)
    painter.end()
    return QIcon(pixmap)


class Sparkline(QWidget):
    def __init__(self):
        super().__init__()
        self.values = []
        self.setMinimumHeight(74)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        painter.setPen(QPen(QColor('#d7e2da'), 1))
        painter.drawLine(0, h - 12, w, h - 12)
        if len(self.values) < 2:
            painter.setPen(QColor('#81938c'))
            painter.drawText(self.rect(), Qt.AlignCenter, '开始管理后显示连接延迟趋势')
            return
        high = max(max(self.values), 50)
        path = QPainterPath()
        for i, value in enumerate(self.values[-40:]):
            x, y = i / (len(self.values[-40:])-1) * (w-4) + 2, h-14-value/high*(h-24)
            path.moveTo(x, y) if i == 0 else path.lineTo(x, y)
        painter.setPen(QPen(QColor('#319b80'), 2.5))
        painter.drawPath(path)


class Bridge(QObject):
    event = Signal(str, object)


class ProfileDialog(QDialog):
    def __init__(self, parent, profile=None):
        super().__init__(parent)
        self.original = copy.deepcopy(profile)
        self.result_profile = None
        self.setWindowTitle('编辑服务器' if profile else '添加服务器')
        self.setMinimumSize(610, 570)
        self.resize(650, 650)
        self.step = 0
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 26, 28, 24)
        root.setSpacing(16)
        root.addWidget(label('连接你的服务器', 'title'))
        root.addWidget(label('只保存在本机。此工具管理已有隧道，不部署 VPS。', 'muted'))
        self.steps = label('01  服务器与域名    /    02  节点参数    /    03  本机连接', 'accent')
        root.addWidget(self.steps)
        self.stack = QStackedWidget()
        root.addWidget(self.stack, 1)
        self.inputs = {}
        def edit(key, title, value='', password=False, placeholder=''):
            e = QLineEdit(str(value))
            e.setPlaceholderText(placeholder)
            if password:
                e.setEchoMode(QLineEdit.Password)
                show = QAction('显示 / 隐藏', e)
                eye = QPixmap(24, 24)
                eye.fill(Qt.transparent)
                painter = QPainter(eye)
                painter.setRenderHint(QPainter.Antialiasing)
                painter.setPen(QPen(QColor('#78958c'), 1.7))
                painter.drawEllipse(3, 7, 18, 10)
                painter.setBrush(QColor('#78958c'))
                painter.drawEllipse(10, 10, 4, 4)
                painter.end()
                show.setIcon(QIcon(eye))
                e.addAction(show, QLineEdit.TrailingPosition)
                show.triggered.connect(lambda: e.setEchoMode(QLineEdit.Normal if e.echoMode() == QLineEdit.Password else QLineEdit.Password))
            self.inputs[key] = e
            return title, e
        p = profile
        page = QWidget()
        form = QFormLayout(page)
        form.setSpacing(18)
        for args in [('name', '线路名称', p.name if p else '', False, '例如：我的洛杉矶服务器'),
                     ('domain', 'Cloudflare 域名', p.domain if p else '', False, 'proxy.your-domain.com'),
                     ('vps_ip', 'VPS IP（可选）', p.vps_ip if p else '', False, '仅作源站信息，不参与 CF 入口替换')]:
            form.addRow(*edit(*args))
        note = label('CF 域名须已正确回源到你的服务端。填写 IP 不会自动配置 DNS、证书或服务端。', 'muted')
        form.addRow(note)
        self.stack.addWidget(page)
        page = QWidget()
        form = QFormLayout(page)
        form.setSpacing(16)
        self.protocol = QComboBox()
        self.protocol.addItems(['VLESS', 'VMess', 'Trojan'])
        self.protocol.setCurrentText(p.protocol.upper() if p and p.protocol != 'vmess' else 'VMess' if p else 'VLESS')
        form.addRow('协议 · WS + TLS', self.protocol)
        self.port = QComboBox()
        self.port.addItems(['443', '2053', '2083', '2087', '2096', '8443'])
        self.port.setCurrentText(str(p.port if p else 8443))
        form.addRow('CF 入口端口', self.port)
        for args in [('credential', 'UUID / Trojan 密码', p.credential if p else '', True),
                     ('path', 'WebSocket 路径', p.path if p else '/'),
                     ('sni', 'SNI（留空跟随域名）', p.sni if p else ''),
                     ('host', 'Host（留空跟随域名）', p.host if p else '')]:
            form.addRow(*edit(*args))
        self.stack.addWidget(page)
        page = QWidget()
        form = QFormLayout(page)
        form.setSpacing(16)
        for args in [('controller', 'Clash 控制地址', p.controller if p else '', False, '留空自动发现；或 http://127.0.0.1:9090'),
                     ('secret', '控制密钥', p.secret if p else '', True, '自动发现时无需填写')]:
            form.addRow(*edit(*args))
        self.direct = copy.deepcopy(p.direct) if p else None
        self.direct_status = label('已设置直连模板' if self.direct else '未设置直连模板；仅生成 CF 线路', 'muted')
        form.addRow(self.direct_status)
        actions = QHBoxLayout()
        actions.addWidget(button('导入直连节点', self.import_direct))
        actions.addWidget(button('清除直连模板', self.clear_direct))
        form.addRow(actions)
        form.addRow(label('保存后先执行优选，再生成动态配置并在 Clash Verge 导入。静态导出不要求安装 Clash。', 'muted'))
        self.stack.addWidget(page)
        self.error = label('', 'error')
        root.addWidget(self.error)
        bar = QHBoxLayout()
        bar.addWidget(button('取消', self.reject, 'quiet'))
        bar.addStretch()
        self.back = button('上一步', lambda: self.change(-1))
        self.next = button('下一步', lambda: self.change(1), 'primary')
        bar.addWidget(self.back)
        bar.addWidget(self.next)
        root.addLayout(bar)
        self.update_step()

    def import_direct(self):
        path, _ = QFileDialog.getOpenFileName(self, '选择仅含直连节点的 JSON / YAML', '', '配置文件 (*.json *.yaml *.yml)')
        if path:
            try:
                value = yaml.safe_load(Path(path).read_text(encoding='utf-8-sig'))
                if isinstance(value, dict) and 'proxies' in value:
                    value = value['proxies'][0]
                if not isinstance(value, dict) or not value.get('type') or not value.get('server'):
                    raise ValueError('请选择单个有效节点')
                self.direct = value
                self.direct_status.setText('已设置直连模板：' + value.get('name', value['type']))
            except Exception:
                self.error.setText('直连模板无效，请检查文件格式')

    def clear_direct(self):
        self.direct = None
        self.direct_status.setText('未设置直连模板；仅生成 CF 线路')

    def update_step(self):
        self.stack.setCurrentIndex(self.step)
        self.back.setEnabled(self.step > 0)
        self.next.setText('保存服务器' if self.step == 2 else '下一步')
        self.steps.setText(f'{self.step+1:02d} / 03    ' + ['服务器与域名', '节点与传输', '本机连接与可选直连'][self.step])

    def change(self, delta):
        self.error.clear()
        if self.step == 0 and delta > 0 and (not self.inputs['name'].text().strip() or not self.inputs['domain'].text().strip()):
            self.error.setText('先填写线路名称和 Cloudflare 域名')
            return
        if self.step == 2 and delta > 0:
            try:
                data = {k: v.text().strip() for k, v in self.inputs.items()}
                # Passwords can contain meaningful leading/trailing whitespace.
                for key in ('credential', 'secret'):
                    data[key] = self.inputs[key].text()
                data.update(protocol=self.protocol.currentText().lower(), port=int(self.port.currentText()), direct=self.direct)
                p = copy.deepcopy(self.original) if self.original else Profile('', '', '')
                for key, value in data.items():
                    setattr(p, key, value)
                self.result_profile = p.validate()
                self.accept()
            except ValueError as exc:
                self.error.setText(str(exc))
            return
        self.step = max(0, min(2, self.step + delta))
        self.update_step()


PARAM_LABELS = {
 'poll_seconds':'当前节点探测周期 / 秒', 'backup_seconds':'备用探测周期 / 秒', 'timeout_ms':'探测超时 / 毫秒',
 'confirmation_seconds':'失败复核等待 / 秒', 'failure_rounds':'故障连续失败轮数', 'recovery_rounds':'备用连续成功轮数',
 'window_seconds':'健康统计窗口 / 秒', 'fresh_seconds':'备用样本新鲜期 / 秒', 'advantage_points':'主动优化领先分数',
 'leading_rounds':'主动优化连续领先轮数', 'cooldown_seconds':'主动切换最小间隔 / 秒', 'idle_seconds':'业务空闲等待 / 秒',
 'protect_activity':'业务活动保护', 'sample_count':'每批扫描 IP 数', 'tcp_workers':'TCP 并发数',
 'validation_candidates':'真实验证候选上限', 'validation_workers':'真实验证并发数', 'validation_interval':'验证轮次间隔 / 秒',
 'download_candidates':'下载测速候选上限', 'download_bytes':'单轮下载量 / 字节', 'download_rounds':'下载复测轮数',
 'warmup_bytes':'每候选预热量 / 字节', 'budget_bytes':'每批下载总预算 / 字节', 'download_timeout':'单轮下载超时 / 秒',
 'bandwidth_floor':'带宽达标线 / Mbps', 'maximum_cv':'速度波动上限 / CV', 'bandwidth_ttl':'带宽成绩有效期 / 秒',
 'target_pool':'目标池大小', 'max_pool':'安全池上限', 'export_count':'默认导出节点数', 'export_ttl':'导出验证有效期 / 秒',
 'daily_seconds':'周期发现间隔 / 秒', 'replenish_seconds':'补充扫描最小间隔 / 秒', 'background_bandwidth':'后台发现时测下载（额外流量）',
 'latency_share':'低延迟候选比例 / 0–1', 'history_share':'历史优秀候选比例 / 0–1',
 'latency_reference':'连接延迟参考值 / 毫秒', 'first_request_reference':'首次请求参考值 / 毫秒', 'jitter_reference':'连接延迟波动参考值 / 毫秒',
 'weight_success':'成功率权重', 'weight_latency':'连接延迟权重', 'weight_first_request':'首次请求耗时权重',
 'weight_jitter':'连接延迟波动权重', 'weight_bandwidth':'带宽权重',
 'probe_urls':'HTTPS 探测地址 / 每行一个（至少两个）', 'download_url':'HTTPS 下载测速地址',
 'stream_url':'自有流式诊断 HTTPS 地址（可选）', 'stream_seconds':'流式诊断最长时长 / 秒', 'stream_idle_seconds':'流式诊断空闲超时 / 秒'}


class SettingsDialog(QDialog):
    def __init__(self, parent, settings):
        super().__init__(parent)
        self.setWindowTitle('调整优选参数')
        self.resize(730, 690)
        self.result_settings = None
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 24, 24, 20)
        root.addWidget(label('为你的工作方式调校', 'title'))
        root.addWidget(label('参数按服务器保存。评分权重即时重排已有双指标结果；动态健康观测会重新收集。', 'muted'))
        bar = QHBoxLayout()
        bar.addWidget(button('恢复 AI 稳定预设', lambda: self.preset('ai')))
        bar.addWidget(button('多模态 / 文件预设', lambda: self.preset('multimodal')))
        bar.addStretch()
        root.addLayout(bar)
        tabs = QTabWidget()
        root.addWidget(tabs)
        self.controls = {}
        groups = [ ('切换与健康', list(asdict(settings))[:15]),
            ('扫描与节点池', ['sample_count','tcp_workers','validation_candidates','validation_workers','validation_interval','target_pool','max_pool','export_count','export_ttl','daily_seconds','replenish_seconds','latency_share','history_share']),
            ('下载测速', ['download_candidates','download_bytes','download_rounds','warmup_bytes','budget_bytes','download_timeout','maximum_cv','bandwidth_ttl','background_bandwidth']),
            ('健康评分', ['weight_success','weight_latency','weight_first_request','weight_jitter','weight_bandwidth','latency_reference','first_request_reference','jitter_reference','bandwidth_floor']),
            ('探测与诊断', ['probe_urls','download_url','stream_url','stream_seconds','stream_idle_seconds'])]
        for title, keys in groups:
            container = QWidget()
            form = QFormLayout(container)
            form.setSpacing(15)
            form.setContentsMargins(12, 20, 18, 20)
            if title == '健康评分':
                note = label('权重为相对比例，设为 0 即不计入。缺少某项测量时，所有参与比较的节点统一移除该项，再按剩余权重评分。\n连接延迟：同一 HTTPS 连接上的第二次请求。首次请求：包含代理建连、TLS 与 WS 握手。均非 AI 首字生成时间。', 'muted')
                note.setWordWrap(True)
                form.addRow(note)
                self.weight_summary = label('', 'accent')
                self.weight_summary.setWordWrap(True)
                form.addRow(self.weight_summary)
            for key in keys:
                value = getattr(settings, key)
                if type(value) is bool:
                    control = QCheckBox('启用')
                    control.setChecked(value)
                elif type(value) is int:
                    control = QSpinBox()
                    control.setRange(0, 500_000_000)
                    control.setGroupSeparatorShown(True)
                    control.setValue(value)
                elif type(value) is float:
                    control = QDoubleSpinBox()
                    control.setRange(0, 1_000_000)
                    control.setDecimals(3)
                    control.setValue(value)
                elif isinstance(value, list):
                    control = QPlainTextEdit('\n'.join(value))
                    control.setMaximumHeight(95)
                else:
                    control = QLineEdit(value)
                control.setToolTip(key + '\n' + PARAM_LABELS[key])
                self.controls[key] = control
                form.addRow(PARAM_LABELS[key], control)
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setWidget(container)
            tabs.addTab(scroll, title)
        for key in ('weight_success', 'weight_latency', 'weight_first_request', 'weight_jitter', 'weight_bandwidth'):
            self.controls[key].valueChanged.connect(self.update_weights)
        self.update_weights()
        self.error = label('', 'error')
        root.addWidget(self.error)
        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.save)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    def preset(self, name):
        changed = '带宽达标线 10 Mbps；成功率 / 连接 / 首次请求 / 波动 / 带宽权重 50 / 12 / 5 / 13 / 20' if name == 'multimodal' else '恢复 AI 稳定默认参数'
        if QMessageBox.question(self, '应用预设', changed + '\n其余参数恢复默认；当前流量预算保持。是否继续？') != QMessageBox.Yes:
            return
        budget = self.controls['budget_bytes'].value()
        s = Settings().preset(name)
        s.budget_bytes = budget
        for key, value in asdict(s).items():
            c = self.controls[key]
            if isinstance(c, QCheckBox): c.setChecked(value)
            elif isinstance(c, (QSpinBox, QDoubleSpinBox)): c.setValue(value)
            elif isinstance(c, QPlainTextEdit): c.setPlainText('\n'.join(value))
            else: c.setText(value)

    def update_weights(self):
        keys = ['weight_success', 'weight_latency', 'weight_first_request', 'weight_jitter', 'weight_bandwidth']
        values = [self.controls[k].value() for k in keys]
        total = sum(values)
        self.weight_summary.setText('完整指标占比 · ' + ' / '.join(f'{name} {100*v/total:.1f}%' if total else f'{name} 0%' for name, v in zip(['成功率','连接','首次','波动','带宽'], values)))

    def save(self):
        values = {}
        for key, c in self.controls.items():
            if isinstance(c, QCheckBox): values[key] = c.isChecked()
            elif isinstance(c, (QSpinBox, QDoubleSpinBox)): values[key] = c.value()
            elif isinstance(c, QPlainTextEdit): values[key] = [x.strip() for x in c.toPlainText().splitlines() if x.strip()]
            else: values[key] = c.text().strip()
        try:
            self.result_settings = Settings.from_dict(values)
            self.accept()
        except ValueError as exc:
            self.error.setText(str(exc))


class ExportDialog(QDialog):
    def __init__(self, parent, profile, rows):
        super().__init__(parent)
        self.setWindowTitle('导出静态优选配置')
        self.resize(800, 570)
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 24, 24, 24)
        root.addWidget(label('把好线路带走', 'title'))
        root.addWidget(label('文件内嵌节点，不依赖本管理器。包含你的节点凭据，请保存在可信位置。', 'muted'))
        form = QFormLayout()
        self.format = QComboBox()
        self.format.addItems(['完整 Mihomo 配置', '仅节点 provider 文件'])
        self.strategy = QComboBox()
        self.strategy.addItems(['手动选择 · select', '内核故障备用 · fallback', '内核延迟优选 · url-test'])
        self.count = QSpinBox()
        self.count.setRange(1,20)
        self.count.setValue(profile.settings.export_count)
        form.addRow('导出格式', self.format)
        form.addRow('节点数量上限', self.count)
        form.addRow('内核策略', self.strategy)
        root.addLayout(form)
        root.addWidget(label('下列节点仅显示本轮真实验证通过的项。下载数据不足不等于断线；过期验证不能导出。', 'muted'))
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(['选择 / 入口 IP', '连接延迟', '首次请求耗时', '带宽证据', '验证时间'])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setSelectionMode(QTableWidget.NoSelection)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.checks = []
        for row in rows:
            if not row.get('accepted'):
                continue
            i = self.table.rowCount()
            self.table.insertRow(i)
            item = QTableWidgetItem(row['ip'])
            item.setCheckState(Qt.Checked)
            fresh = 0 <= time.time()-row.get('validated_at',0) <= profile.settings.export_ttl
            if not fresh:
                item.setCheckState(Qt.Unchecked)
                item.setFlags(item.flags() & ~Qt.ItemIsEnabled)
            self.table.setItem(i,0,item)
            self.checks.append(item)
            bw = row.get('download',{}).get('mbps')
            for col, value in enumerate([f"{row['median']:.0f} ms" if row.get('median') else '—', f"{row['first_request']:.0f} ms" if row.get('first_request') else '—', f'{bw:.2f} Mbps' if bw is not None else '未测 / 不稳定', time.strftime('%m-%d %H:%M',time.localtime(row.get('validated_at',0))) + ('' if fresh else ' 已过期')],1):
                self.table.setItem(i,col,QTableWidgetItem(value))
        root.addWidget(self.table)
        root.addWidget(label('fallback / url-test 是 Mihomo 自身策略，不包含本工具的综合健康度算法。', 'muted'))
        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)


def theme_styles(dark=False):
    bg, surface, text, muted, border, field = ('#131e20','#1c292b','#e5eeeb','#9aacaa','#344448','#243537') if dark else ('#f4f5ef','#ffffff','#213631','#75827c','#e1e6dc','#f9faf5')
    selection_bg, selection_text = ('#2c514b', '#edf8f2') if dark else ('#dcefe6', '#173e34')
    return f'''
    QWidget {{ font-family: "Noto Sans CJK SC", "Microsoft YaHei UI", "Segoe UI"; font-size: 13px; color: {text}; }}
    QMainWindow, QDialog {{ background: {bg}; }}
    QLabel {{ background: transparent; }}
    QLabel[role="title"] {{ font-size: 25px; font-weight: 700; letter-spacing: 1px; }}
    QLabel[role="muted"] {{ color: {muted}; font-size: 12px; }}
    QLabel[role="accent"] {{ color: #349b81; font-weight: 600; }}
    QLabel[role="error"] {{ color: #c95f50; }}
    QLabel[role="metric"] {{ font-size: 29px; font-weight: 650; }}
    QFrame#card {{ background: {surface}; border: 1px solid {border}; border-radius: 14px; }}
    QFrame#hero {{ background: #173e3c; border-radius: 18px; }}
    QFrame#hero QLabel {{ color: #e9f6ed; }}
    QFrame#hero QLabel[role="muted"] {{ color: #a2c3b7; }}
    QFrame#hero QLabel[role="title"] {{ font-size: 30px; }}
    QPushButton {{ border: 1px solid {border}; border-radius: 8px; padding: 10px 17px; background: {surface}; font-weight: 550; }}
    QPushButton:hover {{ border-color: #6bbba0; background: {field}; }}
    QPushButton[role="primary"] {{ color: #f4fff9; background: #268a71; border: 1px solid #268a71; }}
    QPushButton[role="primary"]:hover {{ background: #227860; }}
    QPushButton[role="quiet"] {{ background: transparent; border: none; color: {muted}; }}
    QPushButton:disabled {{ color: {muted}; background: {field}; }}
    QLineEdit, QPlainTextEdit, QSpinBox, QDoubleSpinBox, QComboBox {{ background: {field}; border: 1px solid {border}; border-radius: 7px; padding: 10px; min-height: 19px; selection-background-color: #49a68e; }}
    QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus {{ border: 1px solid #369a81; }}
    QComboBox QAbstractItemView {{ background: {surface}; color: {text}; selection-background-color: #268a71; }}
    QTabWidget::pane {{ border: none; background: transparent; }}
    QTabBar::tab {{ background: transparent; color: {muted}; padding: 15px 24px; margin-right: 8px; border-bottom: 3px solid transparent; font-size: 14px; }}
    QTabBar::tab:selected {{ color: #349b81; border-bottom: 3px solid #349b81; font-weight: 650; }}
    QTableWidget {{ background: {surface}; border: 1px solid {border}; border-radius: 10px; gridline-color: {border}; selection-background-color: {selection_bg}; selection-color: {selection_text}; outline: none; }}
    QTableWidget::item {{ padding: 12px 8px; }}
    QTableWidget::item:selected {{ background: {selection_bg}; color: {selection_text}; }}
    QHeaderView::section {{ background: {field}; color: {muted}; border: none; padding: 12px; font-size: 12px; }}
    QScrollArea {{ border: none; background: transparent; }}
    QScrollArea > QWidget > QWidget {{ background: transparent; }}
    QProgressBar {{ border: none; background: {border}; height: 5px; border-radius: 2px; }}
    QProgressBar::chunk {{ background: #53b99b; border-radius: 2px; }}
    QCheckBox {{ spacing: 9px; }}
    QCheckBox::indicator {{ width: 19px; height: 19px; border: 1px solid {border}; border-radius: 5px; background: {field}; }}
    QCheckBox::indicator:checked {{ background: #268a71; border-color: #268a71; image: none; }}
    QMenu {{ background: {surface}; padding: 7px; border: 1px solid {border}; }}
    QMenu::item {{ padding: 9px 22px; }}
    QMenu::item:selected {{ background: {field}; }}
    QToolTip {{ background: {surface}; color: {text}; border: 1px solid {border}; padding: 8px; }}
    '''


class Window(QMainWindow):
    def __init__(self, store, demo=False):
        super().__init__()
        self.store, self.demo = store, demo
        self.profiles = store.profiles()
        self.states = {}
        self.scan_busy = False
        self.quitting = False
        self.setWindowTitle('澄流 · CF AI Manager')
        self.setWindowIcon(icon())
        self.resize(1120, 800)
        self.setMinimumSize(900, 650)
        self.bridge = Bridge()
        self.bridge.event.connect(self.handle_event)
        self.service = Service(store, self.bridge.event.emit) if not demo else None
        self.preferences = read_json(store.root / 'preferences.json', {'theme':'light','startup':False})
        self.tray = None
        self.build()
        self.apply_theme()
        self.refresh_profiles()
        if store.recovery_note:
            self.status.setText(store.recovery_note)
        if not demo:
            self.refresh_startup(migrate=True)
            self.create_tray()
            self.service.start()

    def build(self):
        base = QWidget()
        self.setCentralWidget(base)
        root = QVBoxLayout(base)
        root.setContentsMargins(32, 24, 32, 18)
        root.setSpacing(18)
        header = QHBoxLayout()
        brand = QLabel()
        brand.setPixmap(icon().pixmap(42,42))
        header.addWidget(brand)
        names = QVBoxLayout()
        names.setSpacing(1)
        names.addWidget(label('澄流', 'title'))
        names.addWidget(label('CF AI MANAGER   /   连接专注，保持流畅', 'muted'))
        header.addLayout(names)
        header.addStretch()
        header.addWidget(label('当前服务器', 'muted'))
        self.selector = QComboBox()
        self.selector.setMinimumWidth(200)
        self.selector.currentIndexChanged.connect(self.selection_changed)
        header.addWidget(self.selector)
        header.addWidget(button('＋ 添加', self.add_profile))
        root.addLayout(header)
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        root.addWidget(self.tabs, 1)
        self.build_overview()
        self.build_servers()
        self.build_results()
        self.build_settings()
        footer = QHBoxLayout()
        self.status = label('准备就绪 · 所有凭据仅保存在本机', 'muted')
        footer.addWidget(self.status,1)
        footer.addWidget(label(f'LOCAL FIRST   ·   v{__version__}', 'muted'))
        root.addLayout(footer)

    def page(self, name):
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0,18,0,0)
        layout.setSpacing(16)
        self.tabs.addTab(container, name)
        return layout

    def build_overview(self):
        layout = self.page('概览')
        hero = QFrame()
        hero.setObjectName('hero')
        hl = QVBoxLayout(hero)
        hl.setContentsMargins(30,26,30,26)
        hl.setSpacing(12)
        hl.addWidget(label('YOUR CONNECTION, IN BALANCE', 'muted'))
        self.hero_title = label('从一条可靠的线路开始', 'title')
        self.hero_subtitle = label('添加自己的服务器，优选入口，再选择动态管理或静态导出。', 'muted')
        hl.addWidget(self.hero_title)
        hl.addWidget(self.hero_subtitle)
        layout.addWidget(hero)
        metrics = QHBoxLayout()
        self.metrics = {}
        for key,title in [('latency','连接延迟'),('first_request','首次请求耗时'),('healthy','健康备用'),('score','综合健康度')]:
            frame, body = card()
            body.addWidget(label(title,'muted'))
            self.metrics[key] = label('—','metric')
            body.addWidget(self.metrics[key])
            metrics.addWidget(frame)
        layout.addLayout(metrics)
        self.monitor_status = label('健康监测：等待接入动态配置。完整优选记录与实时健康探测分别显示。', 'muted')
        self.monitor_status.setWordWrap(True)
        layout.addWidget(self.monitor_status)
        frame, body = card()
        row = QHBoxLayout()
        row.addWidget(label('线路管理', 'accent'))
        row.addStretch()
        self.managed = QCheckBox('动态管理')
        self.optimize = QCheckBox('综合健康度自动优化')
        self.managed.toggled.connect(self.toggle_management)
        self.optimize.toggled.connect(self.toggle_management)
        row.addWidget(self.managed)
        row.addSpacing(20)
        row.addWidget(self.optimize)
        body.addLayout(row)
        body.addWidget(label('关闭综合优化时，健康线路保持不变。开启后仍需明显优势、连续确认与业务空闲。','muted'))
        self.spark = Sparkline()
        body.addWidget(self.spark)
        row = QHBoxLayout()
        row.addWidget(button('生成动态配置', self.generate, 'primary'))
        row.addWidget(button('检查 Clash 连接', lambda: self.command('check')))
        row.addWidget(button('恢复自动管理', lambda: self.command('resume')))
        row.addStretch()
        body.addLayout(row)
        layout.addWidget(frame)
        layout.addStretch()

    def build_servers(self):
        layout = self.page('服务器')
        row = QHBoxLayout()
        row.addWidget(label('你的线路，独立管理', 'title'),1)
        row.addWidget(button('导入现有配置', self.import_profile))
        row.addWidget(button('编辑', self.edit_profile))
        row.addWidget(button('删除', self.delete_profile,'quiet'))
        layout.addLayout(row)
        layout.addWidget(label('每台服务器拥有独立节点池与策略；后台只接管当前启用的匹配配置。','muted'))
        self.server_table = QTableWidget(0,4)
        self.server_table.setHorizontalHeaderLabels(['线路名称','CF 域名','入口协议','策略'])
        self.server_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.server_table.verticalHeader().hide()
        self.server_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.server_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.server_table.cellClicked.connect(lambda row,col: self.selector.setCurrentIndex(row))
        self.server_table.cellDoubleClicked.connect(lambda *_: self.edit_profile())
        layout.addWidget(self.server_table,1)

    def build_results(self):
        layout = self.page('优选结果')
        top = QHBoxLayout()
        top.addWidget(label('好线路，经得起复测', 'title'),1)
        self.download_check = QCheckBox('包含轻量下载测速')
        self.download_check.setChecked(True)
        top.addWidget(self.download_check)
        self.scan_button = button('开始优选',self.scan,'primary')
        self.cancel_button = button('取消',lambda: self.service.submit('cancel') if self.service else None)
        self.cancel_button.setEnabled(False)
        top.addWidget(self.scan_button)
        top.addWidget(self.cancel_button)
        layout.addLayout(top)
        self.scan_status = label('真实隧道验证优先，下载只测少量候选。默认每批下载预算 30 MB。','muted')
        layout.addWidget(self.scan_status)
        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.hide()
        layout.addWidget(self.progress)
        self.result_table = QTableWidget(0,7)
        self.result_table.setHorizontalHeaderLabels(['CF 入口 IP','真实验证','连接延迟','首次请求耗时','健康分','下载能力','验证时间'])
        self.result_table.horizontalHeaderItem(2).setToolTip('复用同一 HTTPS 连接的第二次 HEAD 请求耗时；六次测量取中位数')
        self.result_table.horizontalHeaderItem(3).setToolTip('从本机发起代理连接到收到首次 HTTPS HEAD 响应，含代理、TLS、WS 握手；六次测量取中位数')
        self.result_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.result_table.verticalHeader().hide()
        self.result_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.result_table.setSelectionBehavior(QTableWidget.SelectRows)
        layout.addWidget(self.result_table,1)
        row = QHBoxLayout()
        row.addWidget(label('入口优选不会改变 VPS 出口；网络可达不等于 AI 服务已授权或可用。','muted'),1)
        row.addWidget(button('查看测试详情',self.result_details))
        row.addWidget(button('导出静态配置',self.export,'primary'))
        layout.addLayout(row)

    def build_settings(self):
        layout = self.page('设置')
        layout.addWidget(label('少一点打扰，多一点稳定', 'title'))
        frame, body = card()
        body.addWidget(label('当前服务器 · 优选策略','accent'))
        self.settings_summary = label('选择服务器后调整参数','muted')
        body.addWidget(self.settings_summary)
        row = QHBoxLayout()
        row.addWidget(button('调整全部参数',self.edit_settings,'primary'))
        row.addWidget(button('自有流式诊断',lambda: self.command('stream')))
        row.addStretch()
        body.addLayout(row)
        layout.addWidget(frame)
        frame,body=card()
        body.addWidget(label('应用偏好','accent'))
        form=QFormLayout()
        self.theme=QComboBox()
        self.theme.addItems(['浅色','深色','跟随系统'])
        self.theme.setCurrentIndex({'light':0,'dark':1,'system':2}.get(self.preferences.get('theme'),0))
        self.theme.currentIndexChanged.connect(self.set_theme)
        form.addRow('外观',self.theme)
        self.startup=QCheckBox('登录 Windows 时启动到托盘')
        self.startup.setChecked(self.preferences.get('startup',False))
        self.startup.toggled.connect(self.set_startup)
        startup_row=QHBoxLayout()
        startup_row.addWidget(self.startup)
        startup_row.addWidget(button('检查 / 修复',lambda: self.refresh_startup(migrate=True),'quiet'))
        form.addRow('开机启动',startup_row)
        body.addLayout(form)
        self.startup_status=label('登录启动状态尚未检查','muted')
        self.startup_status.setWordWrap(True)
        body.addWidget(self.startup_status)
        body.addWidget(label('关闭窗口进入托盘；从托盘选择退出会停止本工具，Clash 保持最后线路。','muted'))
        layout.addWidget(frame)
        row=QHBoxLayout()
        row.addWidget(button('打开本机数据目录',lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.store.root)))))
        row.addWidget(button('查看事件日志',self.show_logs))
        row.addWidget(button('备份配置',self.backup))
        row.addWidget(button('恢复备份',self.restore))
        row.addStretch()
        layout.addLayout(row)
        layout.addWidget(label('测试结果不包含账号状态。默认不读取浏览器会话，不发送付费模型请求。','muted'))
        layout.addStretch()

    def current(self):
        instance=self.selector.currentData()
        return next((p for p in self.profiles if p.id==instance),None)

    def command(self,action,*args):
        p=self.current()
        if not p:
            self.message('先添加一台服务器')
        elif self.service:
            self.service.submit(action,p.id,*args)

    def refresh_profiles(self, selected=None):
        previous=selected or self.selector.currentData()
        self.selector.blockSignals(True)
        self.selector.clear()
        for p in self.profiles:
            self.selector.addItem(p.name,p.id)
        if previous:
            self.selector.setCurrentIndex(max(0,self.selector.findData(previous)))
        self.selector.blockSignals(False)
        self.server_table.setRowCount(len(self.profiles))
        for i,p in enumerate(self.profiles):
            for j,text in enumerate([p.name,p.domain,f'{p.protocol.upper()} / {p.port}', '综合优化' if p.optimize else '仅故障切换']):
                self.server_table.setItem(i,j,QTableWidgetItem(text))
            self.server_table.setRowHeight(i,57)
        self.selection_changed()

    def selection_changed(self,*_):
        p=self.current()
        for widget in [self.managed,self.optimize]: widget.blockSignals(True)
        self.managed.setChecked(p.managed if p else False)
        self.optimize.setChecked(p.optimize if p else False)
        self.managed.setEnabled(bool(p))
        self.optimize.setEnabled(bool(p))
        for widget in [self.managed,self.optimize]: widget.blockSignals(False)
        self.spark.values=[]
        self.last_spark_sample=None
        if p:
            s=p.settings
            self.settings_summary.setText(f'权重 · 成功率 {s.weight_success:g} / 连接 {s.weight_latency:g} / 首次请求 {s.weight_first_request:g} / 波动 {s.weight_jitter:g} / 带宽 {s.weight_bandwidth:g}\n下载预算 {s.budget_bytes/1e6:g} MB    ·    目标池 {s.target_pool} 条    ·    优化领先 {s.advantage_points:g} 分 / 连续 {s.leading_rounds} 轮    ·    间隔 {s.cooldown_seconds//60} 分钟')
            self.show_state(self.states.get(p.id,{'state':'ready','message':'配置已保存。优选后生成动态配置，或直接导出静态节点。'}))
        else:
            self.hero_title.setText('从一条可靠的线路开始')
            self.hero_subtitle.setText('添加自己的服务器，优选入口，再选择动态管理或静态导出。')
            for m in self.metrics.values(): m.setText('—')
        self.refresh_results()

    def save_profiles(self,selected=None):
        if self.service:
            self.service.submit('save',copy.deepcopy(self.profiles))
        else:
            self.store.save_profiles(self.profiles)
        self.refresh_profiles(selected)

    def add_profile(self):
        if self.scan_busy:
            return self.message('请等待或取消当前任务后再编辑服务器')
        dialog=ProfileDialog(self)
        if dialog.exec()==QDialog.Accepted:
            self.profiles.append(dialog.result_profile)
            self.save_profiles(dialog.result_profile.id)
            self.tabs.setCurrentIndex(2)

    def edit_profile(self):
        p=self.current()
        if not p: return self.add_profile()
        if self.scan_busy: return self.message('请等待或取消当前任务后再编辑服务器')
        dialog=ProfileDialog(self,p)
        if dialog.exec()==QDialog.Accepted:
            self.profiles=[dialog.result_profile if x.id==p.id else x for x in self.profiles]
            self.save_profiles(p.id)

    def delete_profile(self):
        p=self.current()
        if not p or self.scan_busy: return
        if QMessageBox.question(self,'移除服务器','从本工具移除此服务器？原始配置、provider 和导出文件保留。')==QMessageBox.Yes:
            self.profiles=[x for x in self.profiles if x.id!=p.id]
            self.save_profiles()

    def import_profile(self):
        if self.scan_busy: return self.message('请先结束当前任务')
        path,_=QFileDialog.getOpenFileName(self,'导入现有 Mihomo 配置或旧 manager settings.json','','配置 (*.yaml *.yml *.json)')
        if not path: return
        try:
            value=yaml.safe_load(Path(path).read_text(encoding='utf-8-sig'))
            direct=None
            if isinstance(value,dict) and 'pool_dir' in value:
                pool=Path(os.path.expandvars(value['pool_dir']))
                node=read_json(pool/'template.json')
                name=Path(path).parent.name.replace('-manager','')
            else:
                nodes=value.get('proxies',[value]) if isinstance(value,dict) else value
                if not isinstance(nodes,list): raise ValueError()
                node=next(n for n in nodes if n.get('network')=='ws' and n.get('type') in ('vless','vmess','trojan'))
                direct=next((n for n in nodes if n.get('network')!='ws' and n.get('type') not in ('select','url-test','fallback')),None)
                name=node.get('name','导入线路')
            domain=node.get('servername') or node.get('sni') or node.get('ws-opts',{}).get('headers',{}).get('Host')
            p=Profile(name,domain,node.get('uuid') or node.get('password'),protocol=node['type'],port=node['port'],
                path=node.get('ws-opts',{}).get('path','/'),host=node.get('ws-opts',{}).get('headers',{}).get('Host',''),direct=direct)
            p.validate()
            dialog=ProfileDialog(self,p)
            if dialog.exec()==QDialog.Accepted:
                self.profiles.append(dialog.result_profile)
                self.save_profiles(p.id)
        except Exception:
            self.message('未能导入：首版支持 VLESS / VMess / Trojan 的 WS+TLS。请检查文件或手动填写。',True)

    def edit_settings(self):
        p=self.current()
        if not p: return self.message('先添加服务器')
        if self.scan_busy: return self.message('请先结束当前任务')
        dialog=SettingsDialog(self,p.settings)
        if dialog.exec()==QDialog.Accepted:
            p.settings=dialog.result_settings
            self.save_profiles(p.id)

    def toggle_management(self):
        p=self.current()
        if p:
            p.managed=self.managed.isChecked()
            p.optimize=self.optimize.isChecked()
            self.save_profiles(p.id)

    def scan(self):
        p=self.current()
        if not p: return self.add_profile()
        self.command('scan',self.download_check.isChecked())

    def generate(self):
        p=self.current()
        if not p: return self.message('先添加服务器')
        if self.scan_busy: return self.message('请等待当前优选完成，再生成动态配置')
        folder=QStandardPaths.writableLocation(QStandardPaths.DownloadLocation) or str(Path.home())
        name=''.join('_' if c in '<>:"/\\|?*' else c for c in p.name).strip(' .') or 'CF-AI'
        destination,_=QFileDialog.getSaveFileName(self,'保存动态配置',str(Path(folder)/f'{name}-动态配置.yaml'),'YAML (*.yaml *.yml)')
        if destination:
            if Path(destination).suffix.lower() not in ('.yaml','.yml'):
                destination+='.yaml'
            self.command('dynamic',destination)

    def generated(self, path):
        self.status.setText('动态配置已生成：'+str(path))
        dialog=QMessageBox(self)
        dialog.setWindowTitle('动态配置已生成')
        dialog.setIcon(QMessageBox.Information)
        dialog.setText('在 Clash Verge 的订阅 / 配置页面导入并启用此文件，再选择本实例的 CF 组。')
        dialog.setInformativeText(str(path)+'\n\n动态管理需要本工具持续运行。文件引用本机节点池，请保留本工具的数据目录。')
        dialog.setTextInteractionFlags(Qt.TextSelectableByMouse)
        copy_button=dialog.addButton('复制文件路径',QMessageBox.ActionRole)
        copy_button.clicked.connect(lambda: QApplication.clipboard().setText(str(path)))
        dialog.addButton('完成',QMessageBox.AcceptRole)
        dialog.exec()

    def refresh_results(self):
        p=self.current()
        self.rows=self.store.results(p) if p else []
        if any(r.get('legacy_measurement') for r in self.rows):
            self.scan_status.setText('旧结果仅有首次请求耗时；连接延迟与健康分待重新优选后补齐。')
        self.result_table.setRowCount(len(self.rows))
        for i,row in enumerate(self.rows):
            bw=row.get('download',{}).get('mbps')
            values=[row['ip'],'通过' if row.get('accepted') else '未通过',f"{row['median']:.0f} ms" if row.get('median') else '—',
                f"{row['first_request']:.0f} ms" if row.get('first_request') else '—',
                f"{row['score']:.1f}" if row.get('score') is not None else '数据不足',f'{bw:.2f} Mbps' if bw is not None else '未测 / 不稳定',
                time.strftime('%m-%d %H:%M',time.localtime(row.get('validated_at',0)))]
            for j,value in enumerate(values):
                item=QTableWidgetItem(value)
                if j==1: item.setForeground(QColor('#329c7d' if row.get('accepted') else '#b56e60'))
                self.result_table.setItem(i,j,item)
            self.result_table.setRowHeight(i,51)

    def result_details(self):
        i=self.result_table.currentRow()
        if i<0 or i>=len(self.rows): return self.message('先选择一条结果')
        row=self.rows[i]
        dialog=QDialog(self)
        dialog.setWindowTitle('测试详情 · '+row['ip'])
        dialog.resize(680,560)
        layout=QVBoxLayout(dialog)
        layout.addWidget(label('原始测量 · 不含节点凭据','title'))
        text=QPlainTextEdit(json.dumps(row,ensure_ascii=False,indent=2))
        text.setReadOnly(True)
        layout.addWidget(text)
        layout.addWidget(button('关闭',dialog.accept))
        dialog.exec()

    def export(self):
        p=self.current()
        if not p: return self.message('先添加服务器')
        dialog=ExportDialog(self,p,self.rows)
        if dialog.exec()!=QDialog.Accepted: return
        selected={item.text() for item in dialog.checks if item.checkState()==Qt.Checked}
        if not selected: return self.message('没有选中有效节点，请先完成优选')
        destination,_=QFileDialog.getSaveFileName(self,'保存静态配置',f'{p.name}-优选.yaml','YAML (*.yaml)')
        if destination and self.service:
            self.service.submit('export',p.id,destination,dialog.format.currentIndex()==1,
                ['select','fallback','url-test'][dialog.strategy.currentIndex()],selected,dialog.count.value())

    def handle_event(self,kind,value):
        if kind=='profiles':
            self.profiles=[Profile.from_dict(p) for p in value]
            self.refresh_profiles()
        elif kind=='state':
            self.states[value['id']]=value
            if self.current() and self.current().id==value['id']: self.show_state(value)
        elif kind=='scan_started':
            self.scan_busy=True
            self.scan_button.setEnabled(False)
            self.cancel_button.setEnabled(True)
            self.progress.setRange(0,0)
            self.progress.show()
            self.status.setText('优选任务运行中 · 可随时取消')
        elif kind=='scan':
            self.scan_status.setText(value)
            self.status.setText(value)
        elif kind=='scan_done':
            self.scan_status.setText(f"优选完成 · {sum(r.get('accepted',False) for r in value['rows'])} 条通过真实验证 · 下载 {value['bytes']/1e6:.2f} MB")
        elif kind=='scan_idle':
            self.scan_busy=False
            self.scan_button.setEnabled(True)
            self.cancel_button.setEnabled(False)
            self.progress.hide()
            self.refresh_results()
        elif kind=='scan_cancelled':
            self.scan_status.setText('任务已取消；已结束的独立测试内核会自动清理')
        elif kind=='results': self.refresh_results()
        elif kind=='error': self.message(value,True)
        elif kind=='notice': self.message(value)
        elif kind=='generated':
            self.generated(value)
        elif kind=='stopped' and self.quitting: QApplication.instance().quit()

    def show_state(self,state):
        p=self.current()
        if not p: return
        current=state.get('current')
        active=state['state'] in ('cf','hold')
        self.hero_title.setText(('手动保持 · 持续监测' if state['state']=='hold' else '连接专注，保持流畅' if state['state']=='cf' else p.name))
        self.hero_subtitle.setText((current+'    ·    ' if current else '')+state.get('message',''))
        row=state.get('stats',{}).get(current,{})
        fresh=row.get('fresh',True)
        pending='待探测' if active else '未监测'
        self.metrics['latency'].setText(f"{row['median']:.0f} ms" if fresh and row.get('median') else pending)
        self.metrics['first_request'].setText(f"{row['first_request']:.0f} ms" if fresh and row.get('first_request') else pending)
        self.metrics['healthy'].setText(str(state.get('healthy',0)) if active and state.get('backups_ready',True) else '收集中' if active else '未监测')
        self.metrics['score'].setText(f"{row['score']:.1f}" if fresh and row.get('score') is not None else '收集中' if active and row.get('samples') and fresh else pending)
        def timestamp(value):
            return time.strftime('%m-%d %H:%M:%S',time.localtime(value)) if value else '暂无记录'
        if active:
            next_scan=state.get('next_scan_at',0)
            due='已到期，等待启动' if next_scan and next_scan<=time.time() else timestamp(next_scan)
            scan=('正在优选' if state.get('scanning') else due+' · '+state.get('scan_reason','周期发现'))
            self.monitor_status.setText('当前节点最近探测：'+timestamp(state.get('last_probe_at'))+f'    ·    探测周期 {p.settings.poll_seconds} 秒\n'
                +'上次完整优选：'+timestamp(state.get('last_scan_at'))+'    ·    下次自动优选：'+scan
                +('    ·    保持期间只更新候选结果，不替换节点池' if state['state']=='hold' else ''))
        else:
            self.monitor_status.setText('健康监测：'+state.get('message','等待接入动态配置'))
        point=(p.id,current,row.get('last_at'))
        if fresh and row.get('median') and point!=getattr(self,'last_spark_sample',None):
            self.last_spark_sample=point
            self.spark.values.append(row['median'])
            self.spark.values=self.spark.values[-40:]
            self.spark.update()

    def message(self,text,error=False):
        self.status.setText(text.splitlines()[0])
        if self.quitting: return
        if error: QMessageBox.warning(self,'操作未完成',text)
        else: QMessageBox.information(self,'澄流',text)

    def apply_theme(self):
        mode=self.preferences.get('theme','light')
        dark=mode=='dark' or (mode=='system' and QApplication.styleHints().colorScheme()==Qt.ColorScheme.Dark)
        QApplication.instance().setStyleSheet(theme_styles(dark))

    def set_theme(self,index):
        self.preferences['theme']=['light','dark','system'][index]
        atomic_json(self.store.root/'preferences.json',self.preferences)
        self.apply_theme()

    def set_startup(self,enabled):
        if self.demo: return
        try:
            if not getattr(sys,'frozen',False): raise ValueError('开机启动请使用打包后的 EXE')
            from .startup import configure,describe
            state=configure(enabled,sys.executable,self.store.root)
            self.preferences['startup']=enabled
            atomic_json(self.store.root/'preferences.json',self.preferences)
            self.startup_status.setText(describe(state))
        except (OSError,ValueError) as exc:
            self.startup.blockSignals(True)
            self.startup.setChecked(not enabled)
            self.startup.blockSignals(False)
            self.message(str(exc),True)

    def refresh_startup(self,migrate=False):
        if self.demo:
            self.startup_status.setText('演示模式，不创建登录启动项。')
            return
        if not getattr(sys,'frozen',False):
            self.startup_status.setText('源码模式；请使用便携 EXE 设置登录启动。')
            return
        try:
            from .startup import inspect,configure,describe
            state=inspect(sys.executable,self.store.root)
            if migrate and self.preferences.get('startup') and not state['disabled'] and (not state['correct'] or state['legacy']):
                state=configure(True,sys.executable,self.store.root)
            self.startup.blockSignals(True)
            self.startup.setChecked(state['registered'])
            self.startup.blockSignals(False)
            text=describe(state)
            recent=read_json(self.store.root/'last-startup.json',{})
            if recent.get('started_at'):
                text+='\n本次启动：'+time.strftime('%m-%d %H:%M:%S',time.localtime(recent['started_at']))+' · '+('登录启动入口' if recent.get('mode')=='autostart' else '手动启动')
            self.startup_status.setText(text)
        except (OSError,ValueError) as exc:
            self.startup_status.setText('登录启动检查未完成：'+str(exc))

    def create_tray(self):
        if not QSystemTrayIcon.isSystemTrayAvailable(): return
        self.tray=QSystemTrayIcon(icon(),self)
        self.tray.setToolTip('澄流 · CF AI Manager')
        menu=QMenu()
        menu.addAction('打开澄流',self.reveal)
        menu.addAction('取消当前优选',lambda: self.service.submit('cancel'))
        menu.addSeparator()
        menu.addAction('退出',self.quit)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(lambda reason: self.reveal() if reason==QSystemTrayIcon.DoubleClick else None)
        self.tray.show()

    def reveal(self):
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def quit(self):
        self.quitting=True
        self.status.setText('正在停止探测并清理独立内核…')
        if self.service:
            self.service.stop()
            self.setEnabled(False)
        else: QApplication.instance().quit()

    def closeEvent(self,event):
        if self.demo or self.quitting:
            event.accept()
        elif self.tray:
            self.hide()
            event.ignore()
        else:
            event.ignore()
            self.quit()

    def show_logs(self):
        path=self.store.root/'events.log'
        text=path.read_text(encoding='utf-8')[-50000:] if path.exists() else '暂无事件日志'
        dialog=QDialog(self)
        dialog.resize(760,520)
        dialog.setWindowTitle('事件日志 · 不含节点凭据')
        layout=QVBoxLayout(dialog)
        editor=QPlainTextEdit(text)
        editor.setReadOnly(True)
        layout.addWidget(editor)
        layout.addWidget(button('关闭',dialog.accept))
        dialog.exec()

    def backup(self):
        destination,_=QFileDialog.getSaveFileName(self,'备份配置（含节点凭据，请妥善保管）','澄流-配置备份.json','JSON (*.json)')
        if destination:
            atomic_json(destination,{'schema':1,'profiles':[p.to_dict() for p in self.profiles]})
            self.message('配置已备份；此文件包含节点凭据')

    def restore(self):
        if self.scan_busy: return self.message('请先结束当前任务')
        path,_=QFileDialog.getOpenFileName(self,'恢复配置备份','','JSON (*.json)')
        if not path: return
        try:
            data=read_json(path)
            if data.get('schema')!=1: raise ValueError()
            profiles=[Profile.from_dict(p) for p in data['profiles']]
            if QMessageBox.question(self,'恢复备份',f'替换当前服务器列表为 {len(profiles)} 台？恢复后动态管理默认关闭。')!=QMessageBox.Yes: return
            for p in profiles: p.managed=False
            self.profiles=profiles
            self.save_profiles()
        except Exception: self.message('备份无效，当前配置未更改',True)
