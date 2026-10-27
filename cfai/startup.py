"""Per-user logon shortcut with read-back verification; never changes Windows approval policy."""
import json
import os
from pathlib import Path
import subprocess

NAME = 'CFAIManager'
RUN_KEY = r'Software\Microsoft\Windows\CurrentVersion\Run'


def shortcut_path():
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders') as key:
            folder = winreg.QueryValueEx(key, 'Startup')[0]
    except FileNotFoundError:
        folder = str(Path(os.environ['APPDATA']) / 'Microsoft/Windows/Start Menu/Programs/Startup')
    return Path(os.path.expandvars(folder)) / (NAME + '.lnk')


def shortcut_info(path, executable=None, arguments=None):
    # Values travel through the environment, never interpolated as PowerShell code.
    script = r'''
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$ErrorActionPreference = 'Stop'
$taskShell = New-Object -ComObject WScript.Shell
$taskLink = $taskShell.CreateShortcut($env:CFAI_STARTUP_LINK)
if ($env:CFAI_STARTUP_WRITE -eq '1') {
    $taskLink.TargetPath = $env:CFAI_STARTUP_EXE
    $taskLink.Arguments = $env:CFAI_STARTUP_ARGS
    $taskLink.WorkingDirectory = [System.IO.Path]::GetDirectoryName($env:CFAI_STARTUP_EXE)
    $taskLink.Description = '澄流 · 登录 Windows 后启动到托盘'
    $taskLink.Save()
}
@{target=$taskLink.TargetPath; arguments=$taskLink.Arguments; working_directory=$taskLink.WorkingDirectory} | ConvertTo-Json -Compress
'''
    env = dict(os.environ, CFAI_STARTUP_LINK=str(path), CFAI_STARTUP_WRITE='1' if executable else '0',
               CFAI_STARTUP_EXE=str(executable or ''), CFAI_STARTUP_ARGS=arguments or '')
    powershell = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    try:
        result = subprocess.run([str(powershell), '-NoProfile', '-NonInteractive', '-Command', script],
                                env=env, capture_output=True, timeout=15,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    except subprocess.TimeoutExpired:
        raise ValueError('登录启动检查超时，请稍后点击“检查 / 修复”重试') from None
    if result.returncode:
        raise ValueError('无法读取或保存登录启动快捷方式')
    return json.loads(result.stdout.decode('utf-8-sig'))


def legacy_command():
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            return winreg.QueryValueEx(key, NAME)[0]
    except FileNotFoundError:
        return None


def remove_legacy():
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, NAME)
    except FileNotFoundError:
        pass


def disabled(kind, name):
    import winreg
    try:
        key_path = 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\' + kind
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            value = winreg.QueryValueEx(key, name)[0]
        return isinstance(value, bytes) and len(value) >= 4 and int.from_bytes(value[:4], 'little') in (3, 7)
    except FileNotFoundError:
        return False


def arguments(data_dir):
    return subprocess.list2cmdline(['--autostart', '--data-dir', str(Path(data_dir).resolve())])


def inspect(executable, data_dir):
    path = shortcut_path()
    info = shortcut_info(path) if path.is_file() else {}
    correct = (bool(info) and os.path.normcase(info.get('target', '')) == os.path.normcase(str(Path(executable).resolve()))
               and info.get('arguments') == arguments(data_dir))
    legacy = legacy_command()
    blocked = (path.is_file() and disabled('StartupFolder', path.name)) or (not path.is_file() and bool(legacy) and disabled('Run', NAME))
    return {'registered': path.is_file() or bool(legacy), 'correct': correct, 'legacy': bool(legacy),
            'disabled': blocked, 'path': str(path)}


def configure(enabled, executable, data_dir):
    path = shortcut_path()
    if enabled:
        executable = Path(executable).resolve()
        if not executable.is_file():
            raise ValueError('启动程序不存在，请完整解压便携包后重试')
        path.parent.mkdir(parents=True, exist_ok=True)
        staged = path.with_name(NAME + '.pending.lnk')
        try:
            shortcut_info(staged, executable, arguments(data_dir))
            info = shortcut_info(staged)
            if (os.path.normcase(info.get('target', '')) != os.path.normcase(str(executable))
                    or info.get('arguments') != arguments(data_dir)):
                raise ValueError('登录启动快捷方式回读验证失败，原启动项已保留')
            os.replace(staged, path)
        finally:
            staged.unlink(missing_ok=True)
        # Delete only this application's old entry, after a verified shortcut exists.
        remove_legacy()
    else:
        path.unlink(missing_ok=True)
        remove_legacy()
    return inspect(executable, data_dir)


def describe(state):
    if state['disabled']:
        return '启动项存在，但 Windows 已禁用；请在任务管理器的“启动应用”中检查澄流。'
    if state['correct']:
        return '已验证：当前用户登录后启动到托盘。程序目录移动后请重新检查启动项。'
    if state['registered']:
        return '启动项与当前程序或数据目录不一致，请点击“检查 / 修复”。'
    return '未配置登录启动。'
