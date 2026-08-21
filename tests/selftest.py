import os
import tempfile
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(ROOT, 'src'))

from tshelper import app as mod  # noqa: E402
from tshelper.printer_monitor_launcher import (  # noqa: E402
    PrinterMonitorLauncher,
    build_printer_monitor_command,
)


def assert_eq(actual, expected, msg):
    if actual != expected:
        raise AssertionError(f"{msg}: {actual!r} != {expected!r}")


def test_normalize_phone():
    assert_eq(mod.normalize_phone('+7 (999) 123-45-67'), '79991234567', 'normalize_phone ru')
    assert_eq(mod.normalize_phone(' 123-45-67 '), '', 'normalize_phone short')


def test_canonical_pc_key():
    assert_eq(mod.canonical_pc_key('WS-ABC-01'), 'abc-01', 'canonical_pc_key ws')
    assert_eq(mod.canonical_pc_key('L-WS-ABC'), 'abc', 'canonical_pc_key nested')


def test_release_version_comparison():
    assert mod.is_newer_release('v5.10', 'v5.9.2')
    assert not mod.is_newer_release('v5.9', 'v5.9.2')
    assert not mod.is_newer_release('v5.9.2', '5.9.2')
    assert not mod.is_newer_release('неизвестно', 'v5.9.2')


def test_os_specific_context_actions():
    windows = set(mod.context_action_ids('windows'))
    linux = set(mod.context_action_ids('linux'))
    combined = set(mod.context_action_ids('windows', combine_functionality=True))

    assert {'remote_assistance', 'powershell', 'explorer', 'windows_deploy', 'elma'} <= windows
    assert not {'ssh', 'ssh_key', 'linux_install'} & windows
    assert {'ssh', 'ssh_key', 'linux_install'} <= linux
    assert not {'remote_assistance', 'powershell', 'explorer', 'windows_deploy', 'elma'} & linux
    assert set(mod.CONTEXT_WINDOWS_ACTIONS + mod.CONTEXT_LINUX_ACTIONS) <= combined

    class FakeMenu:
        def __init__(self):
            self.labels = []

        def add_command(self, *, label, command):
            self.labels.append(label)

        def add_separator(self):
            self.labels.append('---')

    button = mod.UserButton.__new__(mod.UserButton)
    windows_menu = FakeMenu()
    linux_menu = FakeMenu()
    button._add_host_actions(windows_menu, 'w-test', 'windows', False)
    button._add_host_actions(linux_menu, 'l-test', 'linux', False)
    assert 'Подключение по SSH' not in windows_menu.labels
    assert 'Windows Deployment' not in linux_menu.labels
    assert 'Подключение по SSH' in linux_menu.labels
    assert 'Windows Deployment' in windows_menu.labels


def test_multi_pc_os_cache_and_merge():
    class DummySettings:
        def __init__(self):
            self.values = {'pc_prefixes': ['w-', 'l-']}

        def get_setting(self, key, default=None):
            return self.values.get(key, default)

        def set_setting(self, key, value):
            self.values[key] = value

    with tempfile.TemporaryDirectory() as td:
        manager = mod.UserManager(os.path.join(td, 'users.json'))
        app = mod.MainWindow.__new__(mod.MainWindow)
        app.settings = DummySettings()
        app.users = manager
        app.os_badge_cache = {}
        app.ping_cache = {}

        app.remember_os_type('w-test', 'windows')
        app.remember_os_type('l-test', 'linux')
        assert_eq(app.get_cached_os_type('w-test'), 'windows', 'windows host cache')
        assert_eq(app.get_cached_os_type('l-test'), 'linux', 'linux host cache')
        assert_eq(app.resolve_os_types_for_user({'pc_name': 'l-test', 'pc_options': ['w-test']}), ['linux', 'windows'], 'dual OS badges')
        assert_eq(app.build_host_candidates({'pc_name': 'l-test', 'pc_options': []})[0], 'l-test', 'selected host has priority')
        assert_eq(app.build_host_candidates({'pc_name': 'w-test', '_strict_host': True}), ['w-test'], 'actions use exact selected host')

        existing = {'name': 'Тест', 'pc_name': 'l-test', 'pc_options': [], 'ext': '4443', 'location': 'Щ5-104'}
        incoming = {'name': 'Тест', 'pc_name': 'w-test', 'pc_options': [], 'ext': '4443', 'location': 'Щ5-104'}
        merged = app._merge_user_records(existing, incoming)
        assert_eq(merged['pc_name'], 'l-test', 'AD sync keeps selected primary PC')
        assert_eq(merged['pc_options'], ['w-test'], 'AD sync remembers second PC')
        assert_eq(merged['location'], 'Щ5-104', 'location survives merge')

        class FakeGlpi:
            @staticmethod
            def find_user_computers(_login, _name):
                return {'main': 'w-test', 'options': ['l-test'], 'source': 'name'}

        updated, changed = app._apply_glpi_prefixes([existing], FakeGlpi(), 'test')
        assert changed
        assert_eq(updated[0]['ext'], '4443', 'GLPI sync keeps extension')
        assert_eq(updated[0]['location'], 'Щ5-104', 'GLPI sync keeps location')
        assert_eq(updated[0]['pc_options'], ['l-test'], 'GLPI sync keeps alternate PC')


def test_card_contact_line_with_location():
    button = mod.UserButton.__new__(mod.UserButton)
    button.user = {'name': 'Азарян Валентина', 'ext': '4443', 'location': 'Щ5-104'}
    button.show_status = False
    button.caller_info = None
    button.status_key = 'online'
    text = button._compose_text('w-vazaryan')
    assert '4443 -- Щ5-104' in text


def test_batched_settings_and_glpi_timeout():
    manager = mod.SettingsManager.__new__(mod.SettingsManager)
    manager.config = {}
    manager._secret_keys = set()
    writes = []
    manager.save_config = lambda: writes.append(dict(manager.config))
    manager.set_settings({'one': 1, 'two': 2, 'three': 3})
    assert_eq(manager.config, {'one': 1, 'two': 2, 'three': 3}, 'batched settings values')
    assert_eq(len(writes), 1, 'batched settings use one config write')

    calls = []

    class FakeResponse:
        content = b'{}'

        @staticmethod
        def raise_for_status():
            return None

        @staticmethod
        def json():
            return {'data': []}

    class FakeSession:
        def get(self, url, **kwargs):
            calls.append((url, kwargs))
            return FakeResponse()

    client = mod.GLPIClient('https://glpi.invalid/apirest.php', 'app', 'user', request_timeout=7)
    client.session = FakeSession()
    client.session_token = 'session'
    client._search('User', 'test')
    assert_eq(calls[0][1].get('timeout'), 7, 'GLPI request timeout')


def test_incremental_card_sync_and_deferred_ad_lookup():
    class FakeApp:
        @staticmethod
        def resolve_os_types_for_user(_user):
            return ['windows']

    button = mod.UserButton.__new__(mod.UserButton)
    button.app = FakeApp()
    button.user = {'name': 'Тест', 'pc_name': 'w-test', 'pc_options': [], 'ext': '1', 'location': ''}
    button._user_render_signature = button._data_signature(button.user)
    button._os_badge_signature = ('windows',)
    button.btn = type('FakeButton', (), {'cget': lambda self, key: '#fff' if key == 'bg' else '#000'})()
    refreshes = []
    badges = []
    button.refresh_text = lambda: refreshes.append(True)
    button._update_os_badge = lambda _bg, _fg: badges.append(True)
    button.sync_user(dict(button.user))
    assert_eq(refreshes, [], 'unchanged card is not redrawn')
    assert_eq(badges, [], 'unchanged OS badge is not rebuilt')
    changed_user = dict(button.user, location='Щ5-104')
    button.sync_user(changed_user)
    assert_eq(len(refreshes), 1, 'changed card is redrawn once')

    app = mod.MainWindow.__new__(mod.MainWindow)
    app._ad_mobile_cache = {}
    app._ad_mobile_failed_cache = {}
    app._ad_mobile_cache_lock = __import__('threading').Lock()
    app._find_ad_candidates_by_mobile = lambda *_args: (_ for _ in ()).throw(AssertionError('network lookup must be deferred'))
    assert app.ad_lookup_by_mobile('+7 999 000-11-22', allow_network=False) is None


def test_ping_dispatch_is_bounded():
    class FakeFuture:
        def add_done_callback(self, callback):
            self.callback = callback

    class FakeExecutor:
        def __init__(self):
            self.submitted = []

        def submit(self, callback, user):
            self.submitted.append((callback, user))
            return FakeFuture()

    class FakeMaster:
        def __init__(self):
            self.jobs = []

        def after(self, delay, callback):
            self.jobs.append((delay, callback))
            return len(self.jobs)

    app = mod.MainWindow.__new__(mod.MainWindow)
    app.ping_generation = 1
    app.ping_max_workers = 2
    app._pending_ping_users = [
        {'pc_name': 'w-one'},
        {'pc_name': 'w-two'},
        {'pc_name': 'w-three'},
    ]
    app._ping_queue_job = None
    app._ping_inflight = {}
    app._ping_inflight_lock = __import__('threading').Lock()
    app.executor = FakeExecutor()
    app.master = FakeMaster()
    app._ping_task = lambda _user: None
    app._dispatch_ping_batch(1)
    assert_eq(len(app.executor.submitted), 2, 'ping submissions are bounded by worker count')
    assert_eq(len(app._ping_inflight), 2, 'ping inflight accounting')
    assert_eq(len(app._pending_ping_users), 1, 'remaining ping stays in app queue')
    assert app._ping_queue_job is not None


def test_broken_json_and_safe_save():
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, 'broken.json')
        with open(p, 'w', encoding='utf-8') as f:
            f.write('{broken')
        data = mod.load_json(p, default={'ok': 1})
        assert_eq(data, {'ok': 1}, 'load_json fallback')

        p2 = os.path.join(td, 'data.json')
        mod.safe_save_json(p2, {'a': 1})
        data2 = mod.load_json(p2, default={})
        assert_eq(data2.get('a'), 1, 'safe_save_json read')

def test_safe_save_json_cleans_temp_on_error():
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, 'data.json')
        original_replace = mod.os.replace
        try:
            mod.os.replace = lambda _a, _b: (_ for _ in ()).throw(RuntimeError('boom'))
            try:
                mod.safe_save_json(p, {'x': 1})
            except RuntimeError:
                pass
        finally:
            mod.os.replace = original_replace
        leftovers = [name for name in os.listdir(td) if name != 'data.json']
        assert_eq(leftovers, [], 'temp files should be cleaned')


def test_callwatcher_parse_helpers():
    block = 'Endpoint: 101 / 101\nExten: 101\nChannel: SIP/101 Up\nCLCID: "Иванов И.И." <79990001122>\nRinging'
    parsed = mod.parse_caller_from_block(block, '101')
    assert parsed is not None, 'parse helper returned None'
    num, name = parsed
    assert_eq(mod.normalize_phone(num), '79990001122', 'parse num')
    assert 'иванов' in name.lower(), 'parse name'
    mixed_name = mod.parse_person_name('Мальцев Сергей В.')
    assert_eq(mixed_name.get('first_init'), 'с', 'full first name initial')
    assert_eq(mixed_name.get('middle_init'), 'в', 'middle initial after full first name')


def test_printer_monitor_launcher_contract():
    command = build_printer_monitor_command('pythonw.exe', r'C:\Data\printers.txt')
    assert_eq(command[:3], ['pythonw.exe', '-m', 'prn_site_ping'], 'print monitor module')
    assert_eq(command[3:5], ['--config', r'C:\Data\printers.txt'], 'print monitor config')

    class RunningProcess:
        @staticmethod
        def poll():
            return None

    launcher = PrinterMonitorLauncher(working_directory=ROOT)
    launcher._process = RunningProcess()
    assert launcher.is_running, 'duplicate launch guard'


def test_embedded_adhelper2_command():
    query = 'ivanov'
    command, working_directory, show_bootstrap_console = mod.build_adhelper2_command(query)
    assert_eq(os.path.basename(working_directory), 'adhelper2', 'ADHelper2 working directory')
    batch_files = [item for item in command if str(item).lower().endswith('run_adhelper.bat')]
    assert batch_files, 'embedded ADHelper2 bootstrap not found'
    assert os.path.isfile(batch_files[0]), 'embedded ADHelper2 bootstrap path not found'
    ready_marker = os.path.join(working_directory, '.venv', '.adhelper-ready')
    assert_eq(show_bootstrap_console, not os.path.isfile(ready_marker), 'ADHelper2 bootstrap visibility')
    search_index = command.index('--search')
    assert_eq(command[search_index + 1], query, 'ADHelper2 search query')
    assert '--autorun' in command, 'ADHelper2 autorun flag missing'

    batch_source = open(batch_files[0], encoding='utf-8').read()
    assert 'import PySide6' in batch_source, 'ADHelper2 bootstrap dependency check missing'
    assert '.adhelper-ready' in batch_source, 'ADHelper2 bootstrap ready marker missing'
    assert 'pythonw.exe' in batch_source, 'ADHelper2 GUI launcher missing'
    assert 'pip install -r requirements.txt' in batch_source, 'ADHelper2 dependency installation missing'


if __name__ == '__main__':
    tests = [
        test_normalize_phone,
        test_canonical_pc_key,
        test_release_version_comparison,
        test_os_specific_context_actions,
        test_multi_pc_os_cache_and_merge,
        test_card_contact_line_with_location,
        test_batched_settings_and_glpi_timeout,
        test_incremental_card_sync_and_deferred_ad_lookup,
        test_ping_dispatch_is_bounded,
        test_broken_json_and_safe_save,
        test_safe_save_json_cleans_temp_on_error,
        test_callwatcher_parse_helpers,
        test_printer_monitor_launcher_contract,
        test_embedded_adhelper2_command,
    ]
    for t in tests:
        t()
        print(f'[OK] {t.__name__}')
    print('Selftest completed.')
