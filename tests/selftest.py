import hashlib
import json
import os
import socket
import shutil
import subprocess
import tempfile
import sys
import types
import zipfile
from urllib import request
from pathlib import Path

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(ROOT, 'src'))

from tshelper import app as mod  # noqa: E402
from tshelper.glpi_inventory import (  # noqa: E402
    InventoryBridgeState,
    apply_recommendation,
    recommend_inventory_update,
)
from tshelper.browser_integration import BrowserIntegrationServer  # noqa: E402
from tshelper.printer_monitor_launcher import (  # noqa: E402
    PrinterMonitorLauncher,
    build_printer_monitor_command,
)
from tshelper.updater import (  # noqa: E402
    MANAGED_DIRECTORIES,
    ReleaseInfo,
    UpdateError,
    can_self_update,
    download_release,
    extract_release_archive,
    find_update_launcher,
    select_release_asset,
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


def test_secure_portable_update_contract():
    assert_eq(
        mod.UPDATE_CHECK_INTERVAL_MS,
        3 * 60 * 60 * 1000,
        'periodic update interval',
    )
    digest = 'a' * 64
    payload = {
        'tag_name': 'v9.9.9',
        'html_url': 'https://github.com/Et0ZheMax/tshelper/releases/tag/v9.9.9',
        'assets': [{
            'name': 'TSHelper-v9.9.9-portable.zip',
            'browser_download_url': (
                'https://github.com/Et0ZheMax/tshelper/releases/download/'
                'v9.9.9/TSHelper-v9.9.9-portable.zip'
            ),
            'digest': f'sha256:{digest}',
            'size': 123,
        }],
    }
    release = select_release_asset(payload)
    assert_eq(release.version, '9.9.9', 'updater release version')
    assert_eq(release.asset_digest, digest, 'updater release digest')

    missing_digest = dict(payload)
    missing_digest['assets'] = [dict(payload['assets'][0], digest='')]
    try:
        select_release_asset(missing_digest)
        raise AssertionError('release without digest was accepted')
    except UpdateError:
        pass

    with tempfile.TemporaryDirectory() as temp_dir:
        content = b'portable-update'

        class FakeResponse:
            status_code = 200

            def iter_content(self, chunk_size):
                del chunk_size
                yield content[:5]
                yield content[5:]

            def close(self):
                pass

        class FakeClient:
            @staticmethod
            def get(*args, **kwargs):
                del args, kwargs
                return FakeResponse()

        download_info = ReleaseInfo(
            tag='v9.9.9', version='9.9.9', html_url='', asset_name='download.zip', asset_url='https://example.invalid/update',
            asset_digest=hashlib.sha256(content).hexdigest(), asset_size=len(content),
        )
        downloaded = download_release(
            download_info, Path(temp_dir) / 'download', http_client=FakeClient()
        )
        assert_eq(downloaded.read_bytes(), content, 'verified updater download')

        root = os.path.join(temp_dir, 'work')
        os.makedirs(root)
        archive = os.path.join(temp_dir, 'update.zip')
        package = 'TSHelper-v9.9.9'
        with zipfile.ZipFile(archive, 'w') as bundle:
            for directory in MANAGED_DIRECTORIES:
                bundle.writestr(f'{package}/{directory}/', '')
            bundle.writestr(f'{package}/src/tshelper/version.py', '__version__ = "9.9.9"\n')
            bundle.writestr(f'{package}/scripts/apply_update.ps1', '# updater\n')
            bundle.writestr(f'{package}/requirements.txt', 'requests\n')
            bundle.writestr(f'{package}/pyproject.toml', '[project]\nname="tshelper"\n')
            bundle.writestr(f'{package}/run_tshelper.bat', '@echo off\n')
        archive_digest = hashlib.sha256(Path(archive).read_bytes()).hexdigest()
        archive_size = os.path.getsize(archive)
        archive_release = ReleaseInfo(
            tag='v9.9.9', version='9.9.9', html_url='', asset_name='update.zip', asset_url='',
            asset_digest=archive_digest, asset_size=archive_size,
        )
        extraction_progress = []
        extracted = extract_release_archive(
            archive_release,
            Path(archive),
            Path(root),
            progress=lambda stage, current, total: extraction_progress.append(
                (stage, current, total)
            ),
        )
        assert os.path.isfile(os.path.join(extracted, 'scripts', 'apply_update.ps1'))
        assert any(
            stage == 'Распаковка обновления' and current == total
            for stage, current, total in extraction_progress
        ), 'archive extraction progress did not reach completion'

        unsafe_archive = os.path.join(temp_dir, 'unsafe.zip')
        with zipfile.ZipFile(unsafe_archive, 'w') as bundle:
            bundle.writestr('../escape.txt', 'blocked')
        try:
            extract_release_archive(archive_release, Path(unsafe_archive), Path(root))
            raise AssertionError('path traversal archive was accepted')
        except UpdateError:
            pass

        install_root = Path(temp_dir) / 'source-layout'
        (install_root / 'src/tshelper').mkdir(parents=True)
        (install_root / 'src/tshelper/version.py').write_text('__version__ = "9.9.9"\n')
        (install_root / 'pyproject.toml').write_text('[project]\nname="tshelper"\n')
        (install_root / 'scripts').mkdir()
        (install_root / 'scripts/run_tshelper.bat').write_text('@echo off\n')
        (install_root / '.git').mkdir()
        assert_eq(
            find_update_launcher(install_root),
            (install_root / 'scripts/run_tshelper.bat').resolve(),
            'source checkout launcher',
        )
        if os.name == 'nt':
            assert can_self_update(install_root), 'source checkout update was disabled'

        unsafe_ads_archive = os.path.join(temp_dir, 'unsafe-ads.zip')
        with zipfile.ZipFile(unsafe_ads_archive, 'w') as bundle:
            bundle.writestr(f'{package}/src/evil:stream', 'blocked')
        try:
            extract_release_archive(
                archive_release, Path(unsafe_ads_archive), Path(root)
            )
            raise AssertionError('NTFS alternate data stream was accepted')
        except UpdateError:
            pass

    updater_script = os.path.join(ROOT, 'scripts', 'apply_update.ps1')
    powershell = shutil.which('powershell.exe') or shutil.which('powershell')
    assert powershell, 'Windows PowerShell not found for updater parser test'
    escaped_updater_script = updater_script.replace("'", "''")
    parse_command = (
        "$errors=$null; [System.Management.Automation.Language.Parser]::ParseFile("
        f"'{escaped_updater_script}', [ref]$null, [ref]$errors) | Out-Null; "
        "if ($errors.Count) { $errors | ForEach-Object { Write-Error $_ }; exit 1 }"
    )
    parsed = subprocess.run([powershell, '-NoProfile', '-Command', parse_command], capture_output=True, text=True)
    assert_eq(parsed.returncode, 0, f'updater PowerShell syntax: {parsed.stderr}')
    updater_source = Path(updater_script).read_text(encoding='utf-8-sig')
    assert 'Initialize-ProgressWindow' in updater_source, 'installer progress window is missing'
    assert 'scripts\\run_tshelper.bat' in updater_source, 'source launcher is not supported'


def test_noisy_powershell_json_and_paged_ad_search():
    noisy = (
        'ПРЕДУПРЕЖДЕНИЕ: Ошибка при инициализации диска по умолчанию: '
        '"Сервер неработоспособен".\n[{"sam":"new.user"}]'
    )
    decoded, warning = mod.decode_json_output(noisy)
    assert_eq(decoded, [{'sam': 'new.user'}], 'PowerShell JSON after warning')
    assert 'ПРЕДУПРЕЖДЕНИЕ' in warning, 'PowerShell warning should be preserved for logging'

    created_connections = []

    class FakePagedSearch:
        def __init__(self):
            self.kwargs = None

        def paged_search(self, **kwargs):
            self.kwargs = kwargs
            return iter([
                {'type': 'searchResEntry', 'attributes': {
                    'cn': 'Старый Пользователь', 'sAMAccountName': 'old.user',
                    'ipPhone': '4100', 'physicalDeliveryOfficeName': 'Щ5-101',
                }},
                {'type': 'searchResRef', 'uri': ['ldap://example.test']},
                {'type': 'searchResEntry', 'attributes': {
                    'cn': 'Новый Пользователь', 'sAMAccountName': 'new.user',
                    'telephoneNumber': '4200', 'l': 'Щ5-104',
                }},
            ])

    class FakeConnection:
        def __init__(self, *_args, **_kwargs):
            self.standard = FakePagedSearch()
            self.extend = types.SimpleNamespace(standard=self.standard)
            self.unbound = False
            created_connections.append(self)

        def unbind(self):
            self.unbound = True

    fake_ldap3 = types.SimpleNamespace(
        NONE=object(), SUBTREE=object(), Server=lambda *_args, **_kwargs: object(), Connection=FakeConnection
    )
    previous_ldap3 = sys.modules.get('ldap3')
    sys.modules['ldap3'] = fake_ldap3
    try:
        users = mod.get_ad_users('dc.test', 'operator', 'secret', 'DC=test', 'test', raise_errors=True)
    finally:
        if previous_ldap3 is None:
            sys.modules.pop('ldap3', None)
        else:
            sys.modules['ldap3'] = previous_ldap3

    assert_eq([user['pc_name'] for user in users], ['w-old.user', 'w-new.user'], 'all AD pages')
    assert_eq(users[1]['location'], 'Щ5-104', 'paged AD location')
    assert_eq(created_connections[0].standard.kwargs['paged_size'], 500, 'AD page size')
    assert created_connections[0].standard.kwargs['generator'], 'paged search generator'
    assert created_connections[0].unbound, 'LDAP connection should be closed'


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
        incoming = {
            'name': 'Тест', 'pc_name': 'w-test', 'pc_options': [], 'ad_login': 'test',
            'pc_source': 'ad_guess', 'ext': '4443', 'location': 'Щ5-104'
        }
        merged = app._merge_user_records(existing, incoming)
        assert_eq(merged['pc_name'], 'l-test', 'AD sync keeps selected primary PC')
        assert_eq(merged['pc_options'], [], 'AD guess does not create opposite-prefix duplicate')
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


def test_glpi_inventory_queue_and_safe_reconciliation():
    user = {
        'name': 'Тест', 'ad_login': 'test', 'pc_name': 'w-test',
        'pc_options': ['l-test', 'w-shared'], 'ext': '4443'
    }
    record = {
        'login': 'test', 'status': 'ok', 'resolution': 'exact-login',
        'glpi_user_id': 42, 'checked_at': '2026-08-27T10:00:00+00:00',
        'computers': [{
            'asset_id': 101, 'hostname': 'l-test', 'os_family': 'linux',
            'os_name': 'Astra Linux', 'is_active': True
        }]
    }
    recommendation = recommend_inventory_update(user, record)
    assert recommendation['safe']
    assert recommendation['changed']
    assert_eq(recommendation['new_main'], 'l-test', 'GLPI exact Computer becomes primary')
    assert_eq(recommendation['new_options'], ['w-shared'], 'unrelated PC survives reconciliation')
    updated = apply_recommendation(user, recommendation)
    assert_eq(updated['pc_source'], 'glpi_html', 'reconciled source is stored')
    assert_eq(updated['glpi_user_id'], 42, 'GLPI identity is stored')

    ambiguous = dict(record)
    ambiguous['computers'] = record['computers'] + [{
        'asset_id': 102, 'hostname': 'w-test2', 'os_family': 'windows', 'is_active': True
    }]
    assert not recommend_inventory_update(user, ambiguous)['safe']

    with tempfile.TemporaryDirectory() as td:
        state_path = os.path.join(td, 'inventory.json')
        state = InventoryBridgeState(state_path)
        first_id = state.enqueue(user, 'full_sync', priority=10)
        assert first_id
        assert_eq(state.enqueue(user, 'ping_failed', priority=100), first_id, 'queue deduplicates login')
        job = state.next_job()['job']
        assert_eq(job['id'], first_id, 'queued job can be claimed')
        completed = state.complete({
            'job_id': first_id, 'login': 'test', 'status': 'ok',
            'resolution': 'exact-login', 'glpi_user_id': 42,
            'computers': [{
                'itemtype': 'Computer', 'id': 101, 'name': 'l-test',
                'os': 'Astra Linux', 'status': 'В работе', 'relation': 'Пользователь'
            }]
        })
        assert completed['ok']
        assert_eq(state.hosts_for_login('test'), ['l-test'], 'inventory host cache')
        assert_eq(state.os_for_host('l-test'), 'linux', 'inventory OS cache')
        reloaded = InventoryBridgeState(state_path)
        assert_eq(reloaded.record_for_login('test')['glpi_user_id'], 42, 'inventory cache persists')

        session_user = dict(user, ad_login='session-test', pc_name='w-session-test')
        session_job_id = reloaded.enqueue(session_user, 'full_sync')
        reloaded.next_job()
        reloaded.complete({
            'job_id': session_job_id, 'login': 'session-test',
            'status': 'session_required', 'error': 'login required'
        })
        session_status = reloaded.status()
        assert_eq(session_status['pending'], 1, 'expired GLPI session keeps job queued')
        assert session_status['paused_seconds'] > 0
        assert_eq(reloaded.next_job()['job'], None, 'expired GLPI session pauses whole queue')


def test_browser_bridge_inventory_routes_and_legacy_open_user():
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]

    received = []
    server = BrowserIntegrationServer(
        host='127.0.0.1', port=port, token='x' * 32,
        open_user_callback=lambda payload: {'ok': payload.get('login') == 'test'},
        inventory_next_callback=lambda: {'ok': True, 'job': {'id': 'job-1', 'login': 'test'}},
        inventory_result_callback=lambda payload: received.append(payload) or {'ok': True},
        inventory_status_callback=lambda: {'ok': True, 'pending': 1},
    )
    server.start()

    def call(path, payload=None):
        body = json.dumps(payload).encode('utf-8') if payload is not None else None
        req = request.Request(
            f'http://127.0.0.1:{port}{path}', data=body,
            headers={'X-TSHelper-Token': 'x' * 32, 'Content-Type': 'application/json'},
        )
        return json.loads(request.urlopen(req, timeout=3).read().decode('utf-8'))

    try:
        assert_eq(call('/health')['bridge'], '1.1', 'browser bridge protocol version')
        assert_eq(call('/inventory/jobs/next')['job']['id'], 'job-1', 'inventory job route')
        assert_eq(call('/inventory/status')['pending'], 1, 'inventory status route')
        assert call('/inventory/jobs/result', {'job_id': 'job-1', 'status': 'ok'})['ok']
        assert_eq(received[0]['job_id'], 'job-1', 'inventory result callback')
        assert call('/open-user', {'login': 'test'})['ok']
    finally:
        server.stop()


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
        def __init__(self, payload=None):
            self.payload = payload or {'data': []}
            self.content = b'{}'

        @staticmethod
        def raise_for_status():
            return None

        def json(self):
            return self.payload

    class FakeSession:
        def get(self, url, **kwargs):
            calls.append((url, kwargs))
            if url.endswith('/initSession'):
                return FakeResponse({'session_token': 'opened-with-get'})
            return FakeResponse()

    client = mod.GLPIClient('https://glpi.invalid/apirest.php', 'app', 'user', request_timeout=7)
    client.session = FakeSession()
    client.session_token = 'session'
    client._search('User', 'test')
    assert_eq(calls[0][1].get('timeout'), 7, 'GLPI request timeout')

    session_client = mod.GLPIClient('https://glpi.invalid/apirest.php', 'app', 'user')
    session_client.session = FakeSession()
    assert session_client._init_session()
    assert_eq(session_client.session_token, 'opened-with-get', 'GLPI initSession uses GET response')


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

    constants_source = open(os.path.join(working_directory, 'adhelper', 'constants.py'), encoding='utf-8').read()
    package_source = open(os.path.join(working_directory, 'adhelper', '__init__.py'), encoding='utf-8').read()
    assert 'APP_VERSION = "2.1.0"' in constants_source, 'embedded ADHelper2 application version'
    assert '__version__ = "2.1.0"' in package_source, 'embedded ADHelper2 package version'


if __name__ == '__main__':
    tests = [
        test_normalize_phone,
        test_canonical_pc_key,
        test_release_version_comparison,
        test_secure_portable_update_contract,
        test_noisy_powershell_json_and_paged_ad_search,
        test_os_specific_context_actions,
        test_multi_pc_os_cache_and_merge,
        test_glpi_inventory_queue_and_safe_reconciliation,
        test_browser_bridge_inventory_routes_and_legacy_open_user,
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
