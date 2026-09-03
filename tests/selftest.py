import hashlib
import json
import os
import socket
import shutil
import subprocess
import tempfile
import sys
import time
import types
import zipfile
from urllib import request
from pathlib import Path

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(ROOT, 'src'))

from tshelper import app as mod  # noqa: E402
from tshelper.glpi_inventory import (  # noqa: E402
    InventoryBridgeState,
    JOB_LEASE_SECONDS,
    apply_inventory_computers,
    apply_recommendation,
    choose_primary_computer,
    is_remote_access_hostname,
    login_from_hostname,
    normalize_computers,
    recommend_inventory_update,
)
from tshelper.browser_integration import BrowserIntegrationServer  # noqa: E402
from tshelper.printer_monitor_launcher import (  # noqa: E402
    PrinterMonitorLauncher,
    build_printer_monitor_command,
)
from tshelper.ping_worker import PingProcessClient, ping_candidates  # noqa: E402
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
    assert_eq(mod.glpi_time_utc3('2026-09-03T06:58:41.000Z'), '09:58:41', 'GLPI monitor UTC+3 time')


def test_release_version_comparison():
    assert mod.is_newer_release('v5.10', 'v5.9.2')
    assert not mod.is_newer_release('v5.9', 'v5.9.2')
    assert not mod.is_newer_release('v5.9.2', '5.9.2')
    assert not mod.is_newer_release('неизвестно', 'v5.9.2')


def test_manual_update_check_feedback():
    window = mod.MainWindow.__new__(mod.MainWindow)
    window._update_check_running = True
    window._update_prompted_version = ''
    window._schedule_next_update_check = lambda: None
    offered = []
    window._offer_update = lambda release: offered.append(release.tag)
    notices = []
    errors = []
    original_showinfo = mod.messagebox.showinfo
    original_showerror = mod.messagebox.showerror
    try:
        mod.messagebox.showinfo = lambda title, message: notices.append((title, message))
        mod.messagebox.showerror = lambda title, message: errors.append((title, message))
        current_release = types.SimpleNamespace(tag=mod.VERSION, version=mod.VERSION.lstrip('v'))
        window._finish_update_check(current_release, None, manual=True)
        assert notices and 'актуальная версия' in notices[-1][1]

        newer_release = types.SimpleNamespace(tag='v99.0.0', version='99.0.0')
        window._finish_update_check(newer_release, None, manual=True)
        assert_eq(offered, ['v99.0.0'], 'manual update check offers newer release')

        window._finish_update_check(None, 'network unavailable', manual=True)
        assert errors and 'network unavailable' in errors[-1][1]
    finally:
        mod.messagebox.showinfo = original_showinfo
        mod.messagebox.showerror = original_showerror

    app_source = (Path(ROOT) / 'src' / 'tshelper' / 'app.py').read_text(encoding='utf-8')
    assert 'label="Проверить обновления", command=self.check_for_updates' in app_source


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
    assert 'Preserve-AdHelperEnvironment' in updater_source, 'ADHelper environment preservation is missing'
    assert 'Restore-AdHelperEnvironment' in updater_source, 'ADHelper environment restoration is missing'
    assert '.requirements.sha256' in updater_source, 'ADHelper requirements marker is missing'


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
            self.requests = []

        def paged_search(self, **kwargs):
            self.requests.append(kwargs)
            if kwargs['search_base'].startswith('OU=Уволенные'):
                return iter([
                    {'type': 'searchResEntry', 'attributes': {
                        'cn': 'Уволенный Пользователь', 'sAMAccountName': 'fired.user',
                    }},
                ])
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
        users, dismissed = mod.get_ad_users(
            'dc.test', 'operator', 'secret', 'DC=test', 'test',
            dismissed_base_dn='OU=Уволенные,DC=test', raise_errors=True,
        )
    finally:
        if previous_ldap3 is None:
            sys.modules.pop('ldap3', None)
        else:
            sys.modules['ldap3'] = previous_ldap3

    assert_eq([user['pc_name'] for user in users], ['w-old.user', 'w-new.user'], 'all AD pages')
    assert_eq([user['pc_name'] for user in dismissed], ['w-fired.user'], 'dismissed AD users')
    assert_eq(users[1]['location'], 'Щ5-104', 'paged AD location')
    requests = created_connections[0].standard.requests
    assert_eq([item['search_base'] for item in requests], ['DC=test', 'OU=Уволенные,DC=test'], 'AD search bases')
    assert all(item['paged_size'] == 500 for item in requests), 'AD page size'
    assert all(item['generator'] for item in requests), 'paged search generator'
    assert created_connections[0].unbound, 'LDAP connection should be closed'

    active_cards, dismissed_cards = mod.partition_dismissed_ad_users(
        [
            {'name': 'Старый Пользователь', 'pc_name': 'l-old.user', 'ad_login': 'old.user'},
            {'name': 'Уволенный Пользователь', 'pc_name': 'l-fired.user'},
            {'name': 'Уволенный Пользователь', 'pc_name': 'l-other', 'ad_login': 'other.user'},
        ],
        dismissed,
    )
    assert_eq([user['pc_name'] for user in dismissed_cards], ['l-fired.user'], 'dismissed cards')
    assert_eq([user['pc_name'] for user in active_cards], ['l-old.user', 'l-other'], 'active cards')


def test_os_specific_context_actions():
    windows = set(mod.context_action_ids('windows'))
    linux = set(mod.context_action_ids('linux'))
    combined = set(mod.context_action_ids('windows', combine_functionality=True))

    assert {'remote_assistance', 'powershell', 'explorer', 'windows_deploy', 'elma'} <= windows
    assert not {'ssh', 'ssh_key', 'linux_install'} & windows
    assert {'remote_linux', 'ssh', 'ssh_key', 'linux_install'} <= linux
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
    assert 'Remote Linux' not in windows_menu.labels
    assert 'Remote Linux' in linux_menu.labels
    assert 'Windows Deployment' in windows_menu.labels

    profile_by_name = mod.build_remote_linux_rdp_config('l-test')
    assert 'full address:s:l-test:3390' in profile_by_name
    assert 'username:s:support' in profile_by_name
    profile_by_ip = mod.build_remote_linux_rdp_config('10.20.30.40')
    assert 'full address:s:10.20.30.40:3390' in profile_by_ip
    try:
        mod.build_remote_linux_rdp_config('l-test\r\nusername:s:admin')
    except ValueError:
        pass
    else:
        raise AssertionError('RDP profile must reject line breaks in host')


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
        assert_eq(mod.user_pc_names({'pc_name': 'wr-test', 'pc_options': ['lr-test', 'w-test']}), ['w-test'], 'remote PCs are hidden')
        assert_eq(app.build_host_candidates({'pc_name': 'wr-test', 'pc_options': ['lr-test']}), [], 'remote PCs have no actions')
        assert_eq(
            app.get_user_pc_display({'pc_name': 'w-test', 'pc_options': ['l-test', 'tv-test', 'w-spare']}),
            'w-test · ещё 3 ПК',
            'large computer lists stay compact in cards',
        )
        assert mod.needs_primary_pc_confirmation({'pc_name': 'w-test', 'pc_options': ['l-test']})
        assert not mod.needs_primary_pc_confirmation({
            'pc_name': 'w-test', 'pc_options': ['l-test'], 'pc_primary_confirmed': True
        })

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
    assert_eq(JOB_LEASE_SECONDS, 90, 'lost inventory job recovery timeout')
    assert is_remote_access_hostname('LR-test.example.local')
    assert is_remote_access_hostname('wr-test')
    assert not is_remote_access_hostname('w-test')
    assert_eq(login_from_hostname('wr-test'), 'test', 'remote prefix login normalization')
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
    already_matching = recommend_inventory_update(updated, record)
    assert already_matching['safe'] and not already_matching['changed']
    assert_eq(already_matching['reason'], 'Уже совпадает с GLPI', 'matching inventory report reason')

    remote_record = dict(record)
    remote_record['computers'] = record['computers'] + [{
        'asset_id': 103, 'hostname': 'wr-test', 'os_family': 'windows', 'is_active': True
    }]
    remote_recommendation = recommend_inventory_update(user, remote_record)
    assert remote_recommendation['safe'], 'remote PC must not make reconciliation ambiguous'
    assert_eq(remote_recommendation['new_main'], 'l-test', 'remote PC is ignored by reconciliation')

    ambiguous = dict(record)
    ambiguous['computers'] = record['computers'] + [{
        'asset_id': 102, 'hostname': 'w-test2', 'os_family': 'windows', 'is_active': True
    }]
    assert not recommend_inventory_update(user, ambiguous)['safe']

    multi_user = dict(user, pc_name='l-test', pc_options=['w-old-guess'])
    imported = apply_inventory_computers(multi_user, ambiguous)
    assert_eq(imported['pc_name'], 'l-test', 'existing GLPI host is retained as provisional primary')
    assert_eq(imported['pc_options'], ['w-test2'], 'all active GLPI computers replace old guesses')
    assert not imported['pc_primary_confirmed'], 'multiple computers require first-use confirmation'
    selected = choose_primary_computer(imported, 'W-TEST2')
    assert_eq(selected['pc_name'], 'w-test2', 'manual primary selection is case-insensitive')
    assert_eq(selected['pc_options'], ['l-test'], 'temporary alternatives remain in the card')
    assert selected['pc_primary_confirmed'], 'manual primary selection is persisted'
    try:
        choose_primary_computer(imported, 'w-missing')
    except ValueError:
        pass
    else:
        raise AssertionError('unknown primary computer must be rejected')

    with tempfile.TemporaryDirectory() as td:
        manager = mod.UserManager(os.path.join(td, 'users.json'))
        manager.users = [{
            'name': 'Тест', 'ad_login': 'test', 'pc_name': 'l-test',
            'pc_options': [], 'pc_primary_confirmed': True,
        }]
        manager.save()
        app = mod.MainWindow.__new__(mod.MainWindow)
        app.users = manager
        app._ensure_glpi_inventory_auto_backup = lambda: None
        app.populate_buttons = lambda: None
        prompted = []
        app._prompt_glpi_primary_computer = lambda updated: prompted.append(dict(updated))
        app._handle_glpi_inventory_completed({'reason': 'ip_lookup'}, ambiguous)
        refreshed = manager.get_users()[0]
        assert_eq(refreshed['pc_name'], 'l-test', 'IP lookup keeps current GLPI host selected by default')
        assert_eq(refreshed['pc_options'], ['w-test2'], 'IP lookup imports a newly found GLPI computer')
        assert not refreshed['pc_primary_confirmed'], 'new multi-PC inventory requires explicit primary selection'
        assert_eq(len(prompted), 1, 'new multi-PC inventory opens the primary-PC question')

    app_source = open(os.path.join(ROOT, 'src', 'tshelper', 'app.py'), encoding='utf-8').read()
    get_ip_body = app_source.split('    def get_ip(', 1)[1].split('    def reset_password_ps(', 1)[0]
    assert 'glpi_job_id = self.app.enqueue_glpi_inventory_for_ip_lookup' in get_ip_body, 'Get IP must enqueue the selected GLPI card immediately'
    assert get_ip_body.index('enqueue_glpi_inventory_for_ip_lookup') < get_ip_body.index('def task()'), 'selected GLPI card must be queued before IP lookup starts'

    reset_password_body = app_source.split('    def reset_password_ps(', 1)[1].split('    def check_account_lockouts(', 1)[0]
    assert 'sam = login_from_user(self.user)' in reset_password_body, 'password reset must use the AD login, not the computer name'
    assert '[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)' in reset_password_body, 'password reset must return readable UTF-8 PowerShell errors'

    assert 'Внести все ПК в карточки' in app_source, 'multiple-PC report action missing'
    assert 'label="Проверить на блокировки"' in app_source, 'account lockout action missing from context menu'
    lockout_body = app_source.split('    def check_account_lockouts(', 1)[1].split('    def _show_account_lockout_result(', 1)[0]
    assert "-Properties LockedOut" in lockout_body, 'lockout check must request the AD LockedOut property'
    assert 'pak-cspmz.ru' in lockout_body and 'omg.cspfmba.ru' in lockout_body, 'lockout check must cover both domains'
    unlock_body = app_source.split('    def _unlock_accounts(', 1)[1].split('    def _show_unlock_result(', 1)[0]
    assert 'Unlock-ADAccount' in unlock_body, 'locked account action must support unlocking'
    assert "if ([bool]$account.LockedOut)" in unlock_body, 'unlocking must verify the resulting AD state'
    assert 'self.master.after(0, self._show_tray_icon)' in app_source, 'tray icon must be created while the main window is open'
    on_map_body = app_source.split('    def _on_map(', 1)[1].split('    def minimize_app(', 1)[0]
    restore_body = app_source.split('    def restore_main_window(', 1)[1].split('    def _remember_mini_geometry(', 1)[0]
    assert '_hide_tray_icon()' not in on_map_body, 'mapping the main window must keep the tray icon'
    assert '_hide_tray_icon()' not in restore_body, 'restoring the main window must keep the tray icon'
    shortcut_source = open(os.path.join(ROOT, 'scripts', 'create_tshelper_shortcut.ps1'), encoding='utf-8-sig').read()
    assert 'TSHelper.lnk' in shortcut_source, 'Start menu shortcut is missing'
    assert 'assets\\ts-logo.ico' in shortcut_source, 'shortcut must use the branded icon'
    launcher_source = open(os.path.join(ROOT, 'scripts', 'run_tshelper.bat'), encoding='utf-8').read()
    assert 'create_tshelper_shortcut.ps1' in launcher_source, 'launcher must create the pinnable shortcut'
    assert 'SetCurrentProcessExplicitAppUserModelID(WINDOWS_APP_USER_MODEL_ID)' in app_source, 'running window must have the TSHelper AppUserModelID'
    assert 'Et0ZheMax.TSHelper' in shortcut_source, 'shortcut must share the application AppUserModelID'
    assert '9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3' in shortcut_source, 'shortcut AppUserModelID property key is missing'
    assert 'ДЕЙСТВИЯ С ДРУГИМ ПК' in app_source, 'temporary computer switch is not highlighted'
    assert 'ВЫБРАТЬ ДРУГОЙ ПК — ТОЛЬКО НА ЭТО ДЕЙСТВИЕ' not in app_source, 'wide menu label remains'
    search_body = app_source.split('    def _do_search(', 1)[1].split('    def _schedule_ping_batch(', 1)[0]
    assert 'populate_buttons(' not in search_body, 'search still performs full card synchronization'
    assert '_compute_view_state(' in search_body, 'search delta rendering is missing'

    with tempfile.TemporaryDirectory() as td:
        state_path = os.path.join(td, 'inventory.json')
        state = InventoryBridgeState(state_path)
        first_id = state.enqueue(user, 'full_sync', priority=10)
        assert first_id
        assert_eq(state.enqueue(user, 'ping_failed', priority=100), first_id, 'queue deduplicates login')
        pause_result = state.pause()
        assert pause_result['manually_paused']
        assert not pause_result['finishing_current']
        assert state.status()['manually_paused']
        assert_eq(state.next_job()['job'], None, 'manual pause blocks claiming jobs')
        assert InventoryBridgeState(state_path).status()['manually_paused'], 'manual pause persists'
        state.resume()
        assert not state.status()['manually_paused']
        job = state.next_job()['job']
        assert_eq(job['id'], first_id, 'queued job can be claimed')
        state.progress({
            'job_id': first_id, 'login': 'test',
            'stage': 'Проверка login', 'message': 'User #42'
        })
        live_status = state.status()
        assert_eq(live_status['current_job']['progress_stage'], 'Проверка login', 'live inventory stage')
        completed = state.complete({
            'job_id': first_id, 'login': 'test', 'status': 'ok',
            'resolution': 'exact-login', 'glpi_user_id': 42,
            'computers': [
                {
                    'itemtype': 'Computer', 'id': 101, 'name': 'l-test',
                    'os': 'Astra Linux', 'status': 'В работе', 'relation': 'Пользователь'
                },
                {
                    'itemtype': 'Computer', 'id': 102, 'name': 'wr-test',
                    'os': 'Windows 11', 'status': 'В работе', 'relation': 'Пользователь'
                },
            ]
        })
        assert completed['ok']
        assert_eq(state.hosts_for_login('test'), ['l-test'], 'inventory host cache')
        assert_eq(state.os_for_host('l-test'), 'linux', 'inventory OS cache')
        assert_eq(state.os_for_host('test'), 'linux', 'inventory OS cache matches an unprefixed AD host')
        assert_eq(state.status()['processed'], 1, 'completed inventory progress count')
        state.pause()
        queued_while_paused = dict(user, ad_login='paused-test', pc_name='w-paused-test')
        state.enqueue(queued_while_paused, 'full_sync', force=True)
        assert state.status()['manually_paused'], 'forced enqueue must not cancel manual pause'
        assert_eq(state.next_job()['job'], None, 'paused queue keeps newly added jobs pending')
        state.resume()
        paused_job = state.next_job()['job']
        state.complete({
            'job_id': paused_job['id'], 'login': 'paused-test',
            'status': 'not_found', 'resolution': 'exact-login'
        })
        reloaded = InventoryBridgeState(state_path)
        assert_eq(reloaded.record_for_login('test')['glpi_user_id'], 42, 'inventory cache persists')

        corrected = normalize_computers([{
            'itemtype': 'Computer', 'id': 1820, 'name': 'W-ALAVROV',
            'os': 'Ubuntu 24.04.1 LTS', 'os_family': 'linux', 'status': '-----'
        }])
        assert_eq(corrected[0]['os_family'], 'windows', 'explicit W- prefix overrides a conflicting parsed OS')

        legacy_state_path = os.path.join(td, 'legacy_inventory.json')
        Path(legacy_state_path).write_text(json.dumps({
            'records': {'alavrov': {
                'login': 'alavrov', 'status': 'ok', 'resolution': 'exact-login',
                'computers': [{
                    'asset_id': 1820, 'hostname': 'W-ALAVROV',
                    'os_name': 'Ubuntu 24.04.1 LTS', 'os_family': 'linux'
                }]
            }}
        }), encoding='utf-8')
        legacy_state = InventoryBridgeState(legacy_state_path)
        assert_eq(legacy_state.os_for_host('W-ALAVROV'), 'windows', 'legacy GLPI cache is normalized on load')

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
        assert_eq(reloaded.queue_info_for_login('session-test')['position'], 1, 'pending queue position')
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
        inventory_progress_callback=lambda payload: received.append(payload) or {'ok': True},
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
        assert call('/inventory/jobs/progress', {'job_id': 'job-1', 'stage': 'search'})['ok']
        assert call('/inventory/jobs/result', {'job_id': 'job-1', 'status': 'ok'})['ok']
        assert_eq(received[0]['stage'], 'search', 'inventory progress callback')
        assert_eq(received[1]['job_id'], 'job-1', 'inventory result callback')
        assert call('/open-user', {'login': 'test'})['ok']
    finally:
        server.stop()


def test_glpi_inventory_extension_fallback_and_progress_contract():
    extension_dir = Path(ROOT) / 'extensions' / 'tshelper-glpi-inventory-bridge'
    content = (extension_dir / 'content.js').read_text(encoding='utf-8')
    background = (extension_dir / 'background.js').read_text(encoding='utf-8')
    app_source = (Path(ROOT) / 'src' / 'tshelper' / 'app.py').read_text(encoding='utf-8')
    manifest = json.loads((extension_dir / 'manifest.json').read_text(encoding='utf-8'))
    assert '/front/user.php?is_deleted=0' in content, 'HTML User search fallback missing'
    assert '/front/search.php?globalsearch=' in content, 'global HTML search fallback missing'
    assert 'mapWithConcurrency(candidates.slice(0, 25), USER_VERIFY_CONCURRENCY' in content, 'parallel exact login verification missing'
    assert 'fetchTextWithTimeout' in content, 'full GLPI response timeout missing'
    assert 'const JOB_TIMEOUT_MS = 35000' in content, 'whole inventory job timeout missing'
    assert 'sendRuntimeMessageWithTimeout' in content, 'extension message timeout missing'
    assert 'isRemoteAccessHostname' in content, 'remote PC filtering missing'
    assert 'readOsFromDocument(doc, false)' in content, 'main Computer form must not be scanned globally for OS names'
    assert 'readOsFromDocument(parseHtml(html), true)' in content, 'OS tab text scan missing'
    assert content.index('searchUsersViaHtml(wanted)') < content.index('loadUserSearchDescriptor()'), 'HTML search must run before AJAX fallback'
    assert 'TSH_INVENTORY_REPORT_PROGRESS' in content, 'content progress reporting missing'
    assert '/inventory/jobs/progress' in background, 'background progress bridge missing'
    assert 'text="Пауза", command=self.pause_glpi_inventory' in app_source, 'live monitor pause button missing'
    assert 'text="Продолжить", command=self.resume_glpi_inventory' in app_source, 'live monitor resume button missing'
    assert 'heartbeat {poll_age:g} сек. назад' in app_source, 'monitor heartbeat label missing'
    assert 'карточка {elapsed_seconds} сек.' in app_source, 'current card timer missing'
    assert 'text="Применить однозначные"' in app_source, 'unambiguous apply button missing'
    assert 'win.after(1500, refresh_report)' in app_source, 'live inventory report refresh missing'
    assert 'controls.pack(side="bottom", fill="x")' in app_source, 'inventory report controls must remain visible below the table'
    assert 'button_controls.pack(fill="x")' in app_source, 'inventory report buttons need a responsive horizontal row'
    assert 'def collect_found_pc_rows()' in app_source, 'apply-all action must collect every card with found computers'
    assert 'and active_computers(record)' in app_source, 'apply-all action must include single-computer cards'
    assert 'command=apply_all_found_computers' in app_source, 'apply-all button is not connected to all found computers'
    assert 'widget.sync_user(matched_user)' in app_source, 'completed inventory result must refresh the affected OS badge'
    assert '"ok": "Найдено в GLPI"' in app_source, 'monitor result must distinguish scanning from applying card changes'
    assert 'GLPI: данные актуальны, карточка обновлена' in app_source, 'IP window needs a successful applied GLPI status'
    assert 'GLPI: найдены новые ПК:' in app_source, 'IP window must report newly discovered computers'
    assert 'queue_info_for_login(login)' in app_source, 'IP window must follow live GLPI queue progress'
    assert '_glpi_result_listeners.setdefault(login, []).append' in app_source, 'IP window must receive GLPI completion by login'
    assert 'self.master.after(350, refresh_glpi_status)' in app_source, 'IP status polling must use the main Tk event loop'
    assert 'normalize_login,' in app_source.split('from .glpi_inventory import (', 1)[1].split(')', 1)[0], 'GLPI result listener login normalizer is not imported'
    assert 'host_identity,' in app_source.split('from .glpi_inventory import (', 1)[1].split(')', 1)[0], 'IP window host normalizer is not imported'

    delivered = []
    result_probe = mod.MainWindow.__new__(mod.MainWindow)
    result_probe.glpi_inventory = types.SimpleNamespace(complete=lambda _payload: {
        'job': {'id': 'job-alavrov', 'reason': 'ip_lookup'},
        'record': {'login': 'ALAVROV', 'status': 'ok'},
    })
    result_probe.master = types.SimpleNamespace(after=lambda _delay, callback: callback())
    result_probe._handle_glpi_inventory_completed = lambda _job, _record: delivered.append('applied')
    result_probe._glpi_result_listeners = {'alavrov': [lambda _record: delivered.append('window')]}
    assert_eq(result_probe._handle_glpi_inventory_result({}), {'ok': True}, 'GLPI result handler response')
    assert_eq(delivered, ['applied', 'window'], 'GLPI result reaches IP window after card update')
    assert_eq(manifest['version'], '0.1.4', 'inventory extension patch version')


def test_card_contact_line_with_location():
    button = mod.UserButton.__new__(mod.UserButton)
    button.user = {'name': 'Азарян Валентина', 'ext': '4443', 'location': 'Щ5-104'}
    button.show_status = False
    button.caller_info = None
    button.status_key = 'online'
    text = button._compose_text('w-vazaryan')
    assert '4443 -- Щ5-104' in text
    assert '()' not in button._compose_text(''), 'empty remote-only PC must not leave empty brackets'


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
        status_icons = {}

        @staticmethod
        def resolve_os_types_for_user(_user):
            return ['windows']

        @staticmethod
        def get_user_pc_display(user):
            return user.get('pc_name', '')

    button = mod.UserButton.__new__(mod.UserButton)
    button.app = FakeApp()
    button.user = {'name': 'Тест', 'pc_name': 'w-test', 'pc_options': [], 'ext': '1', 'location': ''}
    button._user_render_signature = button._data_signature(button.user)
    button._os_badge_signature = ('windows',)
    button.show_status = False
    button.status_key = 'offline'
    class FakeButton:
        def __init__(self):
            self.config_calls = []
            self.image = None

        @staticmethod
        def cget(key):
            return '#fff' if key == 'bg' else '#000'

        def config(self, **kwargs):
            self.config_calls.append(kwargs)

    button.btn = FakeButton()
    button.caller_info = None
    button.status_image = None
    refreshes = []
    badges = []
    button.refresh_text = lambda: refreshes.append(True)
    button._update_os_badge = lambda _bg, _fg: badges.append(True)
    button.sync_user(dict(button.user))
    assert_eq(refreshes, [], 'unchanged card is not redrawn')
    assert_eq(badges, [], 'unchanged OS badge is not rebuilt')
    button.set_status('checking')
    assert_eq(refreshes, [], 'hidden status does not redraw card text')
    button.set_show_status(True)
    button.set_status('online')
    assert_eq(refreshes, [], 'status switch does not run full card redraw')
    assert_eq(len(button.btn.config_calls), 2, 'status switch uses lightweight button update')
    changed_user = dict(button.user, location='Щ5-104')
    button.sync_user(changed_user)
    assert_eq(len(refreshes), 1, 'changed card is redrawn once')

    app = mod.MainWindow.__new__(mod.MainWindow)
    app._ad_mobile_cache = {}
    app._ad_mobile_failed_cache = {}
    app._ad_mobile_cache_lock = __import__('threading').Lock()
    app._find_ad_candidates_by_mobile = lambda *_args: (_ for _ in ()).throw(AssertionError('network lookup must be deferred'))
    assert app.ad_lookup_by_mobile('+7 999 000-11-22', allow_network=False) is None


def test_grid_render_is_batched_and_cancelable():
    class FakeMaster:
        def __init__(self):
            self.jobs = {}
            self.next_id = 0

        def after(self, _delay, callback):
            self.next_id += 1
            self.jobs[self.next_id] = callback
            return self.next_id

        def after_cancel(self, job_id):
            self.jobs.pop(job_id, None)

        def run_next(self):
            job_id = min(self.jobs)
            callback = self.jobs.pop(job_id)
            callback()

    class FakeInner:
        @staticmethod
        def grid_columnconfigure(_column, weight):
            assert_eq(weight, 1, 'grid column weight')

    class FakeCanvas:
        def __init__(self):
            self.window_states = []

        def itemconfigure(self, item, **kwargs):
            if item == 'window' and 'state' in kwargs:
                self.window_states.append(kwargs['state'])

        @staticmethod
        def create_text(*_args, **_kwargs):
            return 'overlay'

        @staticmethod
        def tag_raise(_item):
            return None

        @staticmethod
        def winfo_width():
            return 800

        @staticmethod
        def winfo_height():
            return 600

    class FakeWidget:
        def __init__(self):
            self.show_status = False
            self.grid_calls = []
            self.remove_calls = 0
            self.refresh_calls = 0

        def grid(self, **kwargs):
            self.grid_calls.append(kwargs)

        def grid_remove(self):
            self.remove_calls += 1

        def refresh_text(self):
            self.refresh_calls += 1

        def set_show_status(self, show_status):
            self.show_status = bool(show_status)
            self.refresh_calls += 1

    app = mod.MainWindow.__new__(mod.MainWindow)
    app.master = FakeMaster()
    app.inner = FakeInner()
    app.canvas = FakeCanvas()
    app.canvas_window = 'window'
    app.user_widgets = {f'pc-{index}': FakeWidget() for index in range(60)}
    app.buttons = {}
    app._grid_positions = {}
    app._rendered_keys = set()
    app._grid_render_job = None
    app._grid_render_generation = 0
    app._grid_render_needs_sync = False
    app._grid_render_batch_size = 24
    app._grid_render_active = False
    app._grid_render_overlay = None
    app._scroll_reset_pending = False
    app.orphan_widgets = []
    app.empty_state_label = None
    app._cw_render_state = {'ordered_keys': []}
    app._compute_cols = lambda: 4
    app._update_scrollregion = lambda: None

    keys = list(app.user_widgets)
    app.render_grid(keys, [], show_status=True)
    assert_eq(len(app._rendered_keys), 24, 'first UI pass is bounded')
    assert_eq(app.canvas.window_states[-1], 'hidden', 'partial grid is not exposed')
    assert app.master.jobs, 'remaining cards are deferred to the event loop'
    assert_eq(
        sum(widget.refresh_calls for widget in app.user_widgets.values()),
        24,
        'status text is also updated in batches',
    )

    app.render_grid(keys[:1], [], show_status=False)
    while app.master.jobs:
        app.master.run_next()
    assert_eq(app._rendered_keys, {'pc-0'}, 'stale render is cancelled after query change')
    assert_eq(app.canvas.window_states[-1], 'normal', 'only completed grid is revealed')
    assert_eq(set(app.buttons), {'pc-0'}, 'button lookup follows latest query immediately')

    app.render_grid(keys, [], show_status=False)
    assert len(app._rendered_keys) <= app._grid_render_batch_size
    while app.master.jobs:
        before = len(app._rendered_keys)
        app.master.run_next()
        assert len(app._rendered_keys) - before <= app._grid_render_batch_size
    assert_eq(app._rendered_keys, set(keys), 'cleared search restores every card progressively')
    assert_eq(app.canvas.window_states[-1], 'normal', 'restored grid is revealed atomically')


def test_search_status_and_ping_are_deferred():
    class FakeMaster:
        def __init__(self):
            self.jobs = {}
            self.delays = {}
            self.next_id = 0

        def after(self, delay, callback):
            self.next_id += 1
            self.jobs[self.next_id] = callback
            self.delays[self.next_id] = delay
            return self.next_id

        def after_cancel(self, job_id):
            self.jobs.pop(job_id, None)
            self.delays.pop(job_id, None)

        def run_next(self):
            job_id = min(self.jobs)
            callback = self.jobs.pop(job_id)
            self.delays.pop(job_id, None)
            callback()

    class FakeEntry:
        value = 'abc'

        def get(self):
            return self.value

    app = mod.MainWindow.__new__(mod.MainWindow)
    app.master = FakeMaster()
    app.search_entry = FakeEntry()
    app.search_job = None
    app._search_enrichment_job = None
    app._search_enrichment_delay_ms = 40
    app._ping_queue_job = None
    app._pending_ping_users = []
    app.ping_generation = 0
    app._grid_render_batch_size = 24
    app._cw_render_state = {'show_status': False}
    app._cw_last_signature = None
    view_requests = []
    applied_states = []
    ping_batches = []
    users = [{'pc_name': 'w-test'}]

    def compute_view_state(query, show_status):
        view_requests.append((query, show_status))
        return {'filtered_sorted': users, 'show_status': show_status}

    app._compute_view_state = compute_view_state
    app._apply_call_state_delta = lambda _previous, state: applied_states.append(state)
    app._schedule_ping_batch = lambda queued, generation: ping_batches.append((queued, generation))
    app.buttons = {}
    app.ping_cache = {}
    app.ping_cache_ttl_ok = 25
    app.ping_cache_ttl_fail = 7

    app._do_search()
    assert_eq(view_requests, [('abc', False)], 'typing renders search without status work')
    assert_eq(list(app.master.delays.values()), [40], 'status enrichment yields to search rendering')
    assert_eq(ping_batches, [], 'ping is not prepared in the input callback')

    app._cancel_search_enrichment()
    assert_eq(app.master.jobs, {}, 'new input cancels deferred enrichment')

    app._do_search()
    app.master.run_next()
    assert_eq(view_requests[-1], ('abc', True), 'status appears only after quiet period')
    assert_eq(ping_batches, [], 'ping scan yields back to UI before starting')
    app.master.run_next()
    assert_eq(len(ping_batches), 1, 'ping starts after deferred cache scan')


def test_ping_dispatch_is_bounded():
    class FakePingProcess:
        def __init__(self):
            self.submitted = []

        def submit(self, candidates, callback):
            task_id = f'task-{len(self.submitted)}'
            self.submitted.append((candidates, callback, task_id))
            return task_id

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
    app.ping_process = FakePingProcess()
    app.master = FakeMaster()
    app.build_host_candidates = lambda user: [user['pc_name']]
    app._dispatch_ping_batch(1)
    assert_eq(len(app.ping_process.submitted), 2, 'ping submissions are bounded by worker count')
    assert_eq(len(app._ping_inflight), 2, 'ping inflight accounting')
    assert_eq(len(app._pending_ping_users), 1, 'remaining ping stays in app queue')
    assert app._ping_queue_job is not None
    assert_eq(
        ping_candidates([]),
        {'completed': True, 'ok': False, 'host': '', 'ip': ''},
        'empty helper request result',
    )


def test_ping_process_smoke():
    class FakeMaster:
        def __init__(self):
            self.next_id = 0

        def after(self, _delay, _callback):
            self.next_id += 1
            return self.next_id

        @staticmethod
        def after_cancel(_job_id):
            return None

    results = []
    client = PingProcessClient(FakeMaster(), max_workers=2, poll_ms=10)
    try:
        task_id = client.submit([], results.append)
        assert task_id, 'ping helper accepts request'
        deadline = time.monotonic() + 5
        while not results and time.monotonic() < deadline:
            client._poll_results()
            time.sleep(0.02)
        assert results, 'ping helper returns result from child process'
        assert results[0].get('completed'), 'ping helper completed request'
    finally:
        client.shutdown()


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
    assert '.requirements.sha256' in batch_source, 'ADHelper2 requirements fingerprint missing'
    assert 'NEEDS_INSTALL' in batch_source, 'ADHelper2 conditional dependency installation missing'

    app_source = open(os.path.join(ROOT, 'src', 'tshelper', 'app.py'), encoding='utf-8').read()
    assert 'def repair_embedded_adhelper2_layout()' in app_source, 'nested ADHelper recovery is missing'
    assert 'shutil.copytree(source_path, target_path, dirs_exist_ok=True)' in app_source, 'ADHelper recovery copy is missing'

    build_source = open(os.path.join(ROOT, 'scripts', 'build_release.ps1'), encoding='utf-8-sig').read()
    assert '$targetDirectory = Join-Path $stage $directory' in build_source, 'release directory layout must be explicit'

    update_source = open(os.path.join(ROOT, 'scripts', 'apply_update.ps1'), encoding='utf-8-sig').read()
    assert 'Get-ChildItem -LiteralPath $sourcePath -Force' in update_source, 'updater directory copy must preserve layout'

    constants_source = open(os.path.join(working_directory, 'adhelper', 'constants.py'), encoding='utf-8').read()
    package_source = open(os.path.join(working_directory, 'adhelper', '__init__.py'), encoding='utf-8').read()
    assert 'APP_VERSION = "2.1.1"' in constants_source, 'embedded ADHelper2 application version'
    assert '__version__ = "2.1.1"' in package_source, 'embedded ADHelper2 package version'


if __name__ == '__main__':
    tests = [
        test_normalize_phone,
        test_canonical_pc_key,
        test_release_version_comparison,
        test_manual_update_check_feedback,
        test_secure_portable_update_contract,
        test_noisy_powershell_json_and_paged_ad_search,
        test_os_specific_context_actions,
        test_multi_pc_os_cache_and_merge,
        test_glpi_inventory_queue_and_safe_reconciliation,
        test_browser_bridge_inventory_routes_and_legacy_open_user,
        test_glpi_inventory_extension_fallback_and_progress_contract,
        test_card_contact_line_with_location,
        test_batched_settings_and_glpi_timeout,
        test_incremental_card_sync_and_deferred_ad_lookup,
        test_grid_render_is_batched_and_cancelable,
        test_search_status_and_ping_are_deferred,
        test_ping_dispatch_is_bounded,
        test_ping_process_smoke,
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
