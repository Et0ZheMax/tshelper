import importlib.util
import os
import tempfile
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)
MODULE_PATH = os.path.join(os.path.dirname(__file__), '..', 'TS HELPER V5.0.py')
spec = importlib.util.spec_from_file_location('tshelper_v5', MODULE_PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def assert_eq(actual, expected, msg):
    if actual != expected:
        raise AssertionError(f"{msg}: {actual!r} != {expected!r}")


def test_normalize_phone():
    assert_eq(mod.normalize_phone('+7 (999) 123-45-67'), '79991234567', 'normalize_phone ru')
    assert_eq(mod.normalize_phone(' 123-45-67 '), '', 'normalize_phone short')


def test_canonical_pc_key():
    assert_eq(mod.canonical_pc_key('WS-ABC-01'), 'abc-01', 'canonical_pc_key ws')
    assert_eq(mod.canonical_pc_key('L-WS-ABC'), 'abc', 'canonical_pc_key nested')


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


if __name__ == '__main__':
    tests = [
        test_normalize_phone,
        test_canonical_pc_key,
        test_broken_json_and_safe_save,
        test_safe_save_json_cleans_temp_on_error,
        test_callwatcher_parse_helpers,
    ]
    for t in tests:
        t()
        print(f'[OK] {t.__name__}')
    print('Selftest completed.')
