import gzip
import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'update.py'
spec = importlib.util.spec_from_file_location('qalqon_hash_update', SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def h(n):
    return f'{n:064x}'


def sample(n, file_type='apk'):
    return {'sha256_hash': h(n), 'file_type': file_type}


def reconstruct(before, delta_gz):
    hashes = list(before)
    for line in gzip.decompress(delta_gz).decode('ascii').splitlines():
        assert len(line) == 65
        digest = line[1:]
        if line[0] == '-':
            hashes.remove(digest)
        elif line[0] == '+':
            assert digest not in hashes
            hashes.append(digest)
        else:
            raise ValueError(line)
    return hashes


class UpdateTests(unittest.TestCase):
    def test_apk_only_valid_sha256_and_deduplicate(self):
        self.assertEqual(mod.apk_hashes([sample(1), sample(1), sample(2, 'exe'),
                                        {'file_type': 'apk', 'sha256_hash': 'not-a-sha256'},
                                        {'file_type': 'APK', 'sha256_hash': h(3).upper()}]),
                         {h(1), h(3)})

    def test_restrict_requests_to_metadata_not_downloads(self):
        with self.assertRaises(ValueError):
            mod.fetch({'query': 'get_file', 'sha256_hash': h(1)})
        with self.assertRaises(ValueError):
            mod.fetch({'query': 'get_recent', 'selector': '100'})
        self.assertEqual(mod.LOOKBACK_HOURS, 168)
        self.assertEqual(mod.FILE_TYPE_LIMIT, 1000)
        self.assertEqual(mod.MAX_BYTES, 100_000_000)

    def test_delta_reconstructs_full_snapshot_and_checksum(self):
        before = [h(1), h(2), h(3)]
        snapshot, delta, metadata = mod.build_update(before, [sample(4), sample(5)],
                                                     [sample(4), sample(6, 'exe')],
                                                     7, [], '2026-11-18T00:00:00Z')
        self.assertEqual(metadata['version'], 8)
        self.assertEqual(metadata['new_hashes_added'], 2)
        self.assertEqual(metadata['hashes_removed_due_to_cap'], 0)
        self.assertEqual(reconstruct(before, delta), [h(1), h(2), h(3), h(4), h(5)])
        self.assertEqual(gzip.decompress(snapshot), mod.render_hashes(reconstruct(before, delta)))
        self.assertEqual(metadata['full']['gzip_sha256'], hashlib.sha256(snapshot).hexdigest())
        self.assertEqual(metadata['deltas'][0]['gzip_sha256'], hashlib.sha256(delta).hexdigest())

    def test_oldest_evicted_and_delta_removes_them(self):
        with patch.object(mod, 'MAX_BYTES', 65 * 3):
            before = [h(1), h(2), h(3)]
            snapshot, delta, metadata = mod.build_update(before, [sample(4), sample(5)],
                                                         [], 0, [], 'now')
        self.assertEqual(reconstruct(before, delta), [h(3), h(4), h(5)])
        self.assertEqual(gzip.decompress(snapshot), mod.render_hashes([h(3), h(4), h(5)]))
        self.assertEqual(metadata['hashes_removed_due_to_cap'], 2)
        self.assertEqual(metadata['new_hashes_added'], 2)
        self.assertEqual(metadata['max_plaintext_bytes'], 65 * 3)

    def test_no_changes_no_delta_or_version_bump(self):
        before = [h(1), h(2)]
        snapshot, delta, metadata = mod.build_update(before, [sample(1), sample(2)],
                                                     [], 15, [], 'now')
        self.assertIsNone(delta)
        self.assertEqual(metadata['version'], 15)
        self.assertEqual(gzip.decompress(snapshot), mod.render_hashes(before))

    def test_migrate_legacy_metadata_to_v2_without_plaintext_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / 'database'
            db.mkdir()
            old = mod.render_hashes([h(1)])
            gz = mod.gzip_bytes(old)
            (db / 'apk_hashes.txt.gz').write_bytes(gz)
            (db / 'metadata.json').write_text(json.dumps({
                'schema_version': 1, 'sha256_of_plaintext': hashlib.sha256(old).hexdigest()
            }))
            with patch.multiple(mod, ROOT=db, SNAPSHOT=db/'apk_hashes.txt.gz',
                                LEGACY_PLAINTEXT=db/'apk_hashes.txt', META=db/'metadata.json',
                                UPDATES=db/'updates'):
                previous = mod.load_existing()
                version, history = mod.load_previous_metadata(mod.render_hashes(previous))
                self.assertEqual((version, history), (0, []))
                result = mod.build_update(previous, [sample(2)], [], version, history, 'now')
                mod.publish(*result)
                self.assertEqual(mod.load_existing(), [h(1), h(2)])
                self.assertEqual(mod.load_previous_metadata(mod.render_hashes(mod.load_existing()))[0], 1)
                self.assertTrue((db/'updates/00000001.delta.gz').exists())
                self.assertFalse((db/'apk_hashes.txt').exists())

    def test_failed_api_does_not_modify_database(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = Path(tmpdir) / 'database'
            db.mkdir()
            old = mod.render_hashes([h(1)])
            (db/'apk_hashes.txt.gz').write_bytes(mod.gzip_bytes(old))
            (db/'metadata.json').write_text(json.dumps({'schema_version': 1,
                    'sha256_of_plaintext': hashlib.sha256(old).hexdigest()}))
            original_gz = (db/'apk_hashes.txt.gz').read_bytes()
            original_metadata = (db/'metadata.json').read_bytes()
            with patch.multiple(mod, ROOT=db, SNAPSHOT=db/'apk_hashes.txt.gz',
                                LEGACY_PLAINTEXT=db/'apk_hashes.txt', META=db/'metadata.json',
                                UPDATES=db/'updates'):
                with patch.object(mod, 'fetch', side_effect=[[sample(2)], RuntimeError('API unavailable')]):
                    with self.assertRaisesRegex(RuntimeError, 'API unavailable'):
                        mod.main()
            self.assertEqual(original_gz, (db/'apk_hashes.txt.gz').read_bytes())
            self.assertEqual(original_metadata, (db/'metadata.json').read_bytes())

    def test_api_metadata_cached_across_retries(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = Path(tmpdir) / 'api-cache.json'
            with patch.dict(os.environ, {'QALQON_API_CACHE': str(cache)}):
                with patch.object(mod, 'fetch', side_effect=[[sample(11)], [sample(12)]]) as mocked:
                    first = mod.fetch_or_load_cached_metadata()
                    self.assertEqual(mocked.call_count, 2)
                self.assertTrue(cache.is_file())
                # A second update attempt must not hit the external API again.
                with patch.object(mod, 'fetch', side_effect=AssertionError('unexpected refetch')):
                    second = mod.fetch_or_load_cached_metadata()
                self.assertEqual(first, second)

    def test_failed_api_does_not_leave_retry_cache(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = Path(tmpdir) / 'api-cache.json'
            with patch.dict(os.environ, {'QALQON_API_CACHE': str(cache)}):
                with patch.object(mod, 'fetch', side_effect=[[sample(11)], RuntimeError('API error')]):
                    with self.assertRaisesRegex(RuntimeError, 'API error'):
                        mod.fetch_or_load_cached_metadata()
                self.assertFalse(cache.exists())

    def test_invalid_retry_cache_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = Path(tmpdir) / 'api-cache.json'
            cache.write_text('"not an object"')
            with patch.dict(os.environ, {'QALQON_API_CACHE': str(cache)}):
                with patch.object(mod, 'fetch', side_effect=AssertionError('unexpected API request')):
                    with self.assertRaisesRegex(ValueError, 'Invalid cached'):
                        mod.fetch_or_load_cached_metadata()

    def test_gzip_deterministic(self):
        self.assertEqual(mod.gzip_bytes(b'abc'), mod.gzip_bytes(b'abc'))


if __name__ == '__main__':
    unittest.main()
