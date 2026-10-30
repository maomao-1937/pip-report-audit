import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
CLI = ROOT / 'pip_report_audit.py'
SPEC = importlib.util.spec_from_file_location('audit', CLI)
MOD = None
if CLI.exists():
    MOD = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(MOD)


def report():
    return {'version': '1', 'pip_version': '26.0',
            'environment': {'python_version': '3.11'}, 'install': [{
                'metadata': {'name': 'private-sensitive-name', 'version': '1.0'},
                'is_direct': False, 'is_yanked': False, 'requested': True,
                'download_info': {'url': 'https://files.example.test/pkg.whl',
                                  'archive_info': {'hashes': {'sha256': 'a' * 64}}}}]}


def policy():
    return {'allowed_hosts': ['files.example.test']}


def mixed_report():
    r = report()
    for source, requested, direct in [
            ({'url': 'file:///tmp/demo.whl', 'archive_info': {'hashes': {'sha256': 'b' * 64}}}, False, True),
            ({'url': 'https://source.example.test/repo', 'vcs_info': {'vcs': 'git', 'commit_id': 'revision'}}, False, True),
            ({'url': 'file:///tmp/project', 'dir_info': {}}, True, True),
            ({'url': 'file:///tmp/repo', 'vcs_info': {'vcs': 'svn', 'commit_id': '42'}}, True, False)]:
        item = report()['install'][0]
        item.update(download_info=source, requested=requested, is_direct=direct)
        r['install'].append(item)
    return r


class AuditTests(unittest.TestCase):
    def audit(self, r=None, p=None):
        self.assertIsNotNone(MOD, 'audit implementation is required')
        return MOD.audit(report() if r is None else r, policy() if p is None else p)

    def invalid(self, r=None, p=None):
        self.assertIsNotNone(MOD, 'audit implementation is required')
        with self.assertRaises(MOD.InvalidInput):
            self.audit(r, p)

    def test_clean_archive(self):
        self.assertEqual(self.audit(), {'items': 1, 'requested_count': 1, 'direct_count': 0,
                                       'origin_counts': {'archive': 1, 'vcs': 0, 'local': 0}, 'findings': []})

    def test_empty_report(self):
        r = report(); r['install'] = []
        self.assertEqual(self.audit(r), {'items': 0, 'requested_count': 0, 'direct_count': 0,
                                        'origin_counts': {'archive': 0, 'vcs': 0, 'local': 0}, 'findings': []})

    def test_mixed_origin_coverage_clean_and_findings(self):
        r = mixed_report()
        p = dict(policy(), allow_local=True, allow_vcs=True)
        for yanked in [False, True]:
            r['install'][0]['is_yanked'] = yanked
            result = self.audit(r, p)
            self.assertEqual(result.get('items'), 5)
            self.assertEqual(result.get('requested_count'), 3)
            self.assertEqual(result.get('direct_count'), 3)
            self.assertEqual(result.get('origin_counts'), {'archive': 2, 'vcs': 2, 'local': 1})
            self.assertEqual(result['findings'], [{'item': 1, 'code': 'YANKED'}] if yanked else [])

    def test_unc_ambiguous_file_sources_rejected(self):
        for url in ['file:////server/share', 'file://///server/share',
                    'file:///%2fserver/share', 'file:///%2F%2fserver/share',
                    'file:////%2fserver/share', 'file:///%2f/server/share']:
            for info in [{'dir_info': {}}, {'archive_info': {'hashes': {'sha256': 'a' * 64}}},
                         {'vcs_info': {'vcs': 'git', 'commit_id': 'revision'}}]:
                with self.subTest(url=url, kind=next(iter(info))):
                    r = report(); r['install'][0]['download_info'] = dict(info, url=url)
                    self.invalid(r, dict(policy(), allow_local=True, allow_vcs=True))

    def test_direct_archive_is_allowed(self):
        r = report(); r['install'][0]['is_direct'] = True
        self.assertEqual(self.audit(r)['findings'], [])

    def test_yanked_default(self):
        r = report(); r['install'][0]['is_yanked'] = True
        self.assertEqual(self.audit(r)['findings'], [{'item': 1, 'code': 'YANKED'}])

    def test_yanked_opt_in(self):
        r = report(); r['install'][0]['is_yanked'] = True
        self.assertEqual(self.audit(r, dict(policy(), allow_yanked=True))['findings'], [])

    def test_exact_host(self):
        r = report(); r['install'][0]['download_info']['url'] = 'https://files.example.test.attacker.test/a'
        self.assertEqual(self.audit(r)['findings'], [{'item': 1, 'code': 'HOST_NOT_ALLOWED'}])

    def test_case_normalized_hosts(self):
        r = report(); r['install'][0]['download_info']['url'] = 'https://FILES.EXAMPLE.TEST/a'
        self.assertEqual(self.audit(r)['findings'], [])

    def test_missing_sha256_is_policy_finding(self):
        r = report(); r['install'][0]['download_info']['archive_info'] = {}
        self.assertEqual(self.audit(r)['findings'], [{'item': 1, 'code': 'SHA256_MISSING'}])

    def test_legacy_sha256(self):
        r = report(); r['install'][0]['download_info']['archive_info'] = {'hash': 'sha256=' + 'b' * 64}
        self.assertEqual(self.audit(r)['findings'], [])

    def test_bad_sha256_formats(self):
        for digest in ['a' * 63, 'z' * 64, 123, '', ' a' * 32]:
            with self.subTest(digest=digest):
                r = report(); r['install'][0]['download_info']['archive_info']['hashes']['sha256'] = digest
                self.invalid(r)

    def test_conflicting_hashes(self):
        r = report(); r['install'][0]['download_info']['archive_info']['hash'] = 'sha256=' + 'b' * 64
        self.invalid(r)

    def test_unsupported_report(self):
        r = report(); r['version'] = '2'; self.invalid(r)

    def test_boolean_shapes(self):
        for field in ['is_direct', 'is_yanked', 'requested']:
            r = report(); r['install'][0][field] = 1; self.invalid(r)

    def test_metadata_shapes(self):
        for field in ['name', 'version']:
            r = report(); r['install'][0]['metadata'][field] = ''; self.invalid(r)

    def test_report_basics(self):
        for field, value in [('pip_version', ''), ('environment', []), ('environment', {'a': 1}), ('install', {})]:
            r = report(); r[field] = value; self.invalid(r)

    def test_ambiguous_source(self):
        r = report(); r['install'][0]['download_info']['dir_info'] = {}; self.invalid(r)

    def test_malformed_archive_urls(self):
        for url in ['http://files.example.test/a', 'https://u:p@files.example.test/a',
                    'https://files.example.test/a#x', 'https://files.example.test:443/a',
                    'https://files.example.test./a', 'https://127.0.0.1/a',
                    'https://files.example.test\\@evil.test/a', 'https:///a',
                    'https://files.example.test/a\n', 'https://%66iles.example.test/a',
                    'https://fíles.example.test/a', 'https://[::1]/a',
                    'https://files.example.test/a%0d', 'https://files.example.test/a%zz']:
            with self.subTest(url=url):
                r = report(); r['install'][0]['download_info']['url'] = url; self.invalid(r)

    def test_policy_configuration(self):
        for p in [{}, {'allowed_hosts': 'x'}, {'allowed_hosts': ['*.example.test']},
                  {'allowed_hosts': ['https://example.test']}, dict(policy(), allow_vcs=1),
                  dict(policy(), unknown=True), {'allowed_hosts': ['127.0.0.1']},
                  {'allowed_hosts': ['files.example.test', 'FILES.EXAMPLE.TEST']}]:
            with self.subTest(policy=p): self.invalid(p=p)

    def test_empty_allowlist_denies(self):
        self.assertEqual(self.audit(p={'allowed_hosts': []})['findings'][0]['code'], 'HOST_NOT_ALLOWED')

    def test_vcs_default_denied_and_allowed(self):
        r = report(); r['install'][0]['download_info'] = {
            'url': 'https://source.example.test/repo', 'vcs_info': {'vcs': 'git', 'commit_id': 'recorded-revision'}}
        self.assertEqual(self.audit(r)['findings'][0]['code'], 'VCS_DISALLOWED')
        self.assertEqual(self.audit(r, dict(policy(), allow_vcs=True))['findings'], [])

    def test_vcs_still_validates(self):
        for vcs in [{'vcs': 'git'}, {'vcs': 'bogus', 'commit_id': 'x'},
                    {'vcs': 'git', 'commit_id': ''}, {'vcs': 'git', 'commit_id': 'x', 'requested_revision': 1}]:
            r = report(); r['install'][0]['download_info'] = {'url': 'https://source.example.test/r', 'vcs_info': vcs}
            self.invalid(r, dict(policy(), allow_vcs=True))

    def test_local_directory_default_and_opt_in(self):
        r = report(); r['install'][0]['download_info'] = {'url': 'file:///C:/project', 'dir_info': {'editable': True}}
        self.assertEqual(self.audit(r)['findings'][0]['code'], 'LOCAL_DISALLOWED')
        self.assertEqual(self.audit(r, dict(policy(), allow_local=True))['findings'], [])

    def test_local_archive_requires_hash(self):
        r = report(); r['install'][0]['download_info'] = {'url': 'file:///tmp/a.whl', 'archive_info': {}}
        self.assertEqual(self.audit(r, dict(policy(), allow_local=True))['findings'][0]['code'], 'SHA256_MISSING')

    def test_local_shape(self):
        for url, info in [('https://files.example.test/a', {}), ('file://server/share', {}),
                          ('file:relative', {}), ('file:///tmp/a?x', {}), ('file:///tmp/a', {'editable': 1})]:
            r = report(); r['install'][0]['download_info'] = {'url': url, 'dir_info': info}; self.invalid(r)

    def test_bounds(self):
        self.assertIsNotNone(MOD, 'audit implementation is required')
        r = report(); r['install'] *= MOD.MAX_ITEMS + 1; self.invalid(r)

    def test_json_rejects_duplicate_nonfinite_and_surrogates(self):
        self.assertIsNotNone(MOD, 'audit implementation is required')
        for raw in [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b'{"a":"\\ud800"}']:
            with self.assertRaises(MOD.InvalidInput): MOD.decode_json(raw)

    def test_json_depth_and_bytes(self):
        self.assertIsNotNone(MOD, 'audit implementation is required')
        for raw in [b'[' * (MOD.MAX_DEPTH + 1) + b'0' + b']' * (MOD.MAX_DEPTH + 1), b' ' * (MOD.MAX_BYTES + 1)]:
            with self.assertRaises(MOD.InvalidInput): MOD.decode_json(raw)

    def test_overflow_number_rejected_in_unknown_field(self):
        self.assertIsNotNone(MOD, 'audit implementation is required')
        with self.assertRaises(MOD.InvalidInput): MOD.decode_json(b'{"future":1e999}')

    def test_numeric_hex_host_is_unsupported(self):
        r = report(); r['install'][0]['download_info']['url'] = 'https://0xffffffff/a'
        self.invalid(r, {'allowed_hosts': ['0xffffffff']})

    def test_known_optional_shapes(self):
        r = report(); r['install'][0]['download_info']['subdirectory'] = 3
        self.invalid(r)
        r = report(); r['install'][0]['requested_extras'] = 'extra'
        self.invalid(r)


class CliTests(unittest.TestCase):
    def invoke(self, args, **kwargs):
        return subprocess.run([sys.executable, CLI.name, *args], cwd=ROOT, capture_output=True,
                              text=True, timeout=12, **kwargs)

    def files(self, r, p):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        path = pathlib.Path(tmp.name)
        (path / 'report.json').write_text(json.dumps(r), encoding='utf-8')
        (path / 'policy.json').write_text(json.dumps(p), encoding='utf-8')
        return [str(path / 'report.json'), '--policy', str(path / 'policy.json')]

    def test_clean_json(self):
        proc = self.invoke(self.files(report(), policy()) + ['--json'])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout), {'code': 'CLEAN', 'items': 1, 'requested_count': 1,
                         'direct_count': 0, 'origin_counts': {'archive': 1, 'vcs': 0, 'local': 0},
                         'finding_count': 0, 'findings': []})

    def test_mixed_origin_cli_coverage_both_formats(self):
        for yanked in [False, True]:
            r = mixed_report(); r['install'][0]['is_yanked'] = yanked
            args = self.files(r, dict(policy(), allow_local=True, allow_vcs=True))
            proc = self.invoke(args + ['--json'])
            self.assertEqual(proc.returncode, int(yanked))
            payload = json.loads(proc.stdout)
            self.assertEqual(payload.get('requested_count'), 3)
            self.assertEqual(payload.get('direct_count'), 3)
            self.assertEqual(payload.get('origin_counts'), {'archive': 2, 'vcs': 2, 'local': 1})
            human = self.invoke(args)
            self.assertEqual(human.returncode, int(yanked))
            self.assertIn('requested=3 direct=3 archive=2 vcs=2 local=1', human.stdout)

    def test_empty_cli_coverage(self):
        r = report(); r['install'] = []
        proc = self.invoke(self.files(r, policy()) + ['--json'])
        self.assertEqual(proc.returncode, 0)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload.get('requested_count'), 0)
        self.assertEqual(payload.get('direct_count'), 0)
        self.assertEqual(payload.get('origin_counts'), {'archive': 0, 'vcs': 0, 'local': 0})

    def test_unc_file_cli_neutral_failure(self):
        for url in ['file:////server/share', 'file://///server/share', 'file:///%2fserver/share']:
            r = report(); r['install'][0]['download_info'] = {'url': url, 'dir_info': {}}
            proc = self.invoke(self.files(r, dict(policy(), allow_local=True)) + ['--json'])
            self.assertEqual(proc.returncode, 2)
            self.assertEqual(json.loads(proc.stdout), {'code': 'INVALID_INPUT'})
            self.assertEqual(proc.stderr, '')

    def test_findings_json(self):
        r = report(); r['install'][0]['is_yanked'] = True
        proc = self.invoke(self.files(r, policy()) + ['--json'])
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(json.loads(proc.stdout)['findings'], [{'item': 1, 'code': 'YANKED'}])

    def test_human_privacy(self):
        r = report(); r['install'][0]['download_info']['url'] = 'https://private-secret.example.test/secret'
        proc = self.invoke(self.files(r, policy()))
        self.assertEqual(proc.returncode, 1)
        self.assertIn('HOST_NOT_ALLOWED', proc.stdout)
        for secret in ['private-secret', 'private-sensitive', 'secret', 'example.test', 'report.json']:
            self.assertNotIn(secret, proc.stdout + proc.stderr)

    def test_invalid_inputs_neutral(self):
        r = report(); r['version'] = 'SECRET-VERSION'
        proc = self.invoke(self.files(r, policy()) + ['--json'])
        self.assertEqual(proc.returncode, 2)
        self.assertTrue(proc.stdout, 'neutral structured error must be produced')
        self.assertEqual(json.loads(proc.stdout), {'code': 'INVALID_INPUT'})
        self.assertEqual(proc.stderr, '')

    def test_missing_file_neutral(self):
        proc = self.invoke(['SECRET-PATH', '--policy', 'SECRET-POLICY'])
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn('SECRET', proc.stdout + proc.stderr)

    def test_unknown_argument_neutral(self):
        proc = self.invoke(['--SECRET-ARG'])
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn('SECRET', proc.stdout + proc.stderr)

    def test_help(self):
        proc = self.invoke(['--help']); self.assertEqual(proc.returncode, 0)
        self.assertIn('USAGE', proc.stdout)

    def test_closed_stdout_and_help(self):
        for args in [self.files(report(), policy()), ['--help']]:
            with subprocess.Popen([sys.executable, CLI.name, *args], cwd=ROOT,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
                proc.stdout.close()
                proc.stdout = None
                _, stderr = proc.communicate(timeout=12)
                self.assertEqual(proc.returncode, 2)
                self.assertEqual(stderr, b'')


if __name__ == '__main__':
    unittest.main()
