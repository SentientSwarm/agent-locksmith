"""Invented trusted contexts only; no retained authorization URL or verifier."""
import copy
import importlib.util
from pathlib import Path
import unittest
from urllib.parse import urlencode

SPEC = importlib.util.spec_from_file_location('challenge', Path.cwd()/'scripts/oauth-challenge.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def fixture():
    expected = dict(authorization_endpoint='https://authorize.example.test/custom', client_id='invented-client',
                    redirect_uri='https://callback.example.test/oauth/callback/custom/example', scope='a:read b:read',
                    resource='https://api.example.test/mcp', state='invented-state', code_challenge=M.digest(b'original'))
    query = {k: v for k, v in expected.items() if k != 'authorization_endpoint'}
    query.update(response_type='code', code_challenge_method='S256')
    return expected['authorization_endpoint']+'?'+urlencode(query), expected


class ChallengeEquality(unittest.TestCase):
    def test_only_raw_challenge_value_changes(self):
        url, expected = fixture()
        url = url.replace('a%3Aread+b%3Aread','a%3aread%20b%3aread').replace('client_id=', '%63lient_id=')
        replacement = M.digest(b'different')
        changed = M.rewrite(url, expected, replacement)
        self.assertEqual(changed.replace(replacement, expected['code_challenge']), url)
        self.assertNotEqual(changed, url)


class CommaSerialization(unittest.TestCase):
    def test_comma_serialization_is_preserved(self):
        url, expected = fixture()
        expected['scope'] = 'a:read,b:read'
        url = url.replace('a%3Aread+b%3Aread', 'a%3Aread%2Cb%3Aread')
        replacement = M.digest(b'different')
        self.assertEqual(M.rewrite(url, expected, replacement).replace(
            replacement, expected['code_challenge']), url)


class ChallengeRefusals(unittest.TestCase):
    def test_duplicate_and_blank_keys_refuse(self):
        url, expected = fixture()
        for suffix in ['&code_challenge=', '&%63ode_challenge=x', '&state=', '&unexpected=x']:
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                M.rewrite(url+suffix, expected, M.digest(b'different'))

    def test_fragment_malformed_encoding_and_userinfo_refuse(self):
        url, expected = fixture()
        for bad in [url+'#', url+'#fragment', url.replace('invented-state', '%GG'),
                    url.replace('https://authorize.', 'https://user@authorize.'), url.replace('https:', 'http:')]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                M.rewrite(bad, expected, M.digest(b'different'))

    def test_unchanged_or_invalid_replacement_refuse(self):
        url, expected = fixture()
        for replacement in [expected['code_challenge'], '', 'x'*42, 'B'*43, 'x'*44]:
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                M.rewrite(url, expected, replacement)


class TrustedBindings(unittest.TestCase):
    def test_every_binding_change_refuses(self):
        url, expected = fixture()
        for key in expected:
            bad = copy.deepcopy(expected)
            bad[key] += 'different'
            with self.subTest(key=key), self.assertRaises(ValueError):
                M.rewrite(url, bad, M.digest(b'different'))

    def test_response_and_method_refuse(self):
        url, expected = fixture()
        for bad in [url.replace('response_type=code', 'response_type=token'),
                    url.replace('code_challenge_method=S256', 'code_challenge_method=plain')]:
            with self.assertRaises(ValueError):
                M.rewrite(bad, expected, M.digest(b'different'))

    def test_shape_and_limits_refuse(self):
        url, expected = fixture()
        for bad in [{}, {**expected, 'extra':'canary'}, {**expected, 'client_id':None}]:
            with self.assertRaises(ValueError):
                M.rewrite(url, bad, M.digest(b'different'))
        with self.assertRaises(ValueError):
            M.rewrite(url+'x'*8192, expected, M.digest(b'different'))

    def test_no_url_value_in_closed_error(self):
        url, expected = fixture()
        with self.assertRaisesRegex(ValueError, '^authorization_challenge_refused$'):
            M.rewrite(url+'private-canary', expected, M.digest(b'different'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
