#!/usr/bin/env python3
"""Replace one challenge in a trusted, private shipping authorization receipt."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
from urllib.parse import unquote_plus, urlsplit

FIELDS = {'response_type', 'client_id', 'redirect_uri', 'scope', 'resource', 'state',
          'code_challenge_method', 'code_challenge'}
EXPECTED = {'authorization_endpoint', 'client_id', 'redirect_uri', 'scope', 'resource', 'state', 'code_challenge'}


def refused():
    raise ValueError('authorization_challenge_refused')


def digest(value):
    return base64.urlsafe_b64encode(hashlib.sha256(value).digest()).decode().rstrip('=')


def valid_challenge(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', value):
        return False
    raw = base64.urlsafe_b64decode(value + '=')
    return len(raw) == 32 and base64.urlsafe_b64encode(raw).decode().rstrip('=') == value


def fields(query):
    values, spans, offset = {}, {}, 0
    for part in query.split('&'):
        if '=' not in part or re.search(r'%(?![0-9A-Fa-f]{2})', part):
            refused()
        key, raw = part.split('=', 1)
        name, value = unquote_plus(key, errors='strict'), unquote_plus(raw, errors='strict')
        if name in values or not value or name not in FIELDS or any(ord(c) < 32 or ord(c) == 127 for c in value):
            refused()
        values[name] = value
        spans[name] = (offset + len(key) + 1, offset + len(part))
        offset += len(part) + 1
    if values.keys() != FIELDS:
        refused()
    return values, spans


def rewrite(url, expected, replacement):
    if not isinstance(url, str) or len(url) > 8192 or any(ord(c) < 33 or ord(c) > 126 for c in url):
        refused()
    if not isinstance(expected, dict) or expected.keys() != EXPECTED or any(
            not isinstance(v, str) or not v or len(v) > 2048 for v in expected.values()):
        refused()
    parts = urlsplit(url)
    if parts.scheme != 'https' or parts.username or parts.password or '#' in url or '?' not in url:
        refused()
    endpoint, query = url.split('?', 1)
    if endpoint != expected['authorization_endpoint'] or '?' in endpoint:
        refused()
    values, spans = fields(query)
    bindings = {k: v for k, v in expected.items() if k != 'authorization_endpoint'}
    bindings.update(response_type='code', code_challenge_method='S256')
    if values != bindings or not valid_challenge(values['code_challenge']) or not valid_challenge(replacement):
        refused()
    if replacement == values['code_challenge']:
        refused()
    start, end = spans['code_challenge']
    changed = query[:start] + replacement + query[end:]
    return endpoint + '?' + changed


def private_parent(path):
    info = path.parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o777 != 0o700:
        refused()


def load_private(path):
    private_parent(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o777 != 0o600:
        refused()
    with path.open('rb') as source:
        raw = source.read(65537)
    if len(raw) > 65536:
        refused()
    return json.loads(raw, object_pairs_hook=unique)


def unique(pairs):
    value = {}
    for key, member in pairs:
        if key in value:
            refused()
        value[key] = member
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        request = load_private(args.input)
        if not isinstance(request, dict) or request.keys() != {'url', 'expected'}:
            refused()
        replacement = digest(secrets.token_urlsafe(48).encode())
        result = rewrite(request['url'], request['expected'], replacement)
        private_parent(args.output)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        with os.fdopen(os.open(args.output, flags, 0o600), 'w') as output:
            json.dump({'url': result}, output)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
    except (OSError, ValueError, TypeError, RecursionError):
        print('{"state":"refused","reason":"authorization_challenge_refused"}')
        return 1
    print('{"state":"challenge_changed"}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
