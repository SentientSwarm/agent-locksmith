"""Invented independent service contracts; no external service or credentials."""
import base64
import hashlib
import json
from urllib.parse import parse_qs, urlencode


def authorize(h, query):
    q = {k: v[0] for k, v in parse_qs(query).items()}
    p = h.server.profile
    assert q['client_id'] == p['client_id'] and q['code_challenge_method'] == 'S256'
    assert q['resource'] == p['resource']
    separator = ',' if p['contract']['scope']['request_separator'] == 'comma' else ' '
    assert q['scope'] == separator.join(p['contract']['scope']['required'])
    h._record('issued_code')
    code = f'code-{h.server.counts["issued_code"]}'
    h.server.codes[code] = q
    h.send_response(302)
    h.send_header('Location', q['redirect_uri'] + '?' + urlencode(dict(state=q['state'], code=code)))
    h.send_header('Content-Length', '0')
    h.end_headers()


def exchange(h, raw):
    form = parse_qs(raw.decode())
    p = h.server.profile
    h.phase = 'token'
    h._record('token')
    assert form['client_id'] == [p['client_id']] and form['resource'] == [p['resource']]
    auth = p['contract']['client_auth']
    assert form.get('client_secret') == (['invented-client-secret'] if auth == 'client_secret_post' else None)
    if form['grant_type'] == ['refresh_token']:
        assert form['refresh_token'] == [h.server.refresh]
        h._record('refresh')
        h.server.access, h.server.refresh = 'contract-access-rotated', 'contract-refresh-rotated'
    else:
        assert form['grant_type'] == ['authorization_code']
        if not initial(h, form):
            return
    token_reply(h, token(h))


def initial(h, form):
    issued = h.server.codes.pop(form['code'][0])
    digest = base64.urlsafe_b64encode(hashlib.sha256(form['code_verifier'][0].encode()).digest()).decode().rstrip('=')
    assert form['redirect_uri'] == [issued['redirect_uri']]
    if issued['code_challenge'] != digest:
        assert digest == (h.server.root / 'original-challenge').read_text()
        h._record('original_verifier_received')
        if not (h.server.root / 'accept-wrong-challenge').exists():
            h._record('verifier_refused')
            token_reply(h, dict(ok=False, error='bad_code_verifier'))
            return False
    else:
        h._record('matched_verifier')
    return True


def token_reply(h, value):
    path = h.server.root / 'token-case.json'
    case = json.loads(path.read_text()) if path.exists() else {}
    raw = case.get('raw', json.dumps(case.get('value', value))).encode()
    h.send_response(case.get('http', 200))
    h.send_header('Content-Type', 'application/json')
    h.send_header('Content-Length', str(len(raw)))
    h.end_headers()
    h.wfile.write(raw)


def token(h):
    c = h.server.profile['contract']
    value = dict(access_token=h.server.access, refresh_token=h.server.refresh,
                 token_type='Bearer', expires_in=3600, scope=' '.join(c['scope']['required']))
    if c['token_response'] == 'slack-user-v2' and (h.server.root / 'nested').exists():
        value.update(ok=True, token_type='user', team=dict(id=c['subject']['workspace_id']),
                     authed_user=dict(id=c['subject']['user_id'], scope=value.pop('scope')))
    if (h.server.root / 'missing-scope').exists():
        value.pop('scope', None)
    return value


def identity(h):
    c = h.server.profile['contract']
    h.phase = 'identity'
    h._record('identity')
    value = {k: v for k, v in c['subject'].items() if k != 'kind'}
    if c['identity']['response'] == 'slack-auth-test-v1':
        value['team_id'] = value.pop('workspace_id')
        value['ok'] = True
        value.update(team='Invented Workspace', user='invented-user', url='https://invented.slack.com/')
    if (h.server.root / 'wrong-identity').exists():
        value['subject_id' if 'subject_id' in value else 'user_id'] = 'wrong-observed-subject'
    identity_reply(h, value)


def identity_reply(h, value):
    path = h.server.root / 'identity-case.json'
    case = json.loads(path.read_text()) if path.exists() else {}
    value.update(case.get('set', {}))
    for key in case.get('remove', []):
        value.pop(key, None)
    raw = case.get('raw', json.dumps(value)).encode()
    h.send_response(case.get('http', 200))
    h.send_header('Content-Type', 'application/json')
    h.send_header('Content-Length', str(len(raw)))
    h.end_headers()
    h.wfile.write(raw)
