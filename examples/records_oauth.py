"""OAuth provider role for mcp-records-service.py (`--oauth`); stdlib only.

Authorization code with S256 and client_secret_post, a browser consent page,
refresh, and a `workspace-user-v1` identity endpoint. Tokens are random per
run and kept in memory. Synthetic identities only.
"""

import base64
import hashlib
import html
import secrets
import threading
from urllib.parse import urlencode

WORKSPACE = "northwind"
USER = "ada"
PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>Authorize access</title>
<style>body{{font-family:system-ui,sans-serif;background:#f3f4f6;margin:0;padding:48px}}
.card{{max-width:440px;margin:auto;background:#fff;border-radius:12px;padding:32px;
box-shadow:0 2px 12px #0002}}h1{{font-size:20px;margin:0 0 4px}}p{{color:#444}}
li{{margin:4px 0}}code{{background:#eef;padding:1px 4px;border-radius:4px}}
button{{font-size:15px;padding:10px 18px;border-radius:8px;border:0;margin-right:8px;cursor:pointer}}
.ok{{background:#2563eb;color:#fff}}.no{{background:#e5e7eb}}</style></head><body>
<div class="card"><h1>Records service</h1><p>Signed in as <b>{user}</b> ({workspace})</p>
<p><b>{client}</b> is asking to:</p><ul>{scopes}</ul>
<form action="/authorize/decision" method="get">{hidden}
<button class="ok" name="decision" value="approve">Approve</button>
<button class="no" name="decision" value="deny">Deny</button></form></div></body></html>"""


def s256(verifier):
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


class Provider:
    def __init__(self, client_id, client_secret, scope):
        self.client_id, self.client_secret, self.scope = client_id, client_secret, scope
        self.lock = threading.Lock()
        self.codes, self.access, self.refresh = {}, set(), set()

    def _valid_request(self, q):
        return (
            q.get("response_type") == "code"
            and q.get("client_id") == self.client_id
            and q.get("code_challenge_method") == "S256"
            and q.get("scope") == self.scope
            and all(q.get(k) for k in ("state", "code_challenge", "redirect_uri"))
        )

    def authorize(self, q):
        """GET /authorize: the consent page, or 400 for a malformed request."""
        if not self._valid_request(q):
            return 400, {}, b"invalid authorization request"
        hidden = "".join(
            f'<input type="hidden" name="{k}" value="{html.escape(v)}">'
            for k, v in q.items()
        )
        scopes = "".join(
            f"<li><code>{html.escape(s)}</code></li>" for s in self.scope.split()
        )
        page = PAGE.format(
            user=USER,
            workspace=WORKSPACE,
            client=html.escape(self.client_id),
            scopes=scopes,
            hidden=hidden,
        )
        return 200, {"Content-Type": "text/html; charset=utf-8"}, page.encode()

    def decide(self, q):
        """GET /authorize/decision: redirect back with a code, or access_denied."""
        if not self._valid_request(q):
            return 400, {}, b"invalid authorization request"
        params = {"state": q["state"]}
        if q.get("decision") == "approve":
            code = secrets.token_urlsafe(24)
            with self.lock:
                self.codes[code] = q
            params["code"] = code
        else:
            params["error"] = "access_denied"
        return 302, {"Location": q["redirect_uri"] + "?" + urlencode(params)}, b""

    def token(self, form):
        """POST /token: authorization_code or refresh_token grant."""
        if (
            form.get("client_id") != self.client_id
            or form.get("client_secret") != self.client_secret
        ):
            return 401, {"error": "invalid_client"}
        grant = form.get("grant_type")
        with self.lock:
            if grant == "authorization_code":
                issued = self.codes.pop(form.get("code", ""), None)
                ok = (
                    issued is not None
                    and form.get("redirect_uri") == issued["redirect_uri"]
                    and s256(form.get("code_verifier", "")) == issued["code_challenge"]
                )
            elif grant == "refresh_token":
                ok = form.get("refresh_token") in self.refresh
                self.refresh.discard(form.get("refresh_token"))
            else:
                return 400, {"error": "unsupported_grant_type"}
            if not ok:
                return 400, {"error": "invalid_grant"}
            access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            self.access.add(access)
            self.refresh.add(refresh)
        return 200, {
            "access_token": access,
            "token_type": "Bearer",
            "scope": self.scope,
            "refresh_token": refresh,
            "expires_in": 3600,
        }

    def authorized(self, header):
        token = (header or "").removeprefix("Bearer ")
        with self.lock:
            return token in self.access

    def whoami(self, header):
        """GET /whoami: the identity behind an access token."""
        if not self.authorized(header):
            return 401, {"error": "invalid_token"}
        return 200, {"workspace_id": WORKSPACE, "user_id": USER}
