"""Tests for dist/edge/install_model.py against a local HTTP fixture."""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

EDGE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(EDGE))

import install_model

TOKEN = "hf_test_token_value_0123456789"
REV = "0123456789abcdef0123456789abcdef01234567"
CONFIG = b'{"model_type": "test"}\n'
WEIGHTS = os.urandom(4096)


def git_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def catalog_text(
    *, gated: bool, weights_sha: str | None = None, size: int | None = None
) -> str:
    sha = weights_sha or hashlib.sha256(WEIGHTS).hexdigest()
    return f"""
[[model]]
id = "test-model"
repo = "org/test-model"
revision = "{REV}"
license = "test-licence"
gated = {"true" if gated else "false"}
files = [
  {{ path = "config.json", size = {len(CONFIG)}, git_sha1 = "{git_sha1(CONFIG)}" }},
  {{ path = "onnx/model.onnx", size = {size or len(WEIGHTS)}, sha256 = "{sha}" }},
]
"""


class Fixture:
    """Origin server that may redirect file bodies to a second (CDN) server."""

    def __init__(self, *, status=200, redirect=False):
        self.requests = []
        self.status = status
        self.files = {
            f"/org/test-model/resolve/{REV}/config.json": CONFIG,
            f"/org/test-model/resolve/{REV}/onnx/model.onnx": WEIGHTS,
        }
        self.cdn = self._serve(self._cdn_handler())
        self.origin = self._serve(self._origin_handler(redirect))

    def _serve(self, handler):
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    def url(self, server):
        return f"http://127.0.0.1:{server.server_address[1]}"

    def _record(self, name, req):
        self.requests.append((name, req.path, dict(req.headers)))

    def _origin_handler(self, redirect):
        fixture = self

        class Origin(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                fixture._record("origin", self)
                if redirect == "hf":
                    fixture._hf(self)
                    return
                if fixture.status != 200:
                    self.send_response(fixture.status)
                    self.end_headers()
                    return
                if redirect:
                    self.send_response(302)
                    self.send_header(
                        "Location", fixture.url(fixture.cdn) + "/blob" + self.path
                    )
                    self.end_headers()
                    return
                fixture._send(self, self.path)

        return Origin

    def _hf(self, handler):
        """Hugging Face shape: a small file 307s to a same-host resolve cache
        that requires the token again; an LFS file 302s to the CDN."""
        cache = "/api/resolve-cache/models"
        if handler.path.startswith(cache):
            if "Authorization" not in handler.headers:
                handler.send_response(401)
                handler.end_headers()
                return
            self._send(
                handler,
                handler.path.replace(
                    f"{cache}/org/test-model/{REV}/", f"/org/test-model/resolve/{REV}/"
                ),
            )
            return
        if handler.path.endswith("config.json"):
            handler.send_response(307)
            handler.send_header("Location", f"{cache}/org/test-model/{REV}/config.json")
        else:
            handler.send_response(302)
            handler.send_header("Location", self.url(self.cdn) + "/blob" + handler.path)
        handler.end_headers()

    def _cdn_handler(self):
        fixture = self

        class Cdn(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                fixture._record("cdn", self)
                fixture._send(self, self.path.removeprefix("/blob"))

        return Cdn

    def _send(self, handler, path):
        body = self.files.get(path)
        if body is None:
            handler.send_response(404)
            handler.end_headers()
            return
        handler.send_response(200)
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)

    def close(self):
        for server in (self.origin, self.cdn):
            server.shutdown()
            server.server_close()


class InstallTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="install-model-test-")
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)
        self.hf_home = self.base / "hf"
        self.token_file = self.base / "token"
        self.token_file.write_text(TOKEN + "\n")
        self.token_file.chmod(0o600)

    def fixture(self, **kwargs):
        fx = Fixture(**kwargs)
        self.addCleanup(fx.close)
        return fx

    def install(self, fx, *, gated=False, token=None, **catalog):
        model = install_model.parse_catalog(catalog_text(gated=gated, **catalog))[
            "test-model"
        ]
        return install_model.install(
            model,
            self.hf_home,
            token=token,
            endpoint=fx.url(fx.origin),
            accepted_by="operator-a",
        )

    def repo_dir(self):
        return self.hf_home / "hub" / "models--org--test-model"

    def all_bytes(self):
        return b"".join(p.read_bytes() for p in self.hf_home.rglob("*") if p.is_file())

    def test_ungated_install_layout(self):
        fx = self.fixture()
        self.install(fx)
        snap = self.repo_dir() / "snapshots" / REV
        self.assertEqual((snap / "config.json").read_bytes(), CONFIG)
        self.assertEqual((snap / "onnx/model.onnx").read_bytes(), WEIGHTS)
        self.assertEqual((self.repo_dir() / "refs/main").read_text(), REV)
        manifest = json.loads((self.repo_dir() / "locksmith-manifest.json").read_text())
        self.assertEqual(manifest["repo"], "org/test-model")
        self.assertEqual(manifest["revision"], REV)
        self.assertEqual(manifest["accepted_by"], "operator-a")
        self.assertEqual(
            [f["path"] for f in manifest["files"]], ["config.json", "onnx/model.onnx"]
        )
        self.assertFalse(list(self.repo_dir().glob("*.partial")))

    def test_ungated_sends_no_authorization(self):
        fx = self.fixture()
        self.install(fx, token=TOKEN)
        for _, _, headers in fx.requests:
            self.assertNotIn("Authorization", headers)

    def test_gated_token_only_in_origin_header(self):
        fx = self.fixture(redirect=True)
        self.install(
            fx, gated=True, token=install_model.read_token_file(self.token_file)
        )
        origin = [h for name, _, h in fx.requests if name == "origin"]
        cdn = [h for name, _, h in fx.requests if name == "cdn"]
        self.assertEqual(len(origin), 2)
        self.assertEqual(len(cdn), 2)
        for headers in origin:
            self.assertEqual(headers.get("Authorization"), f"Bearer {TOKEN}")
        for headers in cdn:
            self.assertNotIn("Authorization", headers)
        self.assertNotIn(TOKEN.encode(), self.all_bytes())

    def test_gated_same_origin_redirect_keeps_token(self):
        fx = self.fixture(redirect="hf")
        self.install(fx, gated=True, token=TOKEN)
        origin = [(path, h) for name, path, h in fx.requests if name == "origin"]
        cdn = [h for name, _, h in fx.requests if name == "cdn"]
        self.assertEqual(len(origin), 3)
        self.assertTrue(
            any(path.startswith("/api/resolve-cache/") for path, _ in origin)
        )
        for _, headers in origin:
            self.assertEqual(headers.get("Authorization"), f"Bearer {TOKEN}")
        self.assertEqual(len(cdn), 1)
        self.assertNotIn("Authorization", cdn[0])

    def test_ungated_same_origin_redirect_sends_no_token(self):
        fx = self.fixture(redirect="hf")
        with self.assertRaises(install_model.InstallError):
            # The fixture's resolve cache demands a token; ungated sends none.
            self.install(fx, gated=False, token=TOKEN)
        for _, _, headers in fx.requests:
            self.assertNotIn("Authorization", headers)

    def test_gated_without_token_makes_no_request(self):
        fx = self.fixture()
        with self.assertRaises(install_model.InstallError) as ctx:
            self.install(fx, gated=True)
        self.assertIn("token", str(ctx.exception))
        self.assertEqual(fx.requests, [])

    def test_gated_forbidden_says_accept_licence(self):
        for status in (401, 403):
            fx = self.fixture(status=status)
            with self.assertRaises(install_model.InstallError) as ctx:
                self.install(fx, gated=True, token=TOKEN)
            self.assertIn("accept the licence", str(ctx.exception))
            self.assertNotIn(TOKEN, str(ctx.exception))
            self.assertFalse(self.repo_dir().exists())

    def test_checksum_mismatch_refused(self):
        fx = self.fixture()
        with self.assertRaises(install_model.InstallError) as ctx:
            self.install(fx, weights_sha="0" * 64)
        self.assertIn("checksum", str(ctx.exception))
        self.assertFalse(self.repo_dir().exists())

    def test_oversize_body_refused(self):
        fx = self.fixture()
        with self.assertRaises(install_model.InstallError) as ctx:
            self.install(fx, size=len(WEIGHTS) - 1)
        self.assertIn("size", str(ctx.exception))
        self.assertFalse(self.repo_dir().exists())

    def test_symlinked_hub_refused(self):
        fx = self.fixture()
        elsewhere = self.base / "elsewhere"
        elsewhere.mkdir()
        self.hf_home.mkdir()
        (self.hf_home / "hub").symlink_to(elsewhere)
        with self.assertRaises(install_model.InstallError):
            self.install(fx)
        self.assertEqual(list(elsewhere.iterdir()), [])
        self.assertEqual(fx.requests, [])

    def test_install_is_readable_by_the_service_under_umask_077(self):
        # The installer runs as root; the inspector reads the cache as its own user.
        fx = self.fixture()
        self.hf_home = self.base / "models" / "inspector"  # parents made too
        old = os.umask(0o077)
        try:
            self.install(fx)
        finally:
            os.umask(old)
        for path in [self.base / "models", self.hf_home, self.hf_home / "hub",
                     self.repo_dir(), *self.repo_dir().rglob("*")]:
            mode = path.stat().st_mode & 0o777
            want = 0o755 if path.is_dir() else 0o644
            self.assertEqual(mode, want, str(path))

    def test_cache_under_a_writable_parent_refused(self):
        # Whoever can write a parent can rename the cache away and plant other weights.
        fx = self.fixture()
        parent = self.base / "shared"
        parent.mkdir()
        parent.chmod(0o777)
        self.hf_home = parent / "hf"
        with self.assertRaises(install_model.InstallError) as ctx:
            self.install(fx)
        self.assertIn(str(parent), str(ctx.exception))
        self.assertFalse(self.hf_home.exists())
        self.assertEqual(fx.requests, [])

    def test_cache_under_a_parent_owned_by_another_user_refused(self):
        # Stands in for a service-owned state directory such as $R/inspector.
        fx = self.fixture()
        model = install_model.parse_catalog(catalog_text(gated=False))["test-model"]
        stranger = os.geteuid() + 12345
        with self.assertRaises(install_model.InstallError) as ctx:
            install_model.install(
                model,
                self.hf_home,
                token=None,
                endpoint=fx.url(fx.origin),
                trusted_owners=frozenset({stranger}),
            )
        self.assertIn(str(self.base), str(ctx.exception))
        self.assertFalse(self.hf_home.exists())
        self.assertEqual(fx.requests, [])

    def test_interrupted_or_malformed_download_is_a_clean_error(self):
        import http.client

        spec = install_model.ModelFile(path="w.bin", size=4, sha256="0" * 64, git_sha1=None)

        class Short:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self, n):
                raise http.client.IncompleteRead(b"ab", 2)

        class Opener:
            def __init__(self, result):
                self.result = result

            def open(self, request, timeout):
                if isinstance(self.result, Exception):
                    raise self.result
                return self.result

        for opener in (Opener(Short()), Opener(ValueError("Port out of range 0-65535"))):
            with self.assertRaises(install_model.InstallError):
                install_model._fetch(
                    opener, "https://huggingface.co/x", None, self.base / "w.partial", spec, False
                )

    def test_default_port_counts_as_the_same_origin(self):
        self.assertEqual(
            install_model._origin("https://huggingface.co/x"),
            install_model._origin("https://HuggingFace.co:443/y"),
        )
        self.assertNotEqual(
            install_model._origin("https://huggingface.co/x"),
            install_model._origin("https://huggingface.co:8443/y"),
        )

    def test_existing_destination_refused(self):
        fx = self.fixture()
        self.repo_dir().mkdir(parents=True)
        with self.assertRaises(install_model.InstallError) as ctx:
            self.install(fx)
        self.assertIn("exists", str(ctx.exception))
        self.assertEqual(fx.requests, [])

    def test_readable_token_file_refused(self):
        self.token_file.chmod(0o644)
        with self.assertRaises(install_model.InstallError):
            install_model.read_token_file(self.token_file)

    def test_empty_token_file_refused(self):
        self.token_file.write_text("\n")
        with self.assertRaises(install_model.InstallError):
            install_model.read_token_file(self.token_file)

    def test_prompted_token_is_validated_without_echoing_it(self):
        for bad in ("", "has space", "line\nbreak", "cr\rhere"):
            with self.assertRaises(install_model.InstallError) as ctx:
                install_model.check_token(bad, "the prompt")
            if bad:
                self.assertNotIn(bad, str(ctx.exception))
        self.assertEqual(install_model.check_token(" hf_ok \n", "the prompt"), "hf_ok")

    def test_redirect_downgrade_refused(self):
        self.assertFalse(install_model.redirect_allowed("https://a/x", "http://b/y"))
        self.assertTrue(install_model.redirect_allowed("https://a/x", "https://b/y"))
        self.assertTrue(
            install_model.redirect_allowed("http://127.0.0.1/x", "http://127.0.0.1/y")
        )
        self.assertFalse(
            install_model.redirect_allowed("https://a/x", "file:///etc/passwd")
        )

    def test_cli_has_no_token_argument(self):
        result = subprocess.run(
            [sys.executable, "-I", str(EDGE / "install_model.py"), "--help"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0)
        options = {w.rstrip(",") for w in result.stdout.split() if w.startswith("--")}
        self.assertIn("--token-file", options)
        self.assertNotIn("--token", options)


class CatalogTest(unittest.TestCase):
    def test_shipped_catalog(self):
        models = install_model.load_catalog(EDGE / "models.toml")
        self.assertEqual(set(models), {"horizon-small", "promptguard2-86m"})
        self.assertFalse(models["horizon-small"].gated)
        self.assertTrue(models["promptguard2-86m"].gated)

    def test_file_needs_exactly_one_digest(self):
        bad = catalog_text(gated=False).replace(
            f'git_sha1 = "{git_sha1(CONFIG)}"',
            f'git_sha1 = "{git_sha1(CONFIG)}", sha256 = "{"0" * 64}"',
        )
        with self.assertRaises(install_model.InstallError):
            install_model.parse_catalog(bad)

    def test_revision_must_be_full_sha(self):
        with self.assertRaises(install_model.InstallError):
            install_model.parse_catalog(catalog_text(gated=False).replace(REV, "main"))

    def test_path_traversal_refused(self):
        with self.assertRaises(install_model.InstallError):
            install_model.parse_catalog(
                catalog_text(gated=False).replace("onnx/model.onnx", "../x")
            )


if __name__ == "__main__":
    unittest.main()
