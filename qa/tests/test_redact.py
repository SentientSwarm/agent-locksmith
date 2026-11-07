from pathlib import Path

from harness.redact import Canaries, scan_bundle

CANARY = "canary-value-0123456789abcdef"


def test_canary_found_in_nested_file_without_leaking_it(tmp_path: Path):
    (tmp_path / "a" / "b").mkdir(parents=True)
    (tmp_path / "a" / "b" / "log.txt").write_text(f"token was {CANARY}\n")
    canaries = Canaries()
    canaries.add(CANARY, "op-token")
    findings = scan_bundle(tmp_path, canaries)
    assert findings == ["a/b/log.txt: op-token"]
    assert all(CANARY not in f for f in findings)


def test_shapes_found(tmp_path: Path):
    (tmp_path / "ops.yaml").write_text('token_hash: "$argon2id$v=19$m=4096,t=3,p=1$abc$def"\n')
    (tmp_path / "wire.txt").write_text("pugHvHG2Ixa_kgsJph1xMA.AbCdEfGhIjKlMnOpQrStUvWxYz012345\n")
    (tmp_path / "key.pem").write_text("-----BEGIN PRIVATE KEY-----\nAAAA\n")
    (tmp_path / "bearer.txt").write_text("Authorization: Bearer abcdefghijklmnopqrstuvwxyz\n")
    (tmp_path / "url.txt").write_text("https://idp.example/cb?code=abc123&state=xyz\n")
    findings = scan_bundle(tmp_path, Canaries())
    names = sorted(f.split(":")[0] for f in findings)
    assert names == ["bearer.txt", "key.pem", "ops.yaml", "url.txt", "wire.txt"]


def test_clean_bundle(tmp_path: Path):
    (tmp_path / "report.md").write_text("| SMK-HEALTH-001 | PASS |\n")
    (tmp_path / "results.json").write_text('{"public_id": "pugHvHG2Ixa_kgsJph1xMA"}\n')
    assert scan_bundle(tmp_path, Canaries()) == []


def test_binary_file_is_scanned_without_error(tmp_path: Path):
    (tmp_path / "shot.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\xff" + CANARY.encode())
    canaries = Canaries()
    canaries.add(CANARY, "agent-token")
    assert scan_bundle(tmp_path, canaries) == ["shot.png: agent-token"]


def test_short_values_ignored():
    canaries = Canaries()
    canaries.add("abc", "short")
    canaries.add("", "empty")
    assert canaries.labels() == []


def test_redact_replaces_canary():
    canaries = Canaries()
    canaries.add(CANARY, "op-token")
    assert canaries.redact(f"x {CANARY} y") == "x <redacted:op-token> y"
