#!/usr/bin/env python3
"""Build, smoke-test and verify the eight release assets for a commit, locally.

  scripts/release-local.py --commit SHA --out DIR --mac USER@HOST [--ssh-option OPT ...]
      [--qemu PATH --arm64-root DIR]

GitHub Actions is off for this repository, so release.yml can't build a release.
This script does the same job on hosts you control:

  target                     built on    with                 smoke-tested
  x86_64-unknown-linux-gnu   this host   cargo build          natively
  aarch64-unknown-linux-gnu  this host   cargo zigbuild       under qemu-user (--qemu, --arm64-root)
  aarch64-apple-darwin       --mac       cargo build          natively
  x86_64-apple-darwin        --mac       cargo build (cross)  under Rosetta

This host must be x86_64 Linux. Each target builds with Rust 1.94.0 --locked
from a fresh clone of the commit, so the binaries report source_state clean.
Each pair is then smoke-tested on a host that runs it (the version, help,
--build-info, a daemon start with /version and /readyz, and an agent list),
and scripts/verify-build.py's checks must accept it against SHA256SUMS and
refuse it for a wrong revision.

DIR (outside the source tree) holds:
  targets/SUFFIX/  each target's pair and record.json, kept between runs
  assets/          the eight binaries, SHA256SUMS and validation.json, written
                   only once every target verifies
  notes.md         the commit's CHANGELOG section, from its release-notes.py

A rerun reuses a target whose record is verified for this commit and whose
files still match it. Exit 0 when all eight verify. Otherwise exit 1, naming
each failed target, with no assets/ (so no SHA256SUMS).
"""
import argparse
import hashlib
import json
import os
import platform
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
from native_validation import common as C

V = C.V  # verify-build.py, loaded by common
TOOLCHAIN = "1.94.0"
BUILD_TIMEOUT = 3600
STEP_TIMEOUT = 600
ROLES = ("locksmith", "locksmithd")


class Target:
    def __init__(self, triple, where, builder, smoke):
        self.triple, self.where, self.builder, self.smoke = triple, where, builder, smoke
        self.suffix = C.TARGETS[triple][3]

    def names(self):
        return [f"{role}-{self.suffix}" for role in ROLES]


TARGETS = [
    Target("x86_64-unknown-linux-gnu", "local", "build", "native"),
    Target("aarch64-unknown-linux-gnu", "local", "zigbuild", "qemu-user"),
    Target("aarch64-apple-darwin", "mac", "build", "native"),
    Target("x86_64-apple-darwin", "mac", "build", "rosetta"),
]
BINARIES = sorted(name for t in TARGETS for name in t.names())


class Failed(Exception):
    """A step refused; the message is short and carries no secrets."""


def sha256(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def cargo_args(target):
    args = C.flags(target.triple)
    args[1] = target.builder  # "build" or "zigbuild"
    return args


def sums_text(hashes):
    return "".join(f"{hashes[name]}  {name}\n" for name in sorted(hashes))


# --- hosts -------------------------------------------------------------------

def run(argv, *, cwd=None, env=None, timeout=STEP_TIMEOUT, what="command"):
    """Run in its own process group; kill the group on timeout or exit."""
    child = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             start_new_session=True)
    try:
        out, err = child.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        raise Failed(f"{what} timed out after {timeout} s") from None
    finally:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()
    if child.returncode:
        tail = err.decode(errors="replace").strip().splitlines()[-3:]
        raise Failed(f"{what} exited {child.returncode}: {' | '.join(tail)[:300]}")
    return out.decode(errors="replace")


class Local:
    name = "local"

    def __init__(self, work, path_prefix=()):
        self.work = Path(work)
        self.env = {**C.environment(), "PATH": os.pathsep.join(
            [*map(str, path_prefix), str(Path.home() / ".cargo/bin"), os.environ.get("PATH", "")])}

    def label(self):
        return f"{socket.gethostname().split('.')[0]} ({platform.system()} {platform.machine()})"

    def sh(self, command, timeout=STEP_TIMEOUT, what="command"):
        return run(["bash", "-c", command], env=self.env, timeout=timeout, what=what)

    def put(self, src, dst):
        Path(dst).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

    def get(self, src, dst):
        self.put(src, dst)

    def cleanup(self):
        shutil.rmtree(self.work, ignore_errors=True)


class Remote:
    def __init__(self, dest, work, ssh_options):
        self.dest, self.work = dest, work
        self.ssh = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=15"]
        for option in ssh_options:
            self.ssh += ["-o", option]
        self.name = dest

    def label(self):
        return f"{self.dest.split('@')[-1]} ({self.sh('uname -sm').strip()})"

    def sh(self, command, timeout=STEP_TIMEOUT, what="command"):
        wrapped = f'export PATH="$HOME/.cargo/bin:$HOME/.local/bin:/usr/bin:/bin:/usr/sbin:/sbin"; {command}'
        return run(["ssh", *self.ssh, self.dest, wrapped], timeout=timeout, what=f"{what} on {self.dest}")

    def put(self, src, dst):
        self.sh(f"mkdir -p {shlex.quote(str(Path(dst).parent))}", what="mkdir")
        run(["scp", "-q", *self.ssh, str(src), f"{self.dest}:{dst}"], what=f"copy to {self.dest}")

    def get(self, src, dst):
        Path(dst).parent.mkdir(parents=True, exist_ok=True)
        run(["scp", "-q", *self.ssh, f"{self.dest}:{src}", str(dst)], what=f"copy from {self.dest}")

    def cleanup(self):
        try:
            self.sh(f"rm -rf {shlex.quote(self.work)}", what="cleanup")
        except Failed:
            pass


# --- producing one target ----------------------------------------------------

HELPERS = ["release-local.py", "verify-build.py", "native_validation/common.py", "native_validation/smoke.py",
           "native_validation/build.py", "native_validation/http.py"]


class Producer:
    """Builds, smoke-tests and verifies targets on real hosts."""

    def __init__(self, commit, version, out, bundle, hosts, pythons, qemu=None, arm64_root=None):
        self.commit, self.version, self.out, self.bundle = commit, version, Path(out), bundle
        self.hosts, self.pythons, self.qemu, self.arm64_root = hosts, pythons, qemu, arm64_root
        self.ready = {}

    def wrap(self, target):
        if target.smoke == "qemu-user":
            if not (self.qemu and self.arm64_root):
                raise Failed("--qemu and --arm64-root are needed to run linux-arm64")
            return [str(self.qemu), "-L", str(self.arm64_root)]
        if target.smoke == "rosetta":
            return ["arch", "-x86_64"]
        return []

    def prepare(self, host):
        """Clone the commit and copy the smoke helpers onto the host, once."""
        if host.name in self.ready:
            return self.ready[host.name]
        work = str(host.work)
        host.sh(f"rm -rf {shlex.quote(work)} && mkdir -p {shlex.quote(work)}", what="work dir")
        host.put(self.bundle, f"{work}/src.bundle")
        host.sh(f"cd {shlex.quote(work)} && git clone -q src.bundle src && "
                f"git -C src checkout -q --detach {self.commit} && "
                f"test -z \"$(git -C src status --porcelain --untracked-files=all)\"",
                what="clone the commit")
        for helper in HELPERS:
            host.put(HERE / helper, f"{work}/helpers/{helper}")
        self.ready[host.name] = work
        return work

    def build_and_smoke(self, target):
        host = self.hosts[target.where]
        wrap = self.wrap(target)
        if target.smoke == "rosetta":
            try:
                host.sh("arch -x86_64 /usr/bin/true", what="Rosetta check")
            except Failed:
                raise Failed("Rosetta is not installed on the Mac (softwareupdate --install-rosetta)") from None
        work = self.prepare(host)
        tdir = f"{work}/target-{target.suffix}"
        command = " ".join(shlex.quote(a) for a in ["cargo", *cargo_args(target)])
        started = time.monotonic()
        host.sh(f"cd {shlex.quote(work)}/src && CARGO_TARGET_DIR={shlex.quote(tdir)} {command}",
                timeout=BUILD_TIMEOUT, what=f"{target.suffix} build")
        seconds = round(time.monotonic() - started)
        rustc = host.sh(f"rustc +{TOOLCHAIN} --version --verbose", what="rustc -vV")
        local = self.out / "targets" / target.suffix
        shutil.rmtree(local, ignore_errors=True)
        pair = f"{work}/pair-{target.suffix}"
        host.sh(f"rm -rf {pair} && mkdir -p {pair}", what="pair dir")
        for role, name in zip(ROLES, target.names()):
            built = f"{tdir}/{target.triple}/release/{role}"
            host.sh(f"cp {shlex.quote(built)} {pair}/{name}", what="capture")
            host.get(f"{pair}/{name}", local / name)
            C.binary_arch(local / name, target.triple)
        smoke = self.helper(host, work, target, "smoke", pair, wrap)
        return {
            "state": "smoked", "target": target.triple, "suffix": target.suffix,
            "revision": self.commit, "version": self.version,
            "files": {name: sha256(local / name) for name in target.names()},
            "build": {"host": host.label(), "builder": f"cargo {target.builder}", "command": command,
                      "rustc": rustc.strip(), "seconds": seconds},
            "smoke": {"method": target.smoke, "host": host.label(), "wrapper": Path(wrap[0]).name if wrap else None,
                      "result": smoke},
        }

    def verify(self, target, sums):
        host = self.hosts[target.where]
        work = self.prepare(host)
        pair = f"{work}/pair-{target.suffix}"
        local = self.out / "targets" / target.suffix
        for name in target.names():  # the bytes in DIR are what we verify
            host.put(local / name, f"{pair}/{name}")
        host.put(sums, f"{pair}/SHA256SUMS")
        return self.helper(host, work, target, "verify", pair, self.wrap(target))

    def helper(self, host, work, target, mode, pair, wrap):
        args = [*shlex.split(self.pythons[target.where]), f"{work}/helpers/release-local.py", mode, "--pair", pair,
                "--suffix", target.suffix, "--version", self.version, "--revision", self.commit]
        if wrap:
            args += ["--wrap", json.dumps(wrap)]
        text = host.sh(" ".join(shlex.quote(a) if not a.startswith("~") else a for a in args),
                       what=f"{target.suffix} {mode}")
        try:
            return json.loads(text.strip().splitlines()[-1])
        except (ValueError, IndexError):
            raise Failed(f"{target.suffix} {mode} gave no result") from None


# --- the release -------------------------------------------------------------

def load_record(out, target, commit):
    path = out / "targets" / target.suffix / "record.json"
    try:
        record = json.loads(path.read_text())
        files = {name: sha256(path.parent / name) for name in target.names()}
    except (OSError, ValueError):
        return None
    if record.get("revision") != commit or record.get("files") != files:
        return None
    return record


def save_record(out, target, record):
    path = out / "targets" / target.suffix / "record.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=1, sort_keys=True) + "\n")


def assemble(out, records, source):
    """Write assets/ from verified records, all at once."""
    hashes = {name: digest for r in records.values() for name, digest in r["files"].items()}
    if sorted(hashes) != BINARIES:
        raise Failed("the records do not name exactly the eight binaries")
    staging = out / "assets.partial"
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True)
    for record in records.values():
        for name, digest in record["files"].items():
            shutil.copy2(out / "targets" / record["suffix"] / name, staging / name)
            if sha256(staging / name) != digest:
                raise Failed(f"{name} changed while assembling")
    validation = {
        "source": source,
        "recipe": "scripts/release-local.py (local build; GitHub Actions not used)",
        "assets": {name: {"target": r["target"], "sha256": r["files"][name], "revision": r["revision"],
                          "build_host": r["build"]["host"], "rustc": r["build"]["rustc"],
                          "smoke": {"method": r["smoke"]["method"], "host": r["smoke"]["host"],
                                    "result": r["smoke"]["result"]},
                          "verify": r["verify"]}
                   for r in records.values() for name in r["files"]},
    }
    (staging / "validation.json").write_text(json.dumps(validation, indent=1, sort_keys=True) + "\n")
    (staging / "SHA256SUMS").write_text(sums_text(hashes))  # last: its presence means complete
    os.replace(staging, out / "assets")
    return hashes


def progress(line):
    print(line, file=sys.stderr, flush=True)


def release(out, commit, source, producer, targets=TARGETS, log=progress):
    """Produce every target, verify each against SHA256SUMS, then write assets/."""
    out = Path(out)
    shutil.rmtree(out / "assets", ignore_errors=True)
    shutil.rmtree(out / "assets.partial", ignore_errors=True)
    records, failures = {}, {}
    for target in targets:
        record = load_record(out, target, commit)
        if record and record["state"] in ("smoked", "verified"):
            log(f"{target.suffix}: reusing {record['state']} assets for {commit[:12]}")
        else:
            log(f"{target.suffix}: building and smoke-testing")
            try:
                record = producer.build_and_smoke(target)
            except (Failed, ValueError, OSError) as error:
                failures[target.suffix] = str(error)
                log(f"{target.suffix}: FAILED: {error}")
                continue
            save_record(out, target, record)
        records[target.suffix] = record
    if failures:
        return failures
    hashes = {name: d for r in records.values() for name, d in r["files"].items()}
    with tempfile.TemporaryDirectory() as scratch:
        sums = Path(scratch) / "SHA256SUMS"
        sums.write_text(sums_text(hashes))
        for target in targets:
            record = records[target.suffix]
            if record["state"] == "verified":
                continue
            try:
                result = producer.verify(target, sums)
                if not (result.get("accepted") and result.get("wrong_revision_refused")):
                    raise Failed(f"verify-build result {result}")
            except (Failed, ValueError, OSError) as error:
                failures[target.suffix] = str(error)
                log(f"{target.suffix}: verify FAILED: {error}")
                continue
            record.update(state="verified", verify=result)
            save_record(out, target, record)
            log(f"{target.suffix}: verified against SHA256SUMS")
    if failures:
        return failures
    assemble(out, records, source)
    return {}


# --- helper modes, run on the host that executes the pair --------------------

def wrapped_execute(wrap):
    original = V.execute

    def execute(path, arguments, *, resolve=True, **kwargs):
        if not resolve or not wrap:  # toolchain proxies run as they are
            return original(path, arguments, resolve=resolve, **kwargs)
        program = Path(wrap[0])
        return original(program if program.is_absolute() else Path(shutil.which(wrap[0])),
                        [*wrap[1:], str(Path(path).resolve()), *arguments], resolve=False, **kwargs)
    return execute


def helper_main(argv):
    parser = argparse.ArgumentParser(prog="release-local.py smoke|verify")
    parser.add_argument("mode", choices=["smoke", "verify"])
    for name in ("pair", "suffix", "version", "revision"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--wrap", default="[]")
    args = parser.parse_args(argv)
    wrap = json.loads(args.wrap)
    V.execute = wrapped_execute(wrap)
    pair = Path(args.pair)
    cli, daemon = pair / f"locksmith-{args.suffix}", pair / f"locksmithd-{args.suffix}"
    if args.mode == "verify":
        sums = pair / "SHA256SUMS"
        accepted = V.verify(cli, daemon, sums, args.version, args.revision)
        wrong = "0" * 40 if args.revision != "0" * 40 else "1" * 40
        try:
            V.verify(cli, daemon, sums, args.version, wrong)
            refused = False
        except ValueError as error:
            refused = str(error) == "identity_mismatch"
        result = {"accepted": accepted["verified"], "wrong_revision_refused": refused,
                  "sha256": {r: f["sha256"] for r, f in accepted["files"].items()}}
    else:
        from native_validation.smoke import owned_smoke
        hashes = {p.name: sha256(p) for p in (cli, daemon)}
        sums = pair / "pair.sha256"
        sums.write_text(sums_text(hashes))
        info = {role: V.inspect(path) for role, path in (("locksmith", cli), ("locksmithd", daemon))}
        V.verify(cli, daemon, sums, args.version, args.revision)
        identity = {"version": args.version, "revision": args.revision}
        probe = {}
        with tempfile.TemporaryDirectory(prefix="release-smoke-") as private:
            checks = owned_smoke({"locksmith": cli, "locksmithd": daemon}, identity, Path(private), probe,
                                 wrap=wrap)
        result = {"build_info": info, "checks": checks, "native": not wrap,
                  "host": f"{platform.system()} {platform.machine()}"}
    print(json.dumps(result, sort_keys=True))
    return 0


# --- driver ------------------------------------------------------------------

def driver_main(argv):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--commit", required=True, help="the commit to build (any revision name)")
    parser.add_argument("--out", type=Path, required=True, help="output directory, outside the repo")
    parser.add_argument("--mac", required=True, help="USER@HOST of an Apple silicon Mac")
    parser.add_argument("--ssh-option", action="append", default=[], help="extra ssh -o option")
    parser.add_argument("--mac-python", default="~/.local/bin/uv run -q --no-project --python 3.13 python3",
                        help="Python 3.11+ command on the Mac")
    parser.add_argument("--qemu", type=Path, default=os.environ.get("LOCKSMITH_QEMU_AARCH64"),
                        help="qemu-aarch64 user-mode binary (env LOCKSMITH_QEMU_AARCH64)")
    parser.add_argument("--arm64-root", type=Path, default=os.environ.get("LOCKSMITH_ARM64_ROOT"),
                        help="arm64 Linux root for qemu -L (env LOCKSMITH_ARM64_ROOT)")
    parser.add_argument("--zig-path", type=Path, action="append", default=[],
                        help="directory to put first on PATH for cargo zigbuild (zig or python -m ziglang)")
    args = parser.parse_args(argv)
    out = args.out.resolve()
    if out.is_relative_to(ROOT):
        parser.error("--out must be outside the source tree")
    if (platform.system(), platform.machine()) != ("Linux", "x86_64"):
        parser.error("run this on an x86_64 Linux host")
    started = time.monotonic()
    try:
        commit = run(["git", "-C", str(ROOT), "rev-parse", "--verify", args.commit + "^{commit}"],
                     what="resolve commit").strip()
    except Failed as error:
        print(f"release-local: {error}", file=sys.stderr)
        return 1
    out.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="release-local-", dir=out))
    hosts = {"local": Local(work / "local", args.zig_path),
             "mac": Remote(args.mac, f"/tmp/release-local-{commit[:12]}-{os.getpid()}", args.ssh_option)}
    try:
        src = work / "src"
        run(["git", "clone", "-q", "--no-local", str(ROOT), str(src)], what="clone")
        run(["git", "-C", str(src), "checkout", "-q", "--detach", commit], what="checkout")
        source = C.source(src, commit)  # refuses a dirty clone or another revision
        run(["git", "-C", str(src), "bundle", "create", "-q", str(work / "src.bundle"), "HEAD"], what="bundle")
        producer = Producer(commit, source["version"], out, work / "src.bundle", hosts,
                            {"local": sys.executable, "mac": args.mac_python},
                            args.qemu and args.qemu.resolve(), args.arm64_root and args.arm64_root.resolve())
        failures = release(out, commit, source, producer)
        if not failures:
            # Notes come from the commit's own CHANGELOG and release-notes.py.
            run([sys.executable, "-B", str(src / "scripts/release-notes.py"), "--assets", str(out / "assets"),
                 "--ref", f"refs/tags/v{source['version']}", "--revision", commit,
                 "--out", str(out / "notes.md")], what="release notes")
    except (Failed, ValueError, OSError) as error:
        failures = {"setup": str(error)}
    finally:
        for host in hosts.values():
            host.cleanup()
        shutil.rmtree(work, ignore_errors=True)
    seconds = round(time.monotonic() - started)
    if failures:
        for name, why in failures.items():
            print(f"release-local: {name} failed: {why}", file=sys.stderr)
        print(json.dumps({"ok": False, "commit": commit, "failed": sorted(failures), "seconds": seconds}))
        return 1
    print(json.dumps({"ok": True, "commit": commit, "version": source["version"], "seconds": seconds,
                      "assets": str(out / "assets"), "notes": str(out / "notes.md")}))
    return 0


if __name__ == "__main__":
    os.umask(0o077)
    argv = sys.argv[1:]
    if argv and argv[0] in ("smoke", "verify"):
        sys.exit(helper_main(argv))
    sys.exit(driver_main(argv))
