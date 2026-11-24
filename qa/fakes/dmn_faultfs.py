"""A directory whose writes can be made to fail, for AGENT-251's unwritable-database cases.

`FaultFs` mounts a passthrough FUSE filesystem (no root: fusermount3 and /dev/fuse)
over a backing directory. While `fail_writes()` is in force every write, create,
truncate, fsync, rename and unlink returns EIO, as on an XFS filesystem that has
shut down; reads keep working. `restore()` lifts it. The daemon keeps its open
file descriptors throughout, which a read-only remount would refuse.

The filesystem server runs as `python dmn_faultfs.py BACKING MOUNT FLAG` in its
own process group; it fails writes while FLAG exists.
"""

from __future__ import annotations

import errno
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

WRITE_OPS = frozenset(
    {"write", "truncate", "fsync", "create", "unlink", "rename", "mkdir", "rmdir",
     "chmod", "utimens", "fallocate", "link", "symlink"}
)


def available() -> str | None:
    """None when FaultFs can run here, else why it can't."""
    if not sys.platform.startswith("linux"):
        return "needs Linux FUSE"
    if not os.path.exists("/dev/fuse"):
        return "needs /dev/fuse"
    if shutil.which("fusermount3") is None:
        return "needs fusermount3"
    try:
        import mfusepy  # noqa: F401
    except (ImportError, OSError) as e:
        return f"needs mfusepy and libfuse3 ({e})"
    return None


class FaultFs:
    def __init__(self) -> None:
        # A short, bounded root of our own; removed on close. Same base as the
        # harness work directories, so the leak check covers it (AGENT-356).
        base = os.environ.get("LSQA_WORK_BASE") or "/tmp"
        self.root = Path(tempfile.mkdtemp(prefix="lsqa-fault-", dir=base)).resolve()
        self.backing = self.root / "backing"
        self.mount = self.root / "mnt"
        self.flag = self.root / "fail-writes"
        self.backing.mkdir()
        self.mount.mkdir()
        self.proc = subprocess.Popen(
            [sys.executable, __file__, str(self.backing), str(self.mount), str(self.flag)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        deadline = time.monotonic() + 10
        while not os.path.ismount(self.mount):
            if self.proc.poll() is not None or time.monotonic() > deadline:
                self.close()
                raise RuntimeError("fault filesystem did not mount")
            time.sleep(0.05)

    def fail_writes(self) -> None:
        self.flag.touch()

    def restore(self) -> None:
        self.flag.unlink(missing_ok=True)

    def close(self) -> None:
        self.restore()
        if os.path.ismount(self.mount):
            # Lazy: a process that still holds a file open must not wedge cleanup.
            subprocess.run(["fusermount3", "-u", "-z", str(self.mount)],
                           capture_output=True, timeout=10, check=False)
        if self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
                self.proc.wait(timeout=5)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                os.killpg(self.proc.pid, signal.SIGKILL)
                self.proc.wait(timeout=5)
        shutil.rmtree(self.root, ignore_errors=True)


def _serve(backing: str, mount: str, flag: str) -> None:
    import mfusepy as fuse

    class Passthrough(fuse.Operations):
        use_ns = True

        def __getattribute__(self, name):
            attr = object.__getattribute__(self, name)
            if name in WRITE_OPS and os.path.exists(flag):
                raise fuse.FuseOSError(errno.EIO)
            return attr

        @staticmethod
        def _p(path):
            return os.path.join(backing, path.lstrip("/"))

        def access(self, path, amode):
            if not os.access(self._p(path), amode):
                raise fuse.FuseOSError(errno.EACCES)

        def getattr(self, path, fh=None):
            st = os.lstat(self._p(path))
            return {k: getattr(st, k) for k in (
                "st_atime_ns", "st_ctime_ns", "st_gid", "st_mode", "st_mtime_ns",
                "st_nlink", "st_size", "st_uid")}

        def readdir(self, path, fh):
            return [".", "..", *os.listdir(self._p(path))]

        def open(self, path, flags):
            return os.open(self._p(path), flags)

        def create(self, path, mode, fi=None):
            # Read-write: SQLite maps its -shm file and pages it in through read.
            return os.open(self._p(path), os.O_RDWR | os.O_CREAT, mode)

        def read(self, path, size, offset, fh):
            return os.pread(fh, size, offset)

        def write(self, path, data, offset, fh):
            return os.pwrite(fh, data, offset)

        def truncate(self, path, length, fh=None):
            if fh is not None:
                os.ftruncate(fh, length)
            else:
                os.truncate(self._p(path), length)

        def fsync(self, path, datasync, fh):
            (os.fdatasync if datasync else os.fsync)(fh)

        def flush(self, path, fh):
            return 0

        def release(self, path, fh):
            os.close(fh)

        def unlink(self, path):
            os.unlink(self._p(path))

        def rename(self, old, new):
            os.rename(self._p(old), self._p(new))

        def mkdir(self, path, mode):
            os.mkdir(self._p(path), mode)

        def rmdir(self, path):
            os.rmdir(self._p(path))

        def chmod(self, path, mode):
            os.chmod(self._p(path), mode)

        def utimens(self, path, times=None):
            os.utime(self._p(path), ns=times)

        def statfs(self, path):
            st = os.statvfs(self._p(path))
            return {k: getattr(st, k) for k in (
                "f_bavail", "f_bfree", "f_blocks", "f_bsize", "f_favail", "f_ffree",
                "f_files", "f_flag", "f_frsize", "f_namemax")}

    # No attribute caching: SQLite's mapped -shm file must see its real size.
    fuse.FUSE(Passthrough(), mount, foreground=True, nothreads=False,
              attr_timeout=0, entry_timeout=0, negative_timeout=0)


if __name__ == "__main__":
    _serve(*sys.argv[1:4])
