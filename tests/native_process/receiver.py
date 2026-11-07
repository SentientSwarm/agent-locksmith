"""Separate receiving process: counts every accepted TCP connection, including TLS."""
import json
import os
from pathlib import Path
import socket
import sys


def write(path: Path, value: object) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value))
    os.replace(temporary, path)


def main(directory: Path) -> None:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        write(directory / "count.json", 0)
        write(directory / "port.json", listener.getsockname()[1])
        count = 0
        while True:
            connection, _ = listener.accept()
            count += 1
            write(directory / "count.json", count)
            connection.close()


if __name__ == "__main__":
    main(Path(sys.argv[1]))
