#!/usr/bin/env python3
"""Reference inspection sidecar for agent-locksmith (AGENT-254).

Serves `POST /scan` over a Unix socket, scoring text with PromptGuard 2
(prompt injection and jailbreaks, rule `promptguard`) and CodeShield
(insecure code in responses, rule `codeshield`) through LlamaFirewall.
See README.md for the model licence, install and the systemd unit.

Wire protocol (one request per connection):
  request  {"direction": "request" | "response", "text": "..."}
  answer   {"hits": [{"rule": str, "start": int, "end": int, "score": float}]}
Offsets are UTF-8 byte offsets into `text`; a classifier scores the whole
text, so a hit covers all of it.
"""

import argparse
import json
import os
import socketserver
from http.server import BaseHTTPRequestHandler

MAX_BODY = 2 * 1024 * 1024


def load_firewall():
    try:
        from llamafirewall import LlamaFirewall, Role, ScannerType
    except ImportError as err:
        raise SystemExit(f"llamafirewall is not installed: {err}") from err
    return LlamaFirewall(
        {
            Role.USER: [ScannerType.PROMPT_GUARD],
            Role.TOOL: [ScannerType.PROMPT_GUARD],
            Role.ASSISTANT: [ScannerType.CODE_SHIELD],
        }
    )


def scan(firewall, direction: str, text: str, threshold: float) -> list[dict]:
    from llamafirewall import AssistantMessage, ScanDecision, ToolMessage, UserMessage

    end = len(text.encode("utf-8"))
    hits = []
    message = UserMessage(content=text) if direction == "request" else ToolMessage(content=text)
    guard = firewall.scan(message)
    if guard.score >= threshold:
        hits.append({"rule": "promptguard", "start": 0, "end": end, "score": guard.score})
    if direction == "response" and "```" in text:
        shield = firewall.scan(AssistantMessage(content=text))
        if shield.decision != ScanDecision.ALLOW:
            hits.append({"rule": "codeshield", "start": 0, "end": end, "score": shield.score})
    return hits


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802 (http.server naming)
        if self.path != "/scan":
            return self.answer(404, {"error": "not found"})
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            return self.answer(413, {"error": "too large"})
        try:
            body = json.loads(self.rfile.read(length))
            direction, text = body["direction"], body["text"]
            if direction not in ("request", "response") or not isinstance(text, str):
                raise ValueError("bad request")
        except (ValueError, KeyError, TypeError):
            return self.answer(400, {"error": "bad request"})
        hits = scan(self.server.firewall, direction, text, self.server.threshold)
        self.answer(200, {"hits": hits})

    def answer(self, status: int, body: dict):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)

    def address_string(self):
        return "unix"

    def log_message(self, fmt, *args):
        # Never log request bodies: they may hold secrets.
        pass


class Server(socketserver.UnixStreamServer):
    def __init__(self, path: str, firewall, threshold: float):
        self.firewall = firewall
        self.threshold = threshold
        super().__init__(path, Handler)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--socket", required=True, help="Unix socket path to listen on")
    parser.add_argument("--threshold", type=float, default=0.5, help="PromptGuard score to flag")
    args = parser.parse_args()
    if os.path.exists(args.socket):
        os.unlink(args.socket)
    firewall = load_firewall()
    os.umask(0o077)  # the socket is for Locksmith's user only
    with Server(args.socket, firewall, args.threshold) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
