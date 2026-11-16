#!/usr/bin/env python3
"""Bounded inference probes; credentials stay in memory, response text is never logged."""
import json
import time
import urllib.error
import urllib.request


class ProbeError(Exception):
    pass


def reject_unauthenticated(base, component):
    path = '/v1/responses' if component == 'codex' else '/v1/messages'
    for key in [None, 'edge-handoff-deliberately-invalid-key']:
        headers = {'Content-Type': 'application/json'}
        if key is not None:
            if component == 'codex': headers['Authorization'] = 'Bearer ' + key
            else: headers['x-api-key'] = key
        request = urllib.request.Request(base.rstrip('/') + path, method='POST',
                                         headers=headers, data=b'{}')
        try:
            with urllib.request.urlopen(request, timeout=10):
                raise ProbeError('missing/bad authentication accepted')
        except urllib.error.HTTPError as error:
            # A CDN challenge is not evidence that the local key gate ran.
            try:
                if error.code != 401:
                    raise ProbeError('expected local authentication refusal') from error
            finally:
                error.close()


def completed_stream(response, event, seconds=90):
    deadline = time.monotonic() + seconds
    consumed = 0
    while time.monotonic() < deadline:
        line = response.readline(65537)
        if not line:
            break
        consumed += len(line)
        if len(line) > 65536 or consumed > 1024 * 1024:
            raise ProbeError("inference canary exceeded response budget")
        if not line.startswith(b"data:"):
            continue
        try:
            data = json.loads(line[5:].strip())
        except (ValueError, UnicodeError):
            continue
        if not isinstance(data, dict):
            continue
        if data.get("type") in {"error", "response.failed", "response.incomplete"}:
            raise ProbeError("inference canary returned a failure event")
        if data.get("type") == event:
            return
    raise ProbeError("inference canary stream did not complete")


def responses_probe(base, key, model):
    request = urllib.request.Request(base.rstrip("/") + "/v1/responses", method="POST",
        headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"},
        data=json.dumps({"model": model, "input": [{"role":"user", "content":[{"type":"input_text","text":"Reply with pong."}]}],
                         "instructions": "Reply briefly.", "store": False, "stream": True}).encode())
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            if response.status != 200:
                raise ProbeError("Responses canary HTTP failure")
            completed_stream(response, "response.completed")
    except (OSError, urllib.error.URLError) as error:
        raise ProbeError("Responses canary transport/HTTP failure") from error


def messages_probe(base, key, model):
    request = urllib.request.Request(base.rstrip("/") + "/v1/messages", method="POST",
        headers={"x-api-key": key, "anthropic-version": "2023-06-01", "Content-Type": "application/json"},
        data=json.dumps({"model": model, "max_tokens": 32, "stream": True,
                         "messages": [{"role": "user", "content": "Reply with pong."}]}).encode())
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            if response.status != 200:
                raise ProbeError("Messages canary HTTP failure")
            completed_stream(response, "message_stop")
    except (OSError, urllib.error.URLError) as error:
        raise ProbeError("Messages canary transport/HTTP failure") from error
