#!/usr/bin/env python3
"""Exercise the native_stdio example's actual process pipes after a DSR/RCH build.

No build, package installation, network access, or detached background work.
These are bounded smoke checks, not an official MCP conformance suite.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import select
import selectors
import subprocess
import time
from typing import Any

MAX_STDOUT = 512 * 1024
MAX_STDERR = 64 * 1024


def request(identifier: int, method: str, params: dict[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0", "id": identifier, "method": method,
        "params": {
            **params,
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        },
    }


def call(identifier: int, text: str, delay: int = 0) -> dict[str, Any]:
    return request(identifier, "tools/call", {
        "name": "echo", "arguments": {"text": text, "delay_ms": delay},
    })


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member in process output")
        result[key] = value
    return result


def reject_constant(_: str) -> Any:
    raise ValueError("non-finite JSON number in process output")


def check(server: Path, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    child = subprocess.Popen(
        [str(server.resolve())], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, bufsize=0,
    )
    selector = selectors.DefaultSelector()
    responses: dict[int, dict[str, Any]] = {}
    response_order: list[int] = []
    line_buffer = bytearray()
    totals = {"stdout": 0, "stderr": 0}
    notification_count = 0

    def remaining() -> float:
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("native stdio smoke check exceeded its absolute deadline")
        return left

    def send(message: dict[str, Any]) -> None:
        assert child.stdin is not None
        view = memoryview(json.dumps(message, separators=(",", ":")).encode() + b"\n")
        fd = child.stdin.fileno()
        while view:
            remaining()
            try:
                count = os.write(fd, view)
            except BlockingIOError:
                select.select([], [fd], [], remaining())
                continue
            if count == 0:
                raise RuntimeError("process stdin stopped accepting bytes")
            view = view[count:]

    def pump() -> None:
        nonlocal notification_count
        if not selector.get_map():
            raise RuntimeError("process output closed before the expected response")
        for key, _ in selector.select(remaining()):
            try:
                data = os.read(key.fd, 8192)
            except BlockingIOError:
                continue
            if not data:
                selector.unregister(key.fileobj)
                if key.data == "stdout" and line_buffer:
                    raise RuntimeError("process exited with an incomplete JSON-RPC frame")
                continue
            kind = key.data
            totals[kind] += len(data)
            if totals[kind] > (MAX_STDOUT if kind == "stdout" else MAX_STDERR):
                raise RuntimeError(f"process {kind} exceeded the smoke-check byte bound")
            if kind == "stderr":
                continue  # Never echo arbitrary server diagnostics into a test report.
            line_buffer.extend(data)
            while b"\n" in line_buffer:
                line, _, rest = line_buffer.partition(b"\n")
                line_buffer[:] = rest
                if not line.strip():
                    continue
                message = json.loads(line, object_pairs_hook=strict_object, parse_constant=reject_constant)
                if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
                    raise RuntimeError("non-JSON-RPC data on protocol stdout")
                if "id" not in message and isinstance(message.get("method"), str):
                    notification_count += 1
                    if notification_count > 64:
                        raise RuntimeError("unexpected notification flood")
                    continue
                identifier = message.get("id")
                if type(identifier) is not int or not 1 <= identifier <= 8:
                    raise RuntimeError("unexpected response identity")
                if identifier in responses:
                    raise RuntimeError("duplicate response identity")
                if "method" in message or ("result" in message) == ("error" in message):
                    raise RuntimeError("invalid response result/error shape")
                responses[identifier] = message
                response_order.append(identifier)

    def response(identifier: int) -> dict[str, Any]:
        while identifier not in responses:
            pump()
        message = responses[identifier]
        if "error" in message or not isinstance(message.get("result"), dict):
            raise RuntimeError(f"request {identifier} did not produce a successful object result")
        if message["result"].get("resultType") != "complete":
            raise RuntimeError(f"request {identifier} omitted the modern complete discriminator")
        return message["result"]

    def echoed(identifier: int, text: str) -> None:
        result = response(identifier)
        if result.get("content") != [{"type": "text", "text": text}]:
            raise RuntimeError(f"request {identifier} lost or changed its echo payload")

    try:
        assert child.stdin is not None and child.stdout is not None and child.stderr is not None
        for stream in (child.stdin, child.stdout, child.stderr):
            os.set_blocking(stream.fileno(), False)
        selector.register(child.stdout, selectors.EVENT_READ, "stdout")
        selector.register(child.stderr, selectors.EVENT_READ, "stderr")
        send(request(1, "server/discover", {}))
        response(1)
        send(request(2, "tools/list", {}))
        tools = response(2).get("tools", [])
        if not isinstance(tools, list) or not any(
            isinstance(tool, dict) and tool.get("name") == "echo" for tool in tools
        ):
            raise RuntimeError("native example did not register echo")

        send(call(3, "delayed", 2000))
        send(call(4, "independent"))
        echoed(4, "independent")
        echoed(3, "delayed")
        # A single parent read may contain both frames. Compare wire order,
        # not whether the slower reply was already buffered by that read.
        if response_order.index(4) > response_order.index(3):
            raise RuntimeError("delayed call prevented the independent response from arriving first")

        send(call(5, "must-be-cancelled", 2000))
        send(call(6, "before-cancel"))
        echoed(6, "before-cancel")
        send({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 5}})
        send(call(7, "after-cancel"))
        echoed(7, "after-cancel")

        send(call(8, "accepted-before-eof", 200))
        child.stdin.close()
        echoed(8, "accepted-before-eof")
        while selector.get_map():
            pump()
        if child.wait(timeout=remaining()) != 0:
            raise RuntimeError("native stdio example exited unsuccessfully")
        if set(responses) != {1, 2, 3, 4, 6, 7, 8}:
            raise RuntimeError("cancelled or unexpected response escaped the final drain")
    finally:
        selector.close()
        try:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=2)
        finally:
            for stream in (child.stdin, child.stdout, child.stderr):
                if stream is not None:
                    stream.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("server", type=Path, help="path to the built native_stdio example")
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args()
    if os.name != "posix":
        parser.error("this native process-pipe check requires Unix")
    if not args.server.is_file():
        parser.error("server executable does not exist; build it on the approved runner first")
    if not 5 <= args.timeout <= 120:
        parser.error("timeout must be in 5..=120 seconds")
    check(args.server, args.timeout)
    print("Native process stdio smoke checks passed: discovery, catalog, multiplexing, cancellation, EOF drain.")


if __name__ == "__main__":
    main()
