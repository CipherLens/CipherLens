"""Deterministic local unittest executor used by formal evaluation recording."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch


OUTCOMES = ("passed", "failed", "skipped", "xfailed", "errors")


class StructuredResult(unittest.TestResult):
    """Collect exact test identities without timing or host-dependent text."""

    def __init__(self) -> None:
        super().__init__()
        self.identities: dict[str, list[str]] = {key: [] for key in OUTCOMES}
        self.details: dict[str, str] = {}

    @staticmethod
    def _identity(test: unittest.case.TestCase) -> str:
        return test.id()

    def addSuccess(self, test: unittest.case.TestCase) -> None:
        super().addSuccess(test)
        self.identities["passed"].append(self._identity(test))

    def addFailure(self, test: unittest.case.TestCase, err: tuple) -> None:
        super().addFailure(test, err)
        identity = self._identity(test)
        self.identities["failed"].append(identity)
        self.details[identity] = self._exc_info_to_string(err, test)

    def addError(self, test: unittest.case.TestCase, err: tuple) -> None:
        super().addError(test, err)
        identity = self._identity(test)
        self.identities["errors"].append(identity)
        self.details[identity] = self._exc_info_to_string(err, test)

    def addSkip(self, test: unittest.case.TestCase, reason: str) -> None:
        super().addSkip(test, reason)
        identity = self._identity(test)
        self.identities["skipped"].append(identity)
        self.details[identity] = reason

    def addExpectedFailure(self, test: unittest.case.TestCase, err: tuple) -> None:
        super().addExpectedFailure(test, err)
        identity = self._identity(test)
        self.identities["xfailed"].append(identity)
        self.details[identity] = self._exc_info_to_string(err, test)

    def addUnexpectedSuccess(self, test: unittest.case.TestCase) -> None:
        super().addUnexpectedSuccess(test)
        identity = self._identity(test)
        self.identities["errors"].append(identity)
        self.details[identity] = "unexpected success"


def _deny_network(*_args: object, **_kwargs: object) -> None:
    raise RuntimeError("external network disabled by EvaluationProfile v0.1")


def execute(start_dir: str, pattern: str, suite_name: str, *, deny_network: bool) -> dict[str, object]:
    root = Path.cwd().resolve()
    start = (root / start_dir).resolve()
    start.relative_to(root)
    loader = unittest.TestLoader()
    suite = loader.discover(str(start), pattern=pattern, top_level_dir=str(root))
    result = StructuredResult()
    captured_stdout = io.StringIO()
    captured_stderr = io.StringIO()
    guards = contextlib.ExitStack()
    if deny_network:
        guards.enter_context(patch.object(socket.socket, "connect", _deny_network))
        guards.enter_context(patch.object(socket, "create_connection", _deny_network))
    with guards, contextlib.redirect_stdout(captured_stdout), contextlib.redirect_stderr(captured_stderr):
        suite.run(result)
    identities = {key: sorted(result.identities[key]) for key in OUTCOMES}
    counts = {key: len(identities[key]) for key in OUTCOMES}
    return {
        "schema_version": "cipherlens.structured_test_result.v0.1",
        "suite": suite_name,
        "discovered": suite.countTestCases(),
        "counts": counts,
        "identities": identities,
        "details": {key: result.details[key] for key in sorted(result.details)},
        "captured_stdout": captured_stdout.getvalue(),
        "captured_stderr": captured_stderr.getvalue(),
        "network_policy": "DENY_SOCKET_CONNECT" if deny_network else "UNGUARDED",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", required=True)
    parser.add_argument("--start-dir", required=True)
    parser.add_argument("--pattern", default="test_*.py")
    parser.add_argument("--deny-network", action="store_true")
    args = parser.parse_args(argv)
    result = execute(args.start_dir, args.pattern, args.suite, deny_network=args.deny_network)
    sys.stdout.write(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
    counts = result["counts"]
    assert isinstance(counts, dict)
    return 1 if counts["failed"] or counts["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
