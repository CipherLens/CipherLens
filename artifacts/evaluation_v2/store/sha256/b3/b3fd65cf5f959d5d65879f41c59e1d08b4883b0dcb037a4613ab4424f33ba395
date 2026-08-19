"""Tests for strict CipherLens trace v2 validation and canonical I/O."""

from dataclasses import fields
import json
from pathlib import Path
import tempfile
import unittest

from contract_miner.trace import (
    TraceEvent,
    TraceHeader,
    TraceValidationError,
    dump_trace,
    load_trace,
)


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "traces"
TRACE_PATHS = tuple(sorted(FIXTURE_ROOT.glob("*/*.jsonl")))


def _header(**changes):
    record = {
        "record_type": "header",
        "format": "cipherlens.trace.v2",
        "library": "mbedtls",
        "build": "buggy",
        "library_version": "test-version",
        "pattern_id": "TEST-PATTERN",
        "pair_kind": "same_library_fix",
        "source": "fixture",
    }
    record.update(changes)
    return record


def _event(**changes):
    record = {
        "record_type": "event",
        "seq": 0,
        "api": "test_api",
        "role": None,
        "state_before": None,
        "state_after": None,
        "ret": 0,
        "consumed_len": None,
        "input_len": None,
        "out_state": {},
        "sanitizer_event": None,
        "error_state": None,
    }
    record.update(changes)
    return record


class TraceFormatTests(unittest.TestCase):
    def _write_records(self, root, records, *, canonical=True):
        path = Path(root) / "trace.jsonl"
        separators = (",", ":") if canonical else None
        text = "".join(
            json.dumps(
                record,
                ensure_ascii=False,
                sort_keys=False,
                separators=separators,
            )
            + "\n"
            for record in records
        )
        path.write_text(text, encoding="utf-8", newline="")
        return path

    def _assert_invalid(self, records, *fragments):
        with tempfile.TemporaryDirectory() as root:
            path = self._write_records(root, records)
            with self.assertRaises(TraceValidationError) as caught:
                load_trace(path)
        message = str(caught.exception)
        for fragment in fragments:
            self.assertIn(fragment, message)
        return caught.exception

    def test_dataclass_fields_match_spec_exactly(self):
        self.assertEqual(
            [field.name for field in fields(TraceHeader)],
            [
                "record_type",
                "format",
                "library",
                "build",
                "library_version",
                "pattern_id",
                "pair_kind",
                "source",
            ],
        )
        self.assertEqual(
            [field.name for field in fields(TraceEvent)],
            [
                "record_type",
                "seq",
                "api",
                "role",
                "state_before",
                "state_after",
                "ret",
                "consumed_len",
                "input_len",
                "out_state",
                "sanitizer_event",
                "error_state",
            ],
        )

    def test_exactly_three_fixture_pairs_validate(self):
        self.assertEqual(6, len(TRACE_PATHS))
        self.assertEqual(3, len(tuple(FIXTURE_ROOT.glob("*/README.md"))))
        for path in TRACE_PATHS:
            with self.subTest(path=path):
                header, events = load_trace(path)
                self.assertEqual("cipherlens.trace.v2", header.format)
                self.assertGreaterEqual(len(events), 1)

    def test_all_fixtures_round_trip_byte_identically(self):
        with tempfile.TemporaryDirectory() as root:
            for path in TRACE_PATHS:
                with self.subTest(path=path):
                    header, events = load_trace(path)
                    output = Path(root) / path.name
                    dump_trace(header, events, output)
                    self.assertEqual(path.read_bytes(), output.read_bytes())

    def test_t1_requires_first_and_only_header_and_an_event(self):
        cases = {
            "missing_header": ([_event()], "expected 'header'"),
            "double_header": ([_header(), _header(), _event()], "second header"),
            "no_events": ([_header()], "at least one event"),
        }
        for name, (records, fragment) in cases.items():
            with self.subTest(name=name):
                self._assert_invalid(records, "T1", fragment)

    def test_t2_requires_zero_based_contiguous_sequence(self):
        cases = {
            "nonzero_start": [_event(seq=1)],
            "skip": [_event(seq=0), _event(seq=2)],
            "out_of_order": [_event(seq=0), _event(seq=2), _event(seq=1)],
        }
        for name, events in cases.items():
            with self.subTest(name=name):
                self._assert_invalid([_header(), *events], "T2", ".seq")

    def test_t3_rejects_unknown_role_and_accepts_schema_role(self):
        self._assert_invalid([_header(), _event(role="DECODE")], "T3", "unknown role")
        with tempfile.TemporaryDirectory() as root:
            path = self._write_records(root, [_header(), _event(role="PARSE")])
            _, events = load_trace(path)
        self.assertEqual("PARSE", events[0].role)

    def test_t4_requires_symmetric_bounded_lengths(self):
        cases = (
            _event(consumed_len=1, input_len=None),
            _event(consumed_len=None, input_len=1),
            _event(consumed_len=5, input_len=4),
        )
        for event in cases:
            with self.subTest(event=event):
                self._assert_invalid([_header(), event], "T4")

    def test_t5_rejects_unknown_and_missing_fields_at_both_levels(self):
        header_unknown = _header(extra=True)
        event_unknown = _event(extra=True)
        event_missing = _event()
        del event_missing["api"]
        cases = (
            ([header_unknown, _event()], "line 1.extra: unknown field"),
            ([_header(), event_unknown], "line 2.extra: unknown field"),
            ([_header(), event_missing], "line 2.api: required field missing"),
        )
        for records, fragment in cases:
            with self.subTest(fragment=fragment):
                self._assert_invalid(records, "T5", fragment)

    def test_t5_rejects_boolean_where_integer_is_required(self):
        self._assert_invalid(
            [_header(), _event(ret=True)], "T5", "line 2.ret: expected integer or null"
        )

    def test_t6_rejects_noncanonical_but_semantically_valid_json(self):
        with tempfile.TemporaryDirectory() as root:
            path = self._write_records(root, [_header(), _event()], canonical=False)
            with self.assertRaises(TraceValidationError) as caught:
                load_trace(path)
        self.assertIn("T6 file: non-canonical trace encoding", str(caught.exception))

    def test_t6_preserves_utf8_unicode_line_separator_inside_json_string(self):
        with tempfile.TemporaryDirectory() as root:
            path = self._write_records(
                root, [_header(pattern_id="TEST\u2028PATTERN"), _event()]
            )
            header, events = load_trace(path)
            output = Path(root) / "round-trip.jsonl"
            dump_trace(header, events, output)
            self.assertEqual(path.read_bytes(), output.read_bytes())

    def test_t7_rejects_closed_registry_and_value_violations(self):
        cases = (
            (_event(out_state={"invented": True}), "unknown key"),
            (_event(out_state={"tag_value": "abc"}), "even-length hex"),
            (_event(out_state={"parse_result": "maybe"}), "parse_result"),
            (_event(sanitizer_event="SEGV at 0x7f00"), "sanitizer_event"),
        )
        for event, fragment in cases:
            with self.subTest(fragment=fragment):
                self._assert_invalid([_header(), event], "T7", fragment)

    def test_header_closed_literals_reject_old_format_and_pair_kind(self):
        cases = (
            (_header(format="cipherlens.trace.v1"), ".format"),
            (_header(build="patched"), ".build"),
            (_header(pair_kind="unrelated"), ".pair_kind"),
            (_header(source="generated"), ".source"),
        )
        for header, fragment in cases:
            with self.subTest(fragment=fragment):
                self._assert_invalid([header, _event()], "T1", fragment)

    def test_one_load_aggregates_at_least_three_independent_errors(self):
        header = _header(format="cipherlens.trace.v1", extra=True)
        event = _event(seq=3, role="DECODE", sanitizer_event="raw SIGSEGV")
        del event["api"]
        error = self._assert_invalid(
            [header, event],
            "line 1.extra: unknown field",
            "line 1.format",
            "line 2.api: required field missing",
            "T2 line 2.seq",
            "T3 line 2.role",
            "T7 line 2.sanitizer_event",
        )
        self.assertGreaterEqual(len(error.errors), 3)


if __name__ == "__main__":
    unittest.main()
