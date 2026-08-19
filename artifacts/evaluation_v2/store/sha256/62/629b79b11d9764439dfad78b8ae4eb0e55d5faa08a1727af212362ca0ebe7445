from pathlib import Path
import tempfile
import unittest

from contract_miner.trace import TraceEvent, TraceHeader, TraceValidationError, dump_trace, load_trace


class TraceV03ObservableTests(unittest.TestCase):
    def test_source_observation_fields_round_trip(self):
        header = TraceHeader("header", "cipherlens.trace.v2", "mbedtls", "buggy", "rev", "PATTERN", "same_library_fix", "fixture")
        event = TraceEvent("event", 0, "api", "FINAL", None, None, -1, None, None, {"output_length_before": 0, "output_length_after": 9, "buffer_present": False, "stored_length": 4}, None, None)
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "trace.jsonl"
            dump_trace(header, [event], path)
            loaded_header, events = load_trace(path)
        self.assertEqual(header, loaded_header)
        self.assertEqual(event, events[0])

    def test_negative_output_length_is_rejected(self):
        header = TraceHeader("header", "cipherlens.trace.v2", "mbedtls", "buggy", "rev", "PATTERN", "same_library_fix", "fixture")
        event = TraceEvent("event", 0, "api", "FINAL", None, None, -1, None, None, {"output_length_after": -1}, None, None)
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "trace.jsonl"
            with self.assertRaises(TraceValidationError):
                dump_trace(header, [event], path)


if __name__ == "__main__":
    unittest.main()
