from __future__ import annotations

import tempfile
import time
import unittest
from inspect import signature
from pathlib import Path

from fastapi import HTTPException

from analysis.full_mainline_glm_oracle_campaign import run_campaign
from caller_audit.demo_api import CreateDemoRunRequest, DemoApiState, format_sse_event
from caller_audit.run_stage_normalizer import normalize_mainline_run_stages, summarize_pipeline_coverage


ROOT = Path(__file__).resolve().parents[1]


class DemoApiTest(unittest.TestCase):
    def test_demo_run_lifecycle_and_artifact_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = DemoApiState(workspace=ROOT, run_root=Path(tmp) / "runs")

            demos = [demo.api_view() for demo in state.registry.values()]
            self.assertEqual(demos[0]["id"], "mac-lifecycle")

            created = state.create_run(
                CreateDemoRunRequest(
                    demo_id="mac-lifecycle",
                    mode="regression",
                    discovery_mode="offline_verified_replay",
                )
            )
            run_id = created["run_id"]
            self.assertEqual(created["status"], "queued")

            final = None
            for _ in range(80):
                payload = state.get_run(run_id)
                if payload["status"] in {"completed", "failed"}:
                    final = payload
                    break
                time.sleep(0.25)

            self.assertIsNotNone(final)
            self.assertEqual(final["status"], "completed")
            stages = {stage["id"]: stage for stage in final["stages"]}
            self.assertEqual(stages["testcase_generation"]["status"], "completed")
            self.assertEqual(stages["runtime"]["status"], "completed")
            self.assertEqual(stages["result_record"]["summary"]["candidate_count"], 1)
            self.assertEqual(stages["result_record"]["summary"]["observation_count"], 1)
            self.assertEqual(stages["context_exploration"]["status"], "completed")
            self.assertEqual(stages["context_exploration"]["summary"]["candidate_count"], 1)
            self.assertEqual(stages["context_exploration"]["summary"]["discovered_caller_count"], 1)
            self.assertTrue(final["discovered_callers"])
            self.assertEqual(final["discovered_callers"][0]["files"], ["src/mac.c"])

            events = state.trace(run_id)["events"]
            self.assertTrue(any(event["stage"] == "runtime" for event in events))
            self.assertTrue(any(event["stage"] == "impactlift" for event in events))

            artifact_ids = {item["id"] for item in state.artifacts(run_id)["artifacts"]}
            self.assertIn("rendered_harness", artifact_ids)
            self.assertIn("caller_discovery", artifact_ids)
            self.assertIn("security_impact", artifact_ids)

            harness = state.artifact_content(run_id, "rendered_harness")
            self.assertIn("EVP_MAC_update", harness.body.decode("utf-8"))

            candidates = state.candidates()
            self.assertGreaterEqual(candidates["stats"]["total"], 1)
            self.assertTrue(any(item["candidate_id"] == final["candidate_path"].split("/")[-1].replace(".yaml", "") or item["impact_state"] == "analyzed" for item in candidates["candidates"]))
            detail_id = candidates["candidates"][0]["candidate_id"]
            detail = state.candidate_detail(detail_id)
            self.assertEqual(detail["candidate"]["candidate_id"], detail_id)

            with self.assertRaises(HTTPException) as invalid_artifact:
                state.artifact_content(run_id, "../../AGENTS.md")
            self.assertEqual(invalid_artifact.exception.status_code, 404)

            with self.assertRaises(HTTPException) as invalid_run:
                state.get_run("CL-does-not-exist")
            self.assertEqual(invalid_run.exception.status_code, 404)

    def test_invalid_demo_id_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = DemoApiState(workspace=ROOT, run_root=Path(tmp) / "runs")
            with self.assertRaises(HTTPException) as exc:
                state.create_run(CreateDemoRunRequest(demo_id="missing"))
            self.assertEqual(exc.exception.status_code, 404)

    def test_overview_family_library_and_mainline_stage_normalization(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = DemoApiState(workspace=ROOT, run_root=Path(tmp) / "runs")
            overview = state.overview()
            self.assertGreaterEqual(overview["families"], 7)
            self.assertGreaterEqual(overview["libraries"], 5)
            self.assertTrue(overview["pipeline"])

            families = state.families()["families"]
            self.assertTrue(any(item["id"] == "object_state_lifecycle" for item in families))
            self.assertTrue(all("supported_libraries" in item for item in families))
            self.assertFalse(any(item["id"] == "crash_sanitizer_oracle" for item in families))
            self.assertTrue(any(item["id"] == "buffer_canary_boundary" for item in families))
            family_payload = state.families()
            excluded = family_payload["excluded_non_family_entries"]
            self.assertTrue(any(item["id"] == "crash_sanitizer_oracle" for item in excluded))
            for item in families:
                labels = item.get("supported_library_labels", [])
                self.assertEqual(len(labels), len(set(labels)))

            libraries = state.libraries()["libraries"]
            openssl = next(item for item in libraries if item["id"] == "openssl")
            self.assertEqual(openssl["runtime_capability"], "baseline_only")

            stages = normalize_mainline_run_stages(
                ROOT / "artifacts/cross_library/mainline/one_click_full_mainline_glm_oracle_campaign_v1"
            )
            by_id = {stage["id"]: stage for stage in stages}
            self.assertEqual(by_id["family_selection"]["status"], "completed")
            self.assertIn(by_id["runtime"]["status"], {"planned", "partial"})
            self.assertNotEqual(by_id["runtime"]["status"], "completed")
            self.assertEqual(by_id["context_exploration"]["status"], "not_triggered")

            summary = summarize_pipeline_coverage(stages)
            self.assertGreater(summary["not_executed_stage_count"], 0)
            self.assertEqual(summary["pipeline_coverage_label"], "Finished with partial coverage")

    def test_live_trace_records_artifact_derived_stage_statuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = DemoApiState(workspace=ROOT, run_root=Path(tmp) / "runs")
            run_id = "CL-test-live-trace"
            run_dir = state.run_dir(run_id)
            (run_dir / "selected_inputs").mkdir(parents=True)
            (run_dir / "oracle").mkdir(parents=True)
            (run_dir / "compile_run").mkdir(parents=True)
            (run_dir / "selected_inputs/stage_status.yaml").write_text("status: completed\n", encoding="utf-8")
            (run_dir / "compile_run/compile_run_summary.yaml").write_text("execution_mode: syntax_only\n", encoding="utf-8")
            (run_dir / "oracle/stage_status.yaml").write_text(
                "status: completed\nnew_candidate_count: 0\nsemantic_observation_count: 2\n",
                encoding="utf-8",
            )
            now = "2026-01-01T00:00:00+00:00"
            state.runs[run_id] = {
                "schema": "test",
                "run_id": run_id,
                "family": "object_state_lifecycle",
                "target_library": "mbedtls-3.6.4",
                "mode": "Live Model-assisted Exploration",
                "mode_key": "live",
                "status": "completed",
                "current_stage": "completed",
                "created_at": now,
                "updated_at": now,
                "run_dir": str(run_dir),
                "summary_path": str(run_dir / "run_manifest.yaml"),
                "trace_path": str(state.trace_path(run_id)),
                "stages": {},
                "error": "",
            }
            state._record_missing_normalized_stage_trace(run_id, mode="live")
            payload = state.get_run(run_id)
            stages = {stage["id"]: stage for stage in payload["stages"]}
            self.assertEqual(stages["runtime"]["status"], "planned")
            self.assertEqual(stages["context_exploration"]["status"], "not_triggered")
            self.assertEqual(payload["run_status_label"], "Finished with partial coverage")
            events = state.trace(run_id)["events"]
            self.assertTrue(any(event["stage"] == "context_exploration" and event["status"] == "not_triggered" for event in events))

    def test_sse_serialization_and_progress_callback_default_compatibility(self):
        event = {"stage": "knowledge_retrieval", "status": "running", "message": "Loading context"}
        encoded = format_sse_event(event)
        self.assertTrue(encoded.startswith("event: run_stage\n"))
        self.assertIn('"knowledge_retrieval"', encoded)
        self.assertTrue(encoded.endswith("\n\n"))

        params = signature(run_campaign).parameters
        self.assertIn("progress_callback", params)
        self.assertIsNone(params["progress_callback"].default)


if __name__ == "__main__":
    unittest.main()
