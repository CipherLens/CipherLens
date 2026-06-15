"""ORACLE_EVENT instrumentation helpers for renderers."""

from __future__ import annotations

from typing import Any


def oracle_event_enabled(profile: str) -> bool:
    return profile == "oracle_event_v1"


def oracle_instrumentation_meta(profile: str, family: str) -> dict[str, Any]:
    enabled = oracle_event_enabled(profile)
    events = ["parse", "full_consumption_check", "cleanup"]
    if family == "pkcs_container_parsing":
        events = ["parse", "verify", "full_consumption_check", "cleanup"]
    limitations = []
    if family == "pkcs_container_parsing":
        limitations.append(
            "PKCS12_parse has a return value but no separate pointer-consumption signal; consumed_len is observed from d2i_PKCS12."
        )
    return {
        "enabled": enabled,
        "profile": profile if enabled else "",
        "expected_event_prefix": "ORACLE_EVENT" if enabled else "",
        "emitted_events": events if enabled else [],
        "limitations": limitations if enabled else [],
    }


def oracle_event_cleanup_printf(job: dict[str, Any], api: str, instrumentation_profile: str) -> str:
    if not oracle_event_enabled(instrumentation_profile):
        return ""
    return (
        f'    printf("ORACLE_EVENT schema=oracle_event_v1 case_id={job["case_id"]} '
        f'family={job["family"]} mutation_strategy={job["mutation_strategy"]} '
        f'target_library=openssl phase=cleanup api={api} cleanup_executed=1\\n");\n'
    )
