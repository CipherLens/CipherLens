from __future__ import annotations

from typing import Any


def classify(
    static_checks: dict[str, Any],
    dynamic: dict[str, Any],
    reachability: dict[str, Any],
) -> dict[str, Any]:
    baseline_passed = bool(dynamic.get("baseline_passed"))
    candidate_confirmed = bool(
        dynamic.get("mutation_candidate_confirmed")
    )
    fix_control_passed = bool(dynamic.get("fix_control_passed"))
    sanitizer_error = bool(
        dynamic.get("asan_error") or dynamic.get("ubsan_error")
    )

    production_reachable = bool(
        reachability.get("production_reachable")
    )
    attacker_controlled = bool(
        reachability.get("attacker_controlled_input")
    )
    protocol_route = bool(
        reachability.get("official_protocol_route_found")
    )
    security_impact = bool(
        reachability.get("security_impact_demonstrated")
    )

    if sanitizer_error:
        status = "security_impact_demonstrated"
        reason = "Dynamic execution produced sanitizer evidence."
    elif not baseline_passed:
        status = "invalid_or_inconclusive_harness"
        reason = "The baseline positive control did not pass."
    elif not candidate_confirmed:
        status = "caller_behavior_not_confirmed"
        reason = "The mutation did not reproduce caller behavior."
    elif not fix_control_passed:
        status = "caller_behavior_confirmed_needs_fix_control"
        reason = (
            "Caller behavior is confirmed, but the patched "
            "fix-control regression did not pass."
        )
    elif security_impact:
        status = "security_impact_demonstrated"
        reason = (
            "Caller behavior, fix control, and security impact "
            "were demonstrated."
        )
    elif production_reachable and attacker_controlled:
        status = "production_reachable_candidate"
        reason = (
            "Caller behavior and fix control are confirmed on a "
            "production-reachable attacker-controlled path."
        )
    elif not production_reachable and not protocol_route:
        status = "downgraded_unreachable"
        reason = (
            "Caller behavior and fix control are confirmed, but "
            "no production or official protocol route was demonstrated."
        )
    else:
        status = "caller_behavior_confirmed"
        reason = (
            "Caller behavior and fix control are confirmed; "
            "reachability or security impact remains unresolved."
        )

    return {
        "status": status,
        "reason": reason,
        "baseline_passed": baseline_passed,
        "dynamic_candidate_confirmed": candidate_confirmed,
        "fix_control_passed": fix_control_passed,
        "production_call_sites_without_check": static_checks.get(
            "production_without_full_consumption_check", 0
        ),
        "production_reachable": production_reachable,
        "attacker_controlled_input": attacker_controlled,
        "official_protocol_route_found": protocol_route,
        "security_impact_demonstrated": security_impact,
        "vulnerability_confirmed": (
            status == "security_impact_demonstrated"
        ),
    }
