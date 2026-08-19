"""Shared B0 state names; none represents a completed real campaign."""

from __future__ import annotations

from enum import Enum


class CampaignPreflightStatus(str, Enum):
    PREPARED_FOR_7D_B0_FOUNDATION = "PREPARED_FOR_7D_B0_FOUNDATION"
    PREPARED_FOR_7D_B = "PREPARED_FOR_7D_B"
    B_BLOCKED_WITH_REASONS = "7D_B_BLOCKED_WITH_REASONS"
    BLOCKED = "BLOCKED"
    READY_FOR_7D_C = "READY_FOR_7D_C"


ORACLE_EVENT_SCHEMA = "cipherlens.oracle_event.v0.1"
TARGET_AWARE_BOUND_SOURCE_SCHEMA = "cipherlens.target_aware_bound_source.v0.1"
