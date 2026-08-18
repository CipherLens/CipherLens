"""Production-oriented, fail-closed integration for the CipherLens v2 path.

This package deliberately owns orchestration and operational persistence only.
Security semantics remain in the frozen Contract, Matcher, Merge, and execution
model packages.
"""

from pipeline_v2.artifact_store import ArtifactRef, ArtifactStore
from pipeline_v2.attempt import PipelineAttempt, PipelineAttemptResult
from pipeline_v2.campaign import CampaignPolicy, CampaignState, CampaignSummary

__all__ = [
    "ArtifactRef", "ArtifactStore", "CampaignPolicy", "CampaignState",
    "CampaignSummary", "PipelineAttempt", "PipelineAttemptResult",
]
