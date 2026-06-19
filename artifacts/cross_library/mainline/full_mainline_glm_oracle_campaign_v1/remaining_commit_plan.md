# Remaining Commit Plan

建议下一轮只做精确提交，不要使用 `git add -A`。

建议提交：
- analysis/glm_live_probe.py
- analysis/full_mainline_pipeline_integration.py
- analysis/full_mainline_glm_oracle_campaign.py
- artifacts/cross_library/mainline/glm_live_probe_v1/
- artifacts/cross_library/mainline/glm_live_probe_and_mainline_status_refresh_v1/
- artifacts/cross_library/mainline/full_mainline_pipeline_integration_v1/
- artifacts/cross_library/mainline/full_mainline_glm_oracle_campaign_v1/

不要提交：
- compiled_cases/
- work/
- *.bin
- *.o
- *.so
- *.a
- 大型 *.log
- artifacts/campaigns/**
- artifacts/sprints/**
- artifacts/cross_library/seed_enrichment/**
