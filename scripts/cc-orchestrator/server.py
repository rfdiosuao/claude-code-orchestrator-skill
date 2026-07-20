#!/usr/bin/env python3
"""MCP server exposing Claude Code orchestration tools."""

from __future__ import annotations

import json
from enum import Enum
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field

from cc_orchestrator import (
    ROLE_ORDER,
    OrchestratorError,
    archive_runs,
    build_model_registry,
    benchmark_suite,
    benchmark_model,
    calibrate_policy,
    check_write_scope,
    clean_workspace,
    collect_team_results,
    compact_events,
    controller_report,
    cost_guard,
    cross_review,
    dashboard,
    daily_usage_summary,
    decision_review,
    diff_summary,
    export_report,
    folder_policy,
    handoff_read,
    handoff_repair_prompt,
    handoff_template,
    handoff_validate,
    healthcheck,
    init_workspace,
    git_diff,
    last_run,
    list_profiles,
    open_run_folder,
    score_models,
    resolve_route,
    get_provider,
    migrate_data,
    migrate_legacy_queue_payloads,
    poll_run,
    preflight_write_scope,
    project_public_endpoint,
    project_public_endpoints,
    project_public_endpoint_values,
    queue_cancel,
    queue_policy,
    queue_status,
    queue_submit,
    queue_tick,
    rollback_run,
    run_agent,
    run_status,
    run_streaming_agent,
    run_visible_agent,
    run_workflow_plan,
    workflow_dry_run,
    workflow_retry_node,
    workflow_run,
    workflow_status,
    workflow_stop,
    workflow_validate,
    workflow_write_report,
    repair_mcp_paths,
    secret_scan_run,
    send_instruction,
    local_policy_override,
    list_prompt_pack,
    render_prompt_template,
    score_worker,
    spawn_role_team,
    stop_run,
    summarize_run,
    mock_stream_test,
    upgrade_check,
    verify_run,
    workspace_status,
    write_claude_md,
    write_reports,
)
from runtime_security import RuntimeSecurityError


mcp = FastMCP("claude_code_mcp")
ROLE_DESCRIPTION = "Agent role. Supported: " + ", ".join(ROLE_ORDER) + ". Codex remains the controller."
TASK_TYPE_DESCRIPTION = (
    "Optional task route key. Supported: simple, normal, complex_code, development, "
    "review, security_review, performance_review, compatibility_review, documentation, "
    "automation, architecture, multimodal, ops."
)


class ResponseFormat(str, Enum):
    JSON = "json"
    MARKDOWN = "markdown"


class ListProfilesInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    include_current_first: bool = Field(default=True, description="Reserved for compatibility; profiles are always current-first.")
    response_format: ResponseFormat = Field(default=ResponseFormat.JSON, description="Return JSON or markdown.")


class PickProfileInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    role: str = Field(default="implementation", description=ROLE_DESCRIPTION)
    task_type: Optional[str] = Field(default=None, description=TASK_TYPE_DESCRIPTION)
    profile: Optional[str] = Field(default=None, description="Optional explicit CCSwitch profile name or id.")
    response_format: ResponseFormat = Field(default=ResponseFormat.JSON, description="Return JSON or markdown.")


class RunAgentInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    task: str = Field(..., min_length=1, max_length=20000, description="Task to give Claude Code.")
    role: str = Field(default="implementation", description=ROLE_DESCRIPTION)
    task_type: Optional[str] = Field(default=None, description=TASK_TYPE_DESCRIPTION)
    profile: Optional[str] = Field(default=None, description="Optional explicit CCSwitch profile name or id.")
    allow_write: bool = Field(default=False, description="Allow Claude Code to use acceptEdits. Defaults to read-only/plan behavior.")
    timeout_seconds: Optional[int] = Field(default=None, ge=10, le=1800, description="Optional timeout override.")
    cwd: Optional[str] = Field(default=None, description="Working directory for Claude Code. Defaults to MCP server cwd.")
    context: Optional[str] = Field(default=None, max_length=20000, description="Additional context to append to the prompt.")
    allow_unsafe_runtime: bool = Field(default=False, description="Per-request approval for a locally allowlisted custom runtime; local policy approval is also required.")


class RunStreamingAgentInput(RunAgentInput):
    include_partial_messages: bool = Field(default=True, description="Pass --include-partial-messages with stream-json output.")
    max_output_bytes: Optional[int] = Field(default=None, ge=1, description="Hard stdout+stderr byte budget. Omit to use cost-guard defaults.")
    max_events_bytes: Optional[int] = Field(default=None, ge=1, description="Hard events.ndjson byte budget. Omit to use cost-guard defaults.")
    soft_output_bytes: Optional[int] = Field(default=None, ge=1, description="Warning threshold before the hard output budget.")
    output_budget_policy: str = Field(default="stop", pattern="^(stop|truncate)$", description="What to do on hard budget exceed.")
    kill_on_excessive_output: bool = Field(default=False, description="Alias for policy=stop when the hard budget is exceeded.")
    final_only: bool = Field(default=False, description="Ask the worker to emit final-only output and suppress partial message events.")
    final_max_chars: Optional[int] = Field(default=None, ge=1000, le=200000, description="Final-only answer character budget.")


class PollRunInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    run_id: str = Field(..., description="Run id to poll.")
    stdout_offset: int = Field(default=0, ge=0, description="Byte offset into stdout.txt.")
    stderr_offset: int = Field(default=0, ge=0, description="Byte offset into stderr.txt.")
    event_offset: int = Field(default=0, ge=0, description="Byte offset into events.ndjson.")
    max_bytes: int = Field(default=20000, ge=1000, le=200000, description="Maximum bytes to read from each stream.")
    include_output_tail: bool = Field(default=True, description="Include stdout/stderr tails in the status block.")
    tail_chars: int = Field(default=4000, ge=0, le=20000, description="Tail characters for status output.")
    mode: str = Field(default="controller", pattern="^(controller|raw)$", description="controller returns compact Codex progress; raw returns stdout/stderr/event deltas.")
    max_events: int = Field(default=20, ge=1, le=200, description="Maximum compact events returned in controller mode.")
    max_summary_chars: int = Field(default=2000, ge=200, le=20000, description="Budget for compact text fields.")
    write_artifacts: bool = Field(default=True, description="Write controller artifact files while polling.")


class SummarizeRunInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    run_id: str
    event_offset: int = Field(default=0, ge=0)
    max_bytes: int = Field(default=20000, ge=1000, le=200000)
    max_events: int = Field(default=20, ge=1, le=200)
    max_summary_chars: int = Field(default=2000, ge=200, le=20000)
    write_artifacts: bool = True


class CompactEventsInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    run_id: str
    event_offset: int = Field(default=0, ge=0)
    max_bytes: int = Field(default=20000, ge=1000, le=200000)
    max_events: int = Field(default=20, ge=1, le=200)
    write_artifacts: bool = False


class StopRunInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    run_id: str = Field(..., description="Run id to stop. Required to avoid killing the wrong worker.")
    force: bool = Field(default=False, description="Force kill the process tree when graceful termination is not enough.")
    timeout_seconds: int = Field(default=5, ge=1, le=60, description="Grace seconds before reporting whether the worker is still alive.")


class RunStatusInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    run_id: Optional[str] = Field(default=None, description="Optional run id. When omitted, returns active streaming workers.")
    include_output_tail: bool = Field(default=False, description="Include stdout/stderr tails.")
    include_finished: bool = Field(default=False, description="Include finished runs when listing all runs.")
    tail_chars: int = Field(default=4000, ge=0, le=20000, description="Tail characters when include_output_tail is true.")
    limit: int = Field(default=50, ge=1, le=500, description="Maximum runs returned when listing all runs.")


class SendInstructionInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    run_id: str = Field(..., description="Existing run id.")
    instruction: str = Field(..., min_length=1, max_length=12000, description="New instruction to apply by stop-and-restart.")
    force: bool = Field(default=False, description="Force stop the old run if still active.")
    role: Optional[str] = Field(default=None, description=ROLE_DESCRIPTION)
    task_type: Optional[str] = Field(default=None, description=TASK_TYPE_DESCRIPTION)
    timeout_seconds: Optional[int] = Field(default=None, ge=10, le=1800)
    preserve_route: bool = Field(default=True, description="Preserve the previous profile/model by default.")
    reroute: bool = Field(default=False, description="Allow the follow-up run to choose a new route.")
    route_profile: Optional[str] = Field(default=None, description="Explicit profile for the restarted run.")
    route_model: Optional[str] = Field(default=None, description="Explicit model override for the restarted run.")
    allow_unsafe_runtime: bool = Field(default=False, description="Per-request approval for a locally allowlisted custom runtime; local policy approval is also required.")


class SpawnRoleTeamInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    task: str = Field(..., min_length=1, max_length=20000)
    roles: list[str] = Field(default_factory=lambda: ["requirements", "architecture", "security", "testing"], description=ROLE_DESCRIPTION)
    cwd: Optional[str] = None
    context: Optional[str] = Field(default=None, max_length=20000)
    timeout_seconds: Optional[int] = Field(default=None, ge=10, le=1800)
    allow_unsafe_runtime: bool = Field(default=False, description="Per-request approval for a locally allowlisted custom runtime; local policy approval is also required.")


class CollectTeamResultsInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    team_id: Optional[str] = None
    run_ids: list[str] = Field(default_factory=list)
    tail_chars: int = Field(default=8000, ge=1000, le=50000)


class CrossReviewInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    run_ids: list[str] = Field(..., min_length=1)
    reviewer_roles: list[str] = Field(default_factory=lambda: ["security", "testing", "review"], description=ROLE_DESCRIPTION)
    cwd: Optional[str] = None
    timeout_seconds: Optional[int] = Field(default=None, ge=10, le=1800)
    allow_unsafe_runtime: bool = Field(default=False, description="Per-request approval for a locally allowlisted custom runtime; local policy approval is also required.")


class PreflightWriteScopeInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    cwd: Optional[str] = None
    allowed_paths: list[str] = Field(default_factory=list)
    denied_paths: list[str] = Field(default_factory=list)
    max_diff_lines: int = Field(default=800, ge=1, le=20000)


class DiffSummaryInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    cwd: Optional[str] = None
    limit_chars: int = Field(default=200000, ge=1000, le=1000000)


class SecretScanRunInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    run_id: str
    include_diff: bool = True


class RollbackRunInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    run_id: str
    confirm: bool = Field(default=False, description="Required for applying a reverse patch.")


class CheckWriteScopeInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    run_id: Optional[str] = None
    cwd: Optional[str] = None


class VerifyRunInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    run_id: str
    test_commands: list[str] = Field(default_factory=list, description="Optional shell commands to run after diff/scope/secret checks.")
    test_timeout_seconds: int = Field(default=300, ge=5, le=3600)
    include_diff: bool = True


class BenchmarkModelInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    profile: Optional[str] = None
    role: str = Field(default="testing", description=ROLE_DESCRIPTION)
    task: str = Field(default="Return a concise JSON object with keys ok and summary.", max_length=20000)
    timeout_seconds: int = Field(default=120, ge=10, le=1800)
    execute: bool = Field(default=False, description="When false, returns the planned benchmark without spending model calls.")
    allow_unsafe_runtime: bool = Field(default=False, description="Per-request approval for a locally allowlisted custom runtime; local policy approval is also required.")


class BenchmarkSuiteInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    profile: Optional[str] = None
    timeout_seconds: int = Field(default=120, ge=10, le=1800)
    execute: bool = Field(default=False, description="When false, returns the planned suite without spending model calls.")
    allow_unsafe_runtime: bool = Field(default=False, description="Per-request approval for a locally allowlisted custom runtime; local policy approval is also required.")


class CalibratePolicyInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    preferences: dict = Field(default_factory=dict)
    apply: bool = True


class CostGuardInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    config: dict = Field(default_factory=dict)
    apply: bool = False


class ModelRegistryInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    refresh: bool = True
    apply: bool = False


class LocalPolicyInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    config: dict = Field(default_factory=dict)
    apply: bool = False


class ScoreWorkerInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    run_id: str
    solved: Optional[bool] = None
    hallucination: Optional[bool] = None
    needs_rework: Optional[bool] = None
    notes: Optional[str] = Field(default=None, max_length=4000)
    apply: bool = True


class PromptPackInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    template: Optional[str] = Field(default=None, description="Template name to render. Omit to list templates.")
    task: str = Field(default="", max_length=20000)
    variables: dict = Field(default_factory=dict)


class UsageSummaryInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    date: Optional[str] = Field(default=None, description="UTC date YYYY-MM-DD. Defaults to today.")
    write_report: bool = False


class QueueSubmitInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    task: str = Field(..., min_length=1, max_length=20000)
    role: str = Field(default="implementation", description=ROLE_DESCRIPTION)
    priority: int = Field(default=100, ge=-1000, le=1000)
    cwd: Optional[str] = None
    context: Optional[str] = Field(default=None, max_length=20000)
    timeout_seconds: Optional[int] = Field(default=None, ge=10, le=1800)
    max_retries: int = Field(default=0, ge=0, le=5)
    allow_write: bool = False
    allow_unsafe_runtime: bool = Field(default=False, description="Per-request approval for a locally allowlisted custom runtime; local policy approval is also required.")


class QueueTickInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    max_concurrent: Optional[int] = Field(default=None, ge=1, le=32)


class QueueStatusInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    include_finished: bool = True


class QueueCancelInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    job_id: str


class QueuePolicyInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    config: dict = Field(default_factory=dict)
    apply: bool = False


class QueueMigratePayloadsInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    apply: bool = Field(default=False, description="Preview by default; migrate and scrub legacy plaintext queue payloads only when true.")


class UpgradeCheckInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    apply: bool = False


class MockStreamTestInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    timeout_seconds: int = Field(default=20, ge=5, le=120)


class InitWorkspaceInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    cwd: Optional[str] = Field(default=None, description="Project directory. Defaults to MCP server cwd.")
    role: str = Field(default="development", description=ROLE_DESCRIPTION)
    write_claude_md: bool = Field(default=True, description="Create or update the managed CLAUDE.md section.")
    repair_mcp: bool = Field(default=False, description="Also repair/create .mcp.json path env values.")


class WorkspaceStatusInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    cwd: Optional[str] = Field(default=None, description="Project directory. Defaults to MCP server cwd.")


class MigrateDataInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    cwd: Optional[str] = None
    apply: bool = Field(default=False, description="Actually move old runs/reports/dashboard. Defaults to dry-run.")


class CleanWorkspaceInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    cwd: Optional[str] = None
    older_than_days: int = Field(default=30, ge=0, le=3650)
    dry_run: bool = Field(default=True, description="Preview only by default.")


class ArchiveRunsInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    cwd: Optional[str] = None
    older_than_days: int = Field(default=30, ge=0, le=3650)
    run_ids: list[str] = Field(default_factory=list)
    apply: bool = Field(default=False, description="Actually write the zip archive.")
    remove: bool = Field(default=False, description="Remove archived run folders after apply=true.")


class RepairMcpPathsInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    cwd: Optional[str] = None
    mcp_path: Optional[str] = Field(default=None, description="Optional .mcp.json path. Relative paths resolve under cwd.")
    create: bool = Field(default=False, description="Create .mcp.json if it does not exist.")
    apply: bool = Field(default=False, description="Write changes. Defaults to dry-run.")


class FolderPolicyInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    cwd: Optional[str] = None
    apply: bool = Field(default=False, description="Write policies/folder-policy.json.")


class DashboardInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    include_finished: bool = True
    limit: int = Field(default=12, ge=1, le=500)
    open_browser: bool = False


class OpenRunFolderInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    run_id: str
    open_folder: bool = True


class ExportReportInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    run_id: Optional[str] = None
    team_id: Optional[str] = None
    output_dir: Optional[str] = None


class ControllerReportInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    run_id: Optional[str] = None
    team_id: Optional[str] = None
    date: Optional[str] = None
    include_finished: bool = True
    limit: int = Field(default=50, ge=1, le=500)
    output_dir: Optional[str] = None


class DecisionReviewInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    proposed_action: str = Field(..., min_length=1, max_length=12000)
    task: str = Field(default="", max_length=20000)
    run_id: Optional[str] = None
    team_id: Optional[str] = None
    evidence: Optional[str] = Field(default=None, max_length=20000)
    output_dir: Optional[str] = None


class LastRunInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    run_id: Optional[str] = Field(default=None, description="Run id. Defaults to latest run.")
    include_output: bool = Field(default=True, description="Include stdout/stderr tails.")
    response_format: ResponseFormat = Field(default=ResponseFormat.JSON, description="Return JSON or markdown.")


class DiffInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    cwd: Optional[str] = Field(default=None, description="Git repository path. Defaults to MCP server cwd.")
    limit_chars: int = Field(default=12000, ge=1000, le=100000, description="Maximum diff characters to return.")


class WorkflowPlanInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    task: str = Field(..., min_length=1, max_length=20000, description="User task to plan for the configured Codex-controlled multi-agent workflow.")
    cwd: Optional[str] = Field(default=None, description="Working directory for the workflow.")


class WorkflowFileInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    file: str = Field(..., description="Workflow YAML or JSON file path.")
    task: Optional[str] = Field(default=None, max_length=20000)
    cwd: Optional[str] = None


class WorkflowRunInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    file: str = Field(..., description="Workflow YAML or JSON file path.")
    task: str = Field(..., min_length=1, max_length=20000)
    cwd: Optional[str] = None
    mock: bool = Field(default=True, description="Run without spending model quota by creating mock node runs. Real DAG execution is intentionally disabled in v0.7.0.")
    loop_guard: int = Field(default=50, ge=1, le=500)
    allow_unsafe_runtime: bool = Field(default=False, description="Per-request approval for a locally allowlisted custom runtime; local policy approval is also required.")


class WorkflowIdInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    workflow_id: str
    cwd: Optional[str] = None


class WorkflowRetryNodeInput(WorkflowIdInput):
    node_id: str


class WorkflowStopInput(WorkflowIdInput):
    force: bool = False


class HandoffTemplateInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    role: str = Field(default="testing", description=ROLE_DESCRIPTION)


class HandoffRunInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    run_id: str
    schema: Optional[str] = None


class ReportInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    output_dir: Optional[str] = Field(default=None, description="Optional report output directory. Defaults to reports/ under the orchestrator.")
    response_format: ResponseFormat = Field(default=ResponseFormat.JSON, description="Return JSON or markdown.")


class ClaudeMdInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    cwd: Optional[str] = Field(default=None, description="Project directory where CLAUDE.md should be written. Defaults to MCP server cwd.")
    role: str = Field(default="implementation", description=ROLE_DESCRIPTION)
    project_name: Optional[str] = Field(default=None, description="Optional human-readable project name.")
    append: bool = Field(default=False, description="Append a managed section if CLAUDE.md already exists.")
    force: bool = Field(default=False, description="Replace CLAUDE.md after writing a timestamped backup.")


def _json(data: object) -> str:
    return json.dumps(
        project_public_endpoint_values(data), ensure_ascii=False, indent=2
    )


def _error(exc: Exception) -> str:
    if isinstance(exc, RuntimeSecurityError):
        return _json({
            "ok": False,
            "error": exc.message,
            "security_error": exc.to_dict(),
            "next_step": exc.suggested_action,
        })
    return _json({"ok": False, "error": str(exc), "next_step": "Check cc_healthcheck and profile names, then retry."})


def _profiles_markdown(profiles: list[dict]) -> str:
    profiles = project_public_endpoint_values(profiles)
    lines = ["# Claude Code CCSwitch Profiles", ""]
    for item in profiles:
        current = " current" if item.get("current") else ""
        lines.append(f"## {item.get('name')} ({item.get('id')}){current}")
        lines.append(f"- Model: `{item.get('model')}`")
        lines.append(
            f"- Base URL: `{project_public_endpoint(item.get('base_url'))}`"
        )
        if item.get("endpoints"):
            endpoints = project_public_endpoints(item["endpoints"])
            lines.append(f"- Endpoints: {', '.join(f'`{x}`' for x in endpoints)}")
        lines.append("")
    return "\n".join(lines)


@mcp.tool(
    name="cc_healthcheck",
    annotations={
        "title": "Claude Code Orchestrator Healthcheck",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def cc_healthcheck() -> str:
    """Check Claude Code, CCSwitch, and orchestrator configuration.

    Returns JSON with binary path, CCSwitch database status, config status, profile count,
    current CCSwitch profile, and Claude Code version command result.
    """
    try:
        return _json(healthcheck())
    except Exception as exc:
        return _error(exc)


@mcp.tool(
    name="cc_list_profiles",
    annotations={
        "title": "List CCSwitch Claude Profiles",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def cc_list_profiles(params: ListProfilesInput) -> str:
    """List Claude Code provider profiles from CCSwitch with secrets redacted.

    Args:
        params (ListProfilesInput): Output options.

    Returns:
        JSON or markdown profile list including id, name, current status, model,
        base URL, endpoints, and redacted settings.
    """
    try:
        profiles = list_profiles(include_secrets=False)
        if params.response_format == ResponseFormat.MARKDOWN:
            return _profiles_markdown(profiles)
        return _json({"count": len(profiles), "profiles": profiles})
    except Exception as exc:
        return _error(exc)


@mcp.tool(
    name="cc_pick_profile",
    annotations={
        "title": "Pick Claude Code Profile",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def cc_pick_profile(params: PickProfileInput) -> str:
    """Resolve which CCSwitch profile/model should be used for a role and task type.

    This does not start Claude Code and does not modify global CCSwitch state.
    """
    try:
        route = resolve_route(role=params.role, task_type=params.task_type, profile=params.profile)
        provider = get_provider(route["profile"])
        data = {
            **route,
            "selected_profile": {
                "id": provider.id,
                "name": provider.name,
                "model": route.get("model_override") or provider.model,
                "provider_default_model": provider.model,
                "base_url": project_public_endpoint(
                    provider.env.get("ANTHROPIC_BASE_URL")
                ),
                "endpoints": project_public_endpoints(provider.endpoints),
            },
        }
        data = project_public_endpoint_values(data)
        if params.response_format == ResponseFormat.MARKDOWN:
            return "\n".join(
                [
                    "# Selected Claude Code Profile",
                    "",
                    f"- Role: `{data['role']}`",
                    f"- Task type: `{data['task_type']}`",
                    f"- Profile: `{data['selected_profile']['name']}`",
                    f"- Model: `{data['selected_profile']['provider_default_model']}`",
                    f"- Permission mode: `{data['permission_mode']}`",
                    f"- Reason: {data.get('reason') or 'No route reason configured.'}",
                ]
            )
        return _json(data)
    except Exception as exc:
        return _error(exc)


@mcp.tool(
    name="cc_run_agent",
    annotations={
        "title": "Run Claude Code Agent",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def cc_run_agent(params: RunAgentInput) -> str:
    """Run Claude Code once using a selected CCSwitch profile and role prompt.

    The orchestrator injects provider environment variables into only this subprocess.
    By default it uses plan/read-only behavior. Pass allow_write=true only for scoped
    implementation work after the caller has decided file edits are appropriate.

    Returns JSON metadata with run id, profile/model, exit code, timeout status, log paths,
    and stdout/stderr tails. Secrets are redacted from persisted logs.
    """
    try:
        data = run_agent(
            task=params.task,
            role=params.role,
            task_type=params.task_type,
            profile=params.profile,
            allow_write=params.allow_write,
            timeout_seconds=params.timeout_seconds,
            cwd=Path(params.cwd) if params.cwd else None,
            context=params.context,
            allow_unsafe_runtime=params.allow_unsafe_runtime,
        )
        return _json(data)
    except Exception as exc:
        return _error(exc)


@mcp.tool(
    name="cc_run_streaming_agent",
    annotations={
        "title": "Run Streaming Claude Code Agent",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def cc_run_streaming_agent(params: RunStreamingAgentInput) -> str:
    """Start Claude Code in the background with stream-json output.

    This uses `claude -p --output-format stream-json --include-partial-messages`,
    writes stdout/stderr plus `events.ndjson` under runs/<run_id>/, and returns
    immediately so Codex can poll or stop the worker.
    """
    try:
        data = run_streaming_agent(
            task=params.task,
            role=params.role,
            task_type=params.task_type,
            profile=params.profile,
            allow_write=params.allow_write,
            timeout_seconds=params.timeout_seconds,
            cwd=Path(params.cwd) if params.cwd else None,
            context=params.context,
            include_partial_messages=params.include_partial_messages,
            max_output_bytes=params.max_output_bytes,
            max_events_bytes=params.max_events_bytes,
            soft_output_bytes=params.soft_output_bytes,
            output_budget_policy=params.output_budget_policy,
            kill_on_excessive_output=params.kill_on_excessive_output,
            final_only=params.final_only,
            final_max_chars=params.final_max_chars,
            allow_unsafe_runtime=params.allow_unsafe_runtime,
        )
        return _json(data)
    except Exception as exc:
        return _error(exc)


@mcp.tool(
    name="cc_poll_run",
    annotations={
        "title": "Poll Streaming Claude Code Run",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def cc_poll_run(params: PollRunInput) -> str:
    """Poll a streaming run for status, event deltas, recent output, phase, and tool calls."""
    try:
        return _json(
            poll_run(
                run_id=params.run_id,
                stdout_offset=params.stdout_offset,
                stderr_offset=params.stderr_offset,
                event_offset=params.event_offset,
                max_bytes=params.max_bytes,
                include_output_tail=params.include_output_tail,
                tail_chars=params.tail_chars,
                mode=params.mode,
                max_events=params.max_events,
                max_summary_chars=params.max_summary_chars,
                write_artifacts=params.write_artifacts,
            )
        )
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_summarize_run", annotations={"title": "Summarize Run For Controller", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
async def cc_summarize_run(params: SummarizeRunInput) -> str:
    """Write and return compact controller artifacts for one run."""
    try:
        return _json(summarize_run(run_id=params.run_id, event_offset=params.event_offset, max_bytes=params.max_bytes, max_events=params.max_events, max_summary_chars=params.max_summary_chars, write_artifacts=params.write_artifacts))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_compact_events", annotations={"title": "Compact Run Events", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
async def cc_compact_events(params: CompactEventsInput) -> str:
    """Return compact event/timeline data without dumping raw events."""
    try:
        return _json(compact_events(run_id=params.run_id, event_offset=params.event_offset, max_bytes=params.max_bytes, max_events=params.max_events, write_artifacts=params.write_artifacts))
    except Exception as exc:
        return _error(exc)


@mcp.tool(
    name="cc_stop_run",
    annotations={
        "title": "Stop Streaming Claude Code Run",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def cc_stop_run(params: StopRunInput) -> str:
    """Stop a running Claude Code worker by run id."""
    try:
        return _json(stop_run(run_id=params.run_id, force=params.force, timeout_seconds=params.timeout_seconds))
    except Exception as exc:
        return _error(exc)


@mcp.tool(
    name="cc_run_status",
    annotations={
        "title": "List Streaming Claude Code Runs",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def cc_run_status(params: RunStatusInput) -> str:
    """Return one run's status or list all active Claude Code workers."""
    try:
        return _json(
            run_status(
                run_id=params.run_id,
                include_output_tail=params.include_output_tail,
                tail_chars=params.tail_chars,
                include_finished=params.include_finished,
                limit=params.limit,
            )
        )
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_send_instruction", annotations={"title": "Send Instruction By Restarting Run", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True})
async def cc_send_instruction(params: SendInstructionInput) -> str:
    """Append an instruction by stopping a non-interactive run and restarting with recovered context."""
    try:
        return _json(
            send_instruction(
                params.run_id,
                params.instruction,
                force=params.force,
                role=params.role,
                task_type=params.task_type,
                timeout_seconds=params.timeout_seconds,
                preserve_route=params.preserve_route,
                reroute=params.reroute,
                route_profile=params.route_profile,
                route_model=params.route_model,
                allow_unsafe_runtime=params.allow_unsafe_runtime,
            )
        )
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_spawn_role_team", annotations={"title": "Spawn Role Team", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True})
async def cc_spawn_role_team(params: SpawnRoleTeamInput) -> str:
    """Start several role-specific streaming Claude Code workers and write a team manifest."""
    try:
        return _json(spawn_role_team(params.task, roles=params.roles, cwd=Path(params.cwd) if params.cwd else None, context=params.context, timeout_seconds=params.timeout_seconds, allow_unsafe_runtime=params.allow_unsafe_runtime))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_collect_team_results", annotations={"title": "Collect Team Results", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
async def cc_collect_team_results(params: CollectTeamResultsInput) -> str:
    """Summarize worker outputs and mark repeated agreements plus explicit conflicts/risks."""
    try:
        return _json(collect_team_results(team_id=params.team_id, run_ids=params.run_ids, tail_chars=params.tail_chars))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_cross_review", annotations={"title": "Cross Review Worker Outputs", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True})
async def cc_cross_review(params: CrossReviewInput) -> str:
    """Launch second-round reviewer workers over previous worker outputs."""
    try:
        return _json(cross_review(params.run_ids, reviewer_roles=params.reviewer_roles, cwd=Path(params.cwd) if params.cwd else None, timeout_seconds=params.timeout_seconds, allow_unsafe_runtime=params.allow_unsafe_runtime))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_preflight_write_scope", annotations={"title": "Preflight Write Scope", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False})
async def cc_preflight_write_scope(params: PreflightWriteScopeInput) -> str:
    """Write a project-local scope file that fixes allowed paths, denied paths, and max diff size."""
    try:
        return _json(preflight_write_scope(cwd=Path(params.cwd) if params.cwd else None, allowed_paths=params.allowed_paths, denied_paths=params.denied_paths, max_diff_lines=params.max_diff_lines))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_diff_summary", annotations={"title": "Summarize Git Diff", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
async def cc_diff_summary(params: DiffSummaryInput) -> str:
    """Return a structured summary of changed files, risk markers, and whether tests are recommended."""
    try:
        return _json(diff_summary(cwd=Path(params.cwd) if params.cwd else None, limit_chars=params.limit_chars))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_secret_scan_run", annotations={"title": "Scan Run For Secrets", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
async def cc_secret_scan_run(params: SecretScanRunInput) -> str:
    """Scan stdout, stderr, events, and optionally diff for leaked credentials."""
    try:
        return _json(secret_scan_run(params.run_id, include_diff=params.include_diff))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_rollback_run", annotations={"title": "Rollback Run", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False})
async def cc_rollback_run(params: RollbackRunInput) -> str:
    """Conservatively rollback a run when the pre-run git diff was empty and confirm=true."""
    try:
        return _json(rollback_run(params.run_id, confirm=params.confirm))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_check_write_scope", annotations={"title": "Check Write Scope", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
async def cc_check_write_scope(params: CheckWriteScopeInput) -> str:
    """Check whether a run or current workspace changed files outside the preflight write scope."""
    try:
        return _json(check_write_scope(run_id=params.run_id, cwd=Path(params.cwd) if params.cwd else None))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_verify_run", annotations={"title": "Verify Claude Code Run", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False})
async def cc_verify_run(params: VerifyRunInput) -> str:
    """Run the automatic acceptance pipeline: diff summary, write-scope check, secret scan, optional tests, and report."""
    try:
        return _json(verify_run(params.run_id, test_commands=params.test_commands, test_timeout_seconds=params.test_timeout_seconds, include_diff=params.include_diff))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_benchmark_model", annotations={"title": "Benchmark CCSwitch Model", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True})
async def cc_benchmark_model(params: BenchmarkModelInput) -> str:
    """Run or plan a small real benchmark through Claude Code for a selected profile/model."""
    try:
        return _json(benchmark_model(profile=params.profile, role=params.role, task=params.task, timeout_seconds=params.timeout_seconds, execute=params.execute, allow_unsafe_runtime=params.allow_unsafe_runtime))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_benchmark_suite", annotations={"title": "Benchmark CCSwitch Model Suite", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True})
async def cc_benchmark_suite(params: BenchmarkSuiteInput) -> str:
    """Run or plan the fixed benchmark suite for code fix, review, security, long context, and multimodal planning."""
    try:
        return _json(benchmark_suite(profile=params.profile, execute=params.execute, timeout_seconds=params.timeout_seconds, allow_unsafe_runtime=params.allow_unsafe_runtime))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_calibrate_policy", annotations={"title": "Calibrate Model Policy", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False})
async def cc_calibrate_policy(params: CalibratePolicyInput) -> str:
    """Persist local model preference notes, such as strongest coding or multimodal model."""
    try:
        return _json(calibrate_policy(params.preferences, apply=params.apply))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_model_registry", annotations={"title": "Model Capability Registry", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
async def cc_model_registry(params: ModelRegistryInput) -> str:
    """Build or write the local model capability database from CCSwitch, benchmarks, and worker scores."""
    try:
        return _json(build_model_registry(refresh=params.refresh, apply=params.apply))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_local_policy", annotations={"title": "Local Policy Override", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False})
async def cc_local_policy(params: LocalPolicyInput) -> str:
    """Read or write user-owned local model routing overrides preserved across upgrades."""
    try:
        return _json(local_policy_override(params.config, apply=params.apply))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_score_worker", annotations={"title": "Score Worker Quality", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False})
async def cc_score_worker(params: ScoreWorkerInput) -> str:
    """Grade one Claude Code worker run and append quality history."""
    try:
        return _json(score_worker(params.run_id, solved=params.solved, hallucination=params.hallucination, needs_rework=params.needs_rework, notes=params.notes, apply=params.apply))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_prompt_pack", annotations={"title": "Prompt Pack", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
async def cc_prompt_pack(params: PromptPackInput) -> str:
    """List or render reusable worker prompt templates."""
    try:
        if params.template:
            return _json(render_prompt_template(params.template, task=params.task, variables=params.variables))
        return _json(list_prompt_pack())
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_cost_guard", annotations={"title": "Configure Cost Guard", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False})
async def cc_cost_guard(params: CostGuardInput) -> str:
    """Read or write concurrency and timeout guardrails for worker runs."""
    try:
        return _json(cost_guard(params.config, apply=params.apply))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_usage_summary", annotations={"title": "Daily Usage Summary", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
async def cc_usage_summary(params: UsageSummaryInput) -> str:
    """Estimate daily token usage, duration, failures, and model breakdown from saved run logs."""
    try:
        return _json(daily_usage_summary(date=params.date, write_report=params.write_report))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_queue_submit", annotations={"title": "Submit Queue Job", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True})
async def cc_queue_submit(params: QueueSubmitInput) -> str:
    """Submit a Claude Code worker job to the priority queue without starting it immediately."""
    try:
        return _json(queue_submit(task=params.task, role=params.role, priority=params.priority, cwd=Path(params.cwd) if params.cwd else None, context=params.context, timeout_seconds=params.timeout_seconds, max_retries=params.max_retries, allow_write=params.allow_write, allow_unsafe_runtime=params.allow_unsafe_runtime))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_queue_tick", annotations={"title": "Tick Queue Scheduler", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True})
async def cc_queue_tick(params: QueueTickInput) -> str:
    """Start pending queue jobs up to the configured concurrency limit."""
    try:
        return _json(queue_tick(max_concurrent=params.max_concurrent))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_queue_status", annotations={"title": "Queue Status", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
async def cc_queue_status(params: QueueStatusInput) -> str:
    """Return queued, running, and optionally finished queue jobs."""
    try:
        return _json(queue_status(include_finished=params.include_finished))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_queue_cancel", annotations={"title": "Cancel Queue Job", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False})
async def cc_queue_cancel(params: QueueCancelInput) -> str:
    """Cancel a queued job and stop its active run if it is already running."""
    try:
        return _json(queue_cancel(params.job_id))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_queue_policy", annotations={"title": "Queue Policy", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False})
async def cc_queue_policy(params: QueuePolicyInput) -> str:
    """Read or write queue defaults such as max_concurrent, retry, and timeout policy."""
    try:
        return _json(queue_policy(params.config, apply=params.apply))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_queue_migrate_payloads", annotations={"title": "Migrate Legacy Queue Payloads", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": False})
async def cc_queue_migrate_payloads(params: QueueMigratePayloadsInput) -> str:
    """Move legacy plaintext queue prompts to the native protected store."""
    try:
        return _json(migrate_legacy_queue_payloads(apply=params.apply))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_upgrade_check", annotations={"title": "Upgrade Check", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
async def cc_upgrade_check(params: UpgradeCheckInput) -> str:
    """Check or write version state while preserving local model calibration and cost guard files."""
    try:
        return _json(upgrade_check(apply=params.apply))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_mock_stream_test", annotations={"title": "Mock Streaming E2E Test", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False})
async def cc_mock_stream_test(params: MockStreamTestInput) -> str:
    """Run a fake Claude stream to test events.ndjson, poll, status, and stop without spending model quota."""
    try:
        return _json(mock_stream_test(timeout_seconds=params.timeout_seconds))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_init_workspace", annotations={"title": "Initialize Agent Workspace", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
async def cc_init_workspace(params: InitWorkspaceInput) -> str:
    """Initialize .agent-workspace, templates, policy files, rollback/log dirs, and optional CLAUDE.md."""
    try:
        return _json(init_workspace(cwd=params.cwd, role=params.role, write_claude=params.write_claude_md, repair_mcp=params.repair_mcp))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_workspace_status", annotations={"title": "Workspace Artifact Status", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
async def cc_workspace_status(params: WorkspaceStatusInput) -> str:
    """Show where Codex and Claude Code artifacts will be written."""
    try:
        return _json(workspace_status(cwd=params.cwd))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_migrate_data", annotations={"title": "Migrate Legacy Artifact Data", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False})
async def cc_migrate_data(params: MigrateDataInput) -> str:
    """Move legacy runs/reports/dashboard into the managed workspace when apply=true."""
    try:
        return _json(migrate_data(cwd=params.cwd, apply=params.apply))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_clean_workspace", annotations={"title": "Clean Agent Workspace", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False})
async def cc_clean_workspace(params: CleanWorkspaceInput) -> str:
    """Clean tmp files, non-scaffold empty dirs, and expired run artifacts. Dry-run by default."""
    try:
        return _json(clean_workspace(cwd=params.cwd, older_than_days=params.older_than_days, dry_run=params.dry_run))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_archive_runs", annotations={"title": "Archive Old Runs", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False})
async def cc_archive_runs(params: ArchiveRunsInput) -> str:
    """Zip selected or old run folders under archives/. Removal is optional and explicit."""
    try:
        return _json(archive_runs(cwd=params.cwd, older_than_days=params.older_than_days, run_ids=params.run_ids, apply=params.apply, remove=params.remove))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_repair_mcp_paths", annotations={"title": "Repair MCP Artifact Paths", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False})
async def cc_repair_mcp_paths(params: RepairMcpPathsInput) -> str:
    """Repair .mcp.json so MCP artifacts point at the managed workspace."""
    try:
        return _json(repair_mcp_paths(cwd=params.cwd, mcp_path=params.mcp_path, apply=params.apply, create=params.create))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_folder_policy", annotations={"title": "Agent Folder Policy", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
async def cc_folder_policy(params: FolderPolicyInput) -> str:
    """Return or write the policy that limits agent-generated artifacts to managed folders."""
    try:
        return _json(folder_policy(cwd=params.cwd, apply=params.apply))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_dashboard", annotations={"title": "Generate Worker Dashboard", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False})
async def cc_dashboard(params: DashboardInput) -> str:
    """Generate a local HTML dashboard for recent Claude Code workers."""
    try:
        return _json(dashboard(include_finished=params.include_finished, limit=params.limit, open_browser=params.open_browser))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_open_run_folder", annotations={"title": "Open Run Folder", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False})
async def cc_open_run_folder(params: OpenRunFolderInput) -> str:
    """Open or return a run log directory."""
    try:
        return _json(open_run_folder(params.run_id, open_folder=params.open_folder))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_export_report", annotations={"title": "Export Run Or Team Report", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False})
async def cc_export_report(params: ExportReportInput) -> str:
    """Export a run or team workflow as a Markdown report."""
    try:
        return _json(export_report(run_id=params.run_id, team_id=params.team_id, output_dir=Path(params.output_dir) if params.output_dir else None))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_controller_report", annotations={"title": "Export Controller Pressure Report", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False})
async def cc_controller_report(params: ControllerReportInput) -> str:
    """Export a Markdown report with run inventory, usage, risk, secret scan, dashboard path, and recommendations."""
    try:
        return _json(
            controller_report(
                run_id=params.run_id,
                team_id=params.team_id,
                date=params.date,
                include_finished=params.include_finished,
                limit=params.limit,
                output_dir=Path(params.output_dir) if params.output_dir else None,
            )
        )
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_pressure_report", annotations={"title": "Export Pressure Test Report", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False})
async def cc_pressure_report(params: ControllerReportInput) -> str:
    """Alias of cc_controller_report for pressure-test acceptance reports."""
    try:
        return _json(
            controller_report(
                run_id=params.run_id,
                team_id=params.team_id,
                date=params.date,
                include_finished=params.include_finished,
                limit=params.limit,
                output_dir=Path(params.output_dir) if params.output_dir else None,
            )
        )
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_decision_review", annotations={"title": "Review Controller Decision", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False})
async def cc_decision_review(params: DecisionReviewInput) -> str:
    """Create a supervisor-style decision packet and return approve/revise/block guidance."""
    try:
        return _json(
            decision_review(
                task=params.task,
                proposed_action=params.proposed_action,
                run_id=params.run_id,
                team_id=params.team_id,
                evidence=params.evidence,
                output_dir=Path(params.output_dir) if params.output_dir else None,
            )
        )
    except Exception as exc:
        return _error(exc)


@mcp.tool(
    name="cc_run_visible_agent",
    annotations={
        "title": "Run Claude Code in Visible Window",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def cc_run_visible_agent(params: RunAgentInput) -> str:
    """Open a visible PowerShell window running Claude Code with selected CCSwitch profile.

    Use when the user wants to watch or manually take over the Claude Code session.
    The prompt and launcher script are stored under runs/<run_id>/.
    """
    try:
        data = run_visible_agent(
            task=params.task,
            role=params.role,
            task_type=params.task_type,
            profile=params.profile,
            allow_write=params.allow_write,
            cwd=Path(params.cwd) if params.cwd else None,
            context=params.context,
            allow_unsafe_runtime=params.allow_unsafe_runtime,
        )
        return _json(data)
    except Exception as exc:
        return _error(exc)


@mcp.tool(
    name="cc_last_run",
    annotations={
        "title": "Get Last Claude Code Run",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def cc_last_run(params: LastRunInput) -> str:
    """Return metadata and optional output tails for a previous Claude Code run."""
    try:
        data = last_run(run_id=params.run_id, include_output=params.include_output)
        if params.response_format == ResponseFormat.MARKDOWN:
            return "\n".join(
                [
                    "# Claude Code Run",
                    "",
                    f"- Run id: `{data.get('run_id')}`",
                    f"- Role: `{data.get('role')}`",
                    f"- Profile: `{data.get('profile', {}).get('name')}`",
                    f"- Model: `{data.get('profile', {}).get('model')}`",
                    f"- Exit code: `{data.get('exit_code')}`",
                    f"- Timed out: `{data.get('timed_out')}`",
                    "",
                    "## Stdout Tail",
                    "```",
                    str(data.get("stdout_tail", "")),
                    "```",
                    "",
                    "## Stderr Tail",
                    "```",
                    str(data.get("stderr_tail", "")),
                    "```",
                ]
            )
        return _json(data)
    except Exception as exc:
        return _error(exc)


@mcp.tool(
    name="cc_git_diff",
    annotations={
        "title": "Get Git Diff",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def cc_git_diff(params: DiffInput) -> str:
    """Return git diff for a repository after Claude Code runs."""
    try:
        return _json(git_diff(cwd=Path(params.cwd) if params.cwd else None, limit_chars=params.limit_chars))
    except Exception as exc:
        return _error(exc)


@mcp.tool(
    name="cc_workflow_plan",
    annotations={
        "title": "Plan Claude Code Multi-Agent Workflow",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def cc_workflow_plan(params: WorkflowPlanInput) -> str:
    """Return the configured role/model/permission plan for the Codex-controlled workflow.

    Worker roles include requirements, development, testing, review, performance,
    compatibility, documentation, automation, security, ops, plus legacy architecture,
    implementation, and multimodal roles.
    """
    try:
        return _json(run_workflow_plan(params.task, cwd=Path(params.cwd) if params.cwd else None))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_workflow_validate", annotations={"title": "Validate Workflow DAG", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
async def cc_workflow_validate(params: WorkflowFileInput) -> str:
    """Validate a YAML/JSON workflow DAG without launching workers."""
    try:
        workflow_cwd = Path(params.cwd) if params.cwd else Path.cwd()
        return _json(workflow_validate(params.file, cwd=workflow_cwd))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_workflow_dry_run", annotations={"title": "Dry Run Workflow DAG", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
async def cc_workflow_dry_run(params: WorkflowFileInput) -> str:
    """Return topological batches, fan-in, and fan-out without launching workers."""
    try:
        workflow_cwd = Path(params.cwd) if params.cwd else Path.cwd()
        return _json(workflow_dry_run(params.file, task=params.task, cwd=workflow_cwd))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_workflow_run", annotations={"title": "Run Workflow DAG", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True})
async def cc_workflow_run(params: WorkflowRunInput) -> str:
    """Run a workflow DAG. Use mock=true to validate controller behavior without model quota."""
    try:
        workflow_cwd = Path(params.cwd) if params.cwd else Path.cwd()
        return _json(workflow_run(params.file, task=params.task, cwd=workflow_cwd, mock=params.mock, loop_guard=params.loop_guard, allow_unsafe_runtime=params.allow_unsafe_runtime))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_workflow_status", annotations={"title": "Workflow Status", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
async def cc_workflow_status(params: WorkflowIdInput) -> str:
    """Read workflow node states, run ids, gate details, and decisions."""
    try:
        return _json(workflow_status(params.workflow_id, cwd=Path(params.cwd) if params.cwd else None))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_workflow_retry_node", annotations={"title": "Retry Workflow Node", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False})
async def cc_workflow_retry_node(params: WorkflowRetryNodeInput) -> str:
    """Invalidate one workflow node and downstream nodes for a controller-managed retry."""
    try:
        return _json(workflow_retry_node(params.workflow_id, params.node_id, cwd=Path(params.cwd) if params.cwd else None))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_workflow_stop", annotations={"title": "Stop Workflow", "readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False})
async def cc_workflow_stop(params: WorkflowStopInput) -> str:
    """Cancel a workflow and stop active node runs if any."""
    try:
        return _json(workflow_stop(params.workflow_id, force=params.force, cwd=Path(params.cwd) if params.cwd else None))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_workflow_report", annotations={"title": "Workflow Report", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
async def cc_workflow_report(params: WorkflowIdInput) -> str:
    """Write a workflow report with node states, handoff validation, gates, cost, and decision trail."""
    try:
        return _json(workflow_write_report(params.workflow_id, cwd=Path(params.cwd) if params.cwd else None))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_handoff_template", annotations={"title": "Handoff Template", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
async def cc_handoff_template(params: HandoffTemplateInput) -> str:
    """Return a role-specific machine-verifiable handoff schema and example."""
    try:
        return _json(handoff_template(params.role))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_handoff_validate", annotations={"title": "Validate Handoff", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
async def cc_handoff_validate(params: HandoffRunInput) -> str:
    """Validate a run's handoff.json and write handoff.validation.json."""
    try:
        return _json(handoff_validate(params.run_id, schema_path=params.schema))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_handoff_read", annotations={"title": "Read Handoff", "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
async def cc_handoff_read(params: HandoffRunInput) -> str:
    """Read a run's handoff.json if present."""
    try:
        return _json(handoff_read(params.run_id))
    except Exception as exc:
        return _error(exc)


@mcp.tool(name="cc_handoff_repair_prompt", annotations={"title": "Handoff Repair Prompt", "readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False})
async def cc_handoff_repair_prompt(params: HandoffRunInput) -> str:
    """Generate a concise prompt asking a worker to repair missing handoff fields."""
    try:
        return _json(handoff_repair_prompt(params.run_id))
    except Exception as exc:
        return _error(exc)


@mcp.tool(
    name="cc_write_claude_md",
    annotations={
        "title": "Write CLAUDE.md for Claude Code Workers",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def cc_write_claude_md(params: ClaudeMdInput) -> str:
    """Create or update a project CLAUDE.md for Claude Code sub-agent behavior.

    The generated document tells Claude Code that Codex is the controller, embeds the
    selected role instruction, and adds safety/progress rules for orchestrated workers.
    Existing CLAUDE.md files are not overwritten unless append=true or force=true.
    """
    try:
        return _json(
            write_claude_md(
                cwd=Path(params.cwd) if params.cwd else None,
                role=params.role,
                project_name=params.project_name,
                append=params.append,
                force=params.force,
            )
        )
    except Exception as exc:
        return _error(exc)


@mcp.tool(
    name="cc_score_models",
    annotations={
        "title": "Score Local CCSwitch Models",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
)
async def cc_score_models(params: ListProfilesInput) -> str:
    """Score all Claude models discovered from local CCSwitch provider profiles.

    Scores are local heuristics, not paid benchmark results. JSON output includes
    role_scores for every configured worker role. Secrets are never returned.
    """
    try:
        data = project_public_endpoint_values(score_models())
        if params.response_format == ResponseFormat.MARKDOWN:
            lines = ["# Local CCSwitch Model Scores", "", f"Roles: {', '.join(ROLE_ORDER)}", ""]
            for item in data["models"]:
                role_scores = json.dumps(item.get("role_scores", {}), ensure_ascii=False)
                lines.append(f"- `{item['model']}` via `{item['profile_name']}`: overall `{item['overall']}/10`; role scores `{role_scores}`")
            return "\n".join(lines)
        return _json(data)
    except Exception as exc:
        return _error(exc)


@mcp.tool(
    name="cc_write_strategy_reports",
    annotations={
        "title": "Write Model Score and Strategy Reports",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def cc_write_strategy_reports(params: ReportInput) -> str:
    """Write model scoring and multi-agent strategy reports under the orchestrator."""
    try:
        data = write_reports(output_dir=Path(params.output_dir) if params.output_dir else None)
        if params.response_format == ResponseFormat.MARKDOWN:
            return "\n".join(
                [
                    "# Strategy Reports Written",
                    "",
                    f"- Scores: `{data['scores_path']}`",
                    f"- Strategy: `{data['strategy_path']}`",
                ]
            )
        return _json(data)
    except Exception as exc:
        return _error(exc)


if __name__ == "__main__":
    mcp.run()
