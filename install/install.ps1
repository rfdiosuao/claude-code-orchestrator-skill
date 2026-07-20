param(
    [string]$CodexHome = $env:CODEX_HOME
)

$ErrorActionPreference = "Stop"

if (-not $CodexHome) {
    $CodexHome = Join-Path $env:USERPROFILE ".codex"
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$targetRoot = Join-Path $CodexHome "skills"
$target = Join-Path $targetRoot "claude-code-orchestrator"
$backup = "$target.backup.$(Get-Date -Format 'yyyyMMdd-HHmmss')"

New-Item -ItemType Directory -Force -Path $targetRoot | Out-Null

if (Test-Path -LiteralPath $target) {
    Move-Item -LiteralPath $target -Destination $backup
    Write-Host "Backed up existing skill to $backup"
}

New-Item -ItemType Directory -Force -Path $target | Out-Null
robocopy $repoRoot $target /E /XD .git runs reports dashboard .agent-workspace node_modules __pycache__ /XF *.pyc model_calibration.json model_registry.json model_benchmark_history.json local_policy.override.json runtime_security.override.json runtime_security.audit.key worker_quality_history.json cost_guard.json queue_policy.json version_state.json queue.json | Out-Null
if ($LASTEXITCODE -gt 7) {
    throw "robocopy failed with exit code $LASTEXITCODE"
}
$global:LASTEXITCODE = 0

$preserveRelative = @(
    "scripts\cc-orchestrator\config\model_calibration.json",
    "scripts\cc-orchestrator\config\model_registry.json",
    "scripts\cc-orchestrator\config\model_benchmark_history.json",
    "scripts\cc-orchestrator\config\local_policy.override.json",
    "scripts\cc-orchestrator\config\runtime_security.override.json",
    "scripts\cc-orchestrator\config\worker_quality_history.json",
    "scripts\cc-orchestrator\config\cost_guard.json",
    "scripts\cc-orchestrator\config\queue_policy.json",
    "scripts\cc-orchestrator\config\version_state.json"
)

if (Test-Path -LiteralPath $backup) {
    foreach ($relative in $preserveRelative) {
        $source = Join-Path $backup $relative
        $destination = Join-Path $target $relative
        if (Test-Path -LiteralPath $source) {
            $expectedHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination) | Out-Null
            Copy-Item -LiteralPath $source -Destination $destination -Force
            $actualHash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash
            if ($actualHash -ne $expectedHash) {
                throw "Preserved local config failed verification: $relative"
            }
            Write-Host "Preserved local config: $relative"
        }
    }
}

$toolHome = Join-Path $target "scripts\cc-orchestrator"

Write-Host ""
Write-Host "Claude Code Orchestrator Skill installed."
Write-Host "Skill path: $target"
Write-Host ""
Write-Host "Run:"
Write-Host "  `$env:CC_ORCHESTRATOR_HOME = `"$toolHome`""
Write-Host "  python `"`$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py`" selftest"
Write-Host "  python `"`$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py`" healthcheck"
Write-Host "  python `"`$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py`" init-workspace --cwd ."
Write-Host "  python `"`$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py`" workspace-status --cwd ."
Write-Host "  python `"`$env:CC_ORCHESTRATOR_HOME\cc_orchestrator.py`" upgrade-check --apply"
Write-Host ""
Write-Host "For Codex/Claude MCP auto-registration, run:"
Write-Host "  powershell -ExecutionPolicy Bypass -File `"$target\install\install-mcp.ps1`""
