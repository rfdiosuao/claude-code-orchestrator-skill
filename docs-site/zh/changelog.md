# 更新日志

这里记录 Claude Code Orchestrator Skill 的主要版本变化。

## v0.8.0 - Guarded runtime launch

- 新增 provider 环境隔离和不可变、无密钥的 runtime 启动合约。
- 自定义 runtime 必须同时具备完整递归 identity pin 和每次请求的显式批准。
- foreground、streaming、visible、queue、team、workflow 全链路使用进程身份安全的 containment 和停止逻辑。
- 即时 prompt 改走受控 stdin；队列正文进入受保护存储，unsafe grant 只能消费一次。
- 新增字段白名单、hash chain、认证 checkpoint、失败标记和容量上限的安全审计。
- v0.8.0 的生产级 guarded worker 执行目前仅支持 Windows；macOS 和 Linux 在具备内核强制的整棵进程树 containment 后端之前会 fail closed。
- Windows CI 在 Python 3.10/3.12 上运行完整测试集；Ubuntu 和 macOS 运行专门的 POSIX 发布契约，验证进程身份、runtime 策略、受保护存储、安装行为和生产 fail-closed 边界，Linux 还检查非 UTF-8 Git 路径的字节级精确性。

## v0.7.1 - 手动 retry 会取消 workflow 成功状态

- 修复 GitHub issue #24。
- `workflow-retry-node` 会把被手动 invalidated 的 workflow 从 `succeeded` 改成 `needs_rerun`。
- 被 invalidated 的节点会清掉当前 handoff、校验、gate、run id、token、cost 证据，只保留紧凑的 `stale_evidence` 标记。
- workflow report 会显示手动 invalidation 警告，避免 Codex 或 dashboard 接受过期成功状态。
- selftest 新增手动 retry 状态、stale evidence、报告警告三组检查。

## v0.7.0 - 工作流 DAG、handoff 合约、节点 gate

- 新增 GitHub issues #20、#21、#22 的第一版工作流 DAG 控制层。
- 新增 `workflow-validate`、`workflow-dry-run`、`workflow-run --mock`、`workflow-status`、`workflow-retry-node`、`workflow-stop`、`workflow-report`。v0.7.0 暂时只开放 mock DAG 执行。
- 新增 `handoff-template`、`handoff-validate`、`handoff-read`、`handoff-repair-prompt`。
- 补齐 workflow / handoff 对应 MCP 工具。
- 新增 mock 控制器 gate：重试决策、超过重试阻断、缺 handoff 阻断下游、loop guard、decision trail 报告。
- 新增 `examples/workflows/safe-refactor.yaml`。

## v0.6.4 - 用数据验证的 worker 管控修复

- 修复 GitHub issues #16、#17、#18。
- `--final-only` 会先过滤 raw stream 噪声，再计算持久 stdout 预算，并只写紧凑最终结果。
- `run`、`run-streaming`、`run-visible` 会使用 `--cwd` 对应的 artifact root，并通过 run index 保证控制器还能按 run id 找到日志。
- 真实 token 聚合会先从 raw Claude `modelUsage` 计算，再做脱敏。
- Windows PID 检测从慢 `tasklist` 改为系统 API。
- `mock-stream-test` 新增 final-only 噪声过滤、cwd 产物路由、token 聚合保留三组 gate。

## v0.6.3 - 文档部署稳定性

- 修复 GitHub Actions 文档部署里的密钥扫描误报。
- 保留占位密钥回归测试，但把样例 token 拆成字符串拼接，避免仓库级扫描误判为真实 key。
- 同步 README、文档站 changelog、package 元数据和 version 元数据。

## v0.6.2 - 实际模型归因

- 修复 #15：把 Claude stream 里的 `modelUsage` 保存为 `actual_model_usage`。
- run status 和 metadata 新增 `actual_model`、`actual_cost_usd`、`actual_total_tokens`、`route_mismatch`。
- `detect_failure_modes` 会把路由不一致标成高风险。
- `usage-summary`、dashboard、控制报告都会区分声明路由模型和实际计费模型。
- 新增 `supervise-decision`，作为 `decision-review` 的兼容别名。

## v0.6.1 - issue 审核补丁

- `controller-report` / `pressure-report` Markdown 补齐按模型统计、总耗时、token 估算、输出字节、事件字节、预算停止次数、warning/blocking 计数和最高风险等级。
- 每个 run 的报告行新增耗时、token 估算、stdout/events 字节、warning/blocking 计数、预算状态、源码/产物变化数量。
- dashboard 输出预算区域新增 token 估算。
- `usage-summary` 和按模型统计新增 warning/blocking 风险计数。
- 旧 metadata 写入路径统一走 UTF-8/控制字符清洗。

## v0.6.0 - 总控运维加固

- 修复 GitHub issues #3-#12。
- `spawn-role-team` 新增团队容量预检和部分启动回滚，避免失败后留下后台 worker。
- streaming worker 新增输出/事件硬预算、final-only 模式和预算停止原因。
- `send-instruction` 默认保留上一次 profile/model，并记录 route drift。
- metadata、events、CLI JSON、dashboard 增加 UTF-8 和控制字符保护，中文路径/中文 prompt 更稳。
- 风险结果拆成阻塞状态、警告、最高等级和兼容旧 `ok`。
- 密钥扫描新增分类，输出只给脱敏证据。
- diff 拆分项目源码改动和 `.agent-workspace` Agent 产物改动。
- dashboard 升级成总控运维面板。
- 新增 `controller-report` / `pressure-report` 和对应 MCP 报告工具。
- 新增监督审查 `decision-review` / `cc_decision_review`。

## v0.5.1 - 便携资产和安全清理

- 修复 GitHub issues #1 和 #2。
- 轻量 `tools/cc-orchestrator` 复制布局现在能发现 `version.json` 和 Prompt Pack。
- 用户也可以用 `CC_ORCHESTRATOR_SKILL_ROOT` 指向完整 Skill 包。
- `healthcheck` 新增 `skill_root`、`version_path`、`prompt_pack_path` 和 Prompt Pack 是否可用的输出。
- `clean-workspace` 现在会保护刚初始化出来的骨架目录，不再提示删除它们。
- selftest 新增 Prompt Pack 可用性和清理不删除骨架目录的回归检查。

## v0.5.0 - 工作区治理

- 新增 `.agent-workspace/claude-code-orchestrator`，默认收纳 Agent 生成的运行产物。
- 新增 `init-workspace`、`workspace-status`、`migrate-data`、`clean-workspace`、`archive-runs`、`repair-mcp-paths`、`folder-policy`。
- 每个工作区治理命令都补齐了对应 MCP 工具。
- 更新 worker prompt 和生成的 `CLAUDE.md`，让日志、报告、临时文件、回滚记录进入统一目录。
- 更新安装示例和文档，让不同电脑上的产物路径更稳定。

## v0.4.1 - 总控 checkpoint 和队列状态补强

- 新增滚动 `checkpoint-###.md`，用于长任务阶段总结。
- 新增工具调用去重摘要，比如 `Grep x7`、`Read x3`。
- `poll-run` 的 controller 模式默认写入压缩后的总控产物。
- 队列状态明确为 `queued`、`running`、`done`、`failed`、`timed_out`、`cancelled`。
- 改进本地 dashboard，看模型路由、时间线、日志、diff、风险和控制命令更清楚。

## v0.4.0 - Codex 总控系统

- 新增 `references/codex-controller-playbook.md`。
- 新增 Prompt Pack：仓库审计、Bug 修复、安全审计、前端打磨、测试生成、重构计划、发布检查。
- 新增压缩轮询、`cc_summarize_run`、`cc_compact_events`。
- 新增队列策略、模型能力库、benchmark 历史、本机偏好保留、worker 质量历史、失败模式识别。
- 新增时间线看板和每日检查 GitHub 更新的说明。

## v0.3.0 - 验收和安全运行

- 新增一键 `cc_verify_run`。
- 串起 diff 摘要、写入范围检查、密钥扫描、可选测试、Markdown 报告。
- 新增不消耗模型额度的 mock streaming 测试。
- 新增用量统计、升级检查、benchmark suite、MCP 自动注册。
- 新增 `version.json` 作为版本元数据来源。

## v0.2.0 - 实时 worker 控制

- 新增 `run-streaming` / `cc_run_streaming_agent`。
- Claude Code 使用 `--output-format stream-json --include-partial-messages` 启动。
- 新增 `poll-run`、`run-status`、`stop-run`。
- 新增角色团队、结果汇总、交叉审查、dashboard、报告导出、成本护栏、可视 worker 窗口。

## v0.1.0 - Skill、MCP、CLI、CCSwitch 基座

- 创建 Codex Skill 入口。
- 新增内置 MCP Server 和 CLI orchestrator。
- 新增 CCSwitch profile 发现和 Claude Code 二进制发现。
- 新增本机模型按角色评分和角色路由。
- 新增安全默认值、运行元数据、日志、`CLAUDE.md` 生成、UTF-8 输出处理、密钥脱敏。
