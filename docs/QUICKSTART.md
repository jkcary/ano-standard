# Run ANO in ten minutes / 十分钟快速开始

Requirements: Git, Python 3.10+, and network access to install Python dependencies. Run commands from the repository root. No paid account, LLM key, Docker or Kubernetes is needed for this example.

```sh
git clone https://github.com/jkcary/ano-standard.git
cd ano-standard
python -m venv .venv
```

Activate the environment on Linux/macOS:

```sh
source .venv/bin/activate
```

On Windows PowerShell, activation is optional: replace `python` below with `.\.venv\Scripts\python.exe`. No execution-policy change is needed.

```sh
python -m pip install -e .
python tools/run_quickstart.py
```

The quickstart starts a child process, persists a scheduled commitment and exits that child abruptly. A new service recovers the commitment and fires its due trigger. Another reload suppresses a duplicate trigger. An action without a permission grant is rejected; the commitment becomes blocked and cannot jump directly to completed.

Expected output includes:

```json
{
  "status": "passed",
  "child_exit_code": 23,
  "scheduled_commitment_recovered": true,
  "trigger_deliveries": 1,
  "ungranted_action_rejected": true,
  "blocked_state_recovered": true,
  "completion_without_verification_rejected": true,
  "final_state": "blocked",
  "external_side_effects": false
}
```

The blocked state is intentional: this demo grants no production permission and sends no message. It proves restart after a completed local write, not recovery from a torn write or power failure, and not exactly-once delivery to external systems. Temporary demo state is cleaned up automatically.

For a separate local demonstration of authorized action and result verification:

```sh
python tools/run_mvp_demo.py
```

This uses a simulated local tool, not a real customer workflow. Inspect `reports/mvp-demo-report.json` for the evidence and declared boundaries.

To execute the regression suite and evaluate the highest cumulative profile:

```sh
python tools/run_conformance.py --profile ANO-S
```

The suite starts local loopback services. Conditional skips are explained in its report; they are not production certification. Run from a clone with the schema, examples and state-machine directories present: the current package is a source-checkout reference runtime, not a standalone installed SDK.

## Integration boundary

An existing agent framework can propose actions while ANO holds commitment and permission state. Start with one explicit boundary: map a task to a commitment, evaluate authorization before the tool runs, and verify the result before completion. Framework-specific LangGraph and Temporal adapters are community tasks, not shipped integrations. See [community backlog](COMMUNITY_BACKLOG.md).

## 中文说明

这个示例会启动子进程保存承诺，然后在写入完成后异常退出；重新加载状态后继续调度，再次加载不会重复触发。没有授权的操作会被拒绝，任务保留为 blocked，不能直接伪报完成。示例不调用模型、不发送消息，不证明断电恢复或外部系统的 exactly-once。

Windows 不需要修改 PowerShell 执行策略，直接使用 `.\.venv\Scripts\python.exe` 执行安装和演示命令即可。完整中文技术说明见 [README.zh-CN.md](../README.zh-CN.md)。
