# Contributing to ANO

English and Chinese contributions are welcome. Start with the [quickstart](docs/QUICKSTART.md), then choose a task in the [community backlog](docs/COMMUNITY_BACKLOG.md). Bug reproductions, real-world use cases, translations and specification reviews are as valuable as code.

## Development

Use Python 3.10 or newer in a virtual environment, then run from the repository root:

```sh
python -m pip install -e .
python tools/run_quickstart.py
python tools/run_conformance.py --profile ANO-S
```

The conformance runner executes the complete suite and evaluates the selected cumulative profile. The current suite conditionally skips the physical/financial units profile because the reference runtime exposes neither action domain; skipped capabilities are not verified. Some tests start loopback servers and subprocesses. No model API key is required.

## Propose a change

1. Search existing issues. Open an issue before a large change, new dependency or specification change.
2. Describe the observed problem, expected behavior and a small reproducible example. Remove credentials and private data.
3. Fork the repository and create a focused branch. Keep unrelated refactors out of the pull request.
4. Add meaningful regression tests for changed behavior. New conformance tests need a unique `@conformance` ID and the appropriate profile manifest entries.
5. Explain what changed, why, how it was verified, and any limitations. Attach commands and summaries rather than machine-specific logs.

For normative changes, follow [governance](GOVERNANCE.md): document compatibility, migration and test implications in an RFC issue before implementation. Do not weaken assertions simply to make a test pass. Reports and reference implementations are not independent certification.

## AI-assisted contributions

AI-assisted work is welcome. The submitting contributor remains responsible for understanding the patch, verifying its behavior and checking provenance. Describe substantial AI assistance in the PR. Prefer small, reviewable changes; do not submit bulk generated code or unsupported claims of security, autonomy or performance.

## Review and participation

Maintainers review correctness, scope, compatibility and evidence. They may ask for changes or decline a proposal with a reason. There is no guaranteed response-time SLA. Repeated useful contributions can lead to maintainership under GOVERNANCE.md. Follow the [code of conduct](CODE_OF_CONDUCT.md).

Unless explicitly stated otherwise, contributions are submitted under this repository's Apache-2.0 license. Only contribute material you have the right to license. No separate CLA is currently required.

## 中文说明

欢迎中文 Issue、PR、案例和规范评审。先运行快速开始，再选择社区任务。较大改动先讨论；规范变更需要说明兼容性、迁移和测试。AI 辅助贡献需要由提交者理解并验证，不能用生成的测试结果代替实际运行。维护者重视真实复现、独立验证和可审查的小改动。
