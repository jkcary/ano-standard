# ANO 0.5.0-alpha.4 — Community preview

ANO is now being opened for developer collaboration: an engineering specification and Python reference runtime for long-running AI agents, with persistent commitments, permission boundaries, execution evidence and controlled capability updates.

## Start here

- [English overview](https://github.com/jkcary/ano-standard#readme)
- [中文说明](https://github.com/jkcary/ano-standard/blob/main/README.zh-CN.md)
- [No-API-key quickstart](https://github.com/jkcary/ano-standard/blob/main/docs/QUICKSTART.md)
- [Community tasks](https://github.com/jkcary/ano-standard/blob/main/docs/COMMUNITY_BACKLOG.md)

This community launch adds Apache-2.0 licensing for code and documents, bilingual entry points, an abrupt-process-exit recovery example, contribution and governance policies, security reporting guidance, issue/PR templates and a Windows/Linux CI matrix. The implementation remains 0.5.0-alpha.4; this is not a new production-stability claim.

## Local verification

At preparation time on Windows/Python 3.14, each of the five cumulative profile runs executed 151 tests: 150 passed, one conditionally skipped, zero failed. The skip is `C-UNIT-001`: the reference runtime exposes no physical or financial action profile.

Evolution, distributed, external-trust and federation acceptance demos passed 11/11, 11/11, 13/13 and 15/15 checks. The alpha release audit passed 16/16 checks. The new quickstart and the separate simulated action/evidence demo passed.

Reports bind to source digest `sha256:f0b7166a6cfeafbd189cddceb9ee8f0df2dd091b517cc443120b6b249aad5c4b`. See [Actions](https://github.com/jkcary/ano-standard/actions) for independently executed CI results and [report guidance](https://github.com/jkcary/ano-standard/blob/main/reports/README.md) for reproduction.

## Boundaries

This is an experimental reference implementation and open specification draft. It is not a production platform, established industry standard, independent security certification or proof of autonomous self-improvement. Real PostgreSQL, cloud KMS/HSM and multi-host federation remain unverified where declared. The quickstart demonstrates restart after a completed local write, not power-loss recovery or exactly-once external effects. No model API calls or external messages are made by the quickstart.

## Join us

Help with real-world failure reports, integration examples, English specification review, storage adapters or independent implementations. Start small, discuss normative changes in an RFC, and include reproducible evidence. Chinese and English contributions are welcome.

中文：欢迎共同建设 ANO。本次开源补齐许可、双语入口、快速开始、贡献治理与自动化检查。当前仍为实验性参考实现，欢迎真实接入、故障复现和独立验证，不以测试通过替代生产认证。
