# First community tasks

Pick a task and open an issue before starting so work is not duplicated. These are invitations, not claims of implemented integrations. English and Chinese are welcome.

| Task | Scope | Acceptance criteria |
|---|---|---|
| Quickstart usability review | Good first contribution | Run from a fresh clone; report OS/Python and every confusing step; propose a focused doc patch. |
| English core-spec glossary | Documentation | Translate identity, goal, commitment, action, evidence and permission terms; link each definition to the Chinese source; flag ambiguities. |
| Restart failure reproduction | Testing | Provide a deterministic reproduction of a restart/replay edge case, expected invariant and a regression test if a defect exists. |
| LangGraph integration example | Integration | RFC first; persist one commitment, demonstrate approval and result verification; document which guarantees belong to each layer. |
| Temporal integration design | Integration | Map retry/idempotency ownership and commitment lifecycle; identify duplicate-effect risks; provide a minimal executable example after RFC acceptance. |
| PostgreSQL adapter | Advanced | Implement the existing storage contract; test concurrency, stale-worker fencing and crash recovery against a real PostgreSQL instance; do not claim multi-region consensus. |
| Independent schema implementation | Interoperability | Validate representative examples and invalid cases in a second language; publish incompatibilities and reproducible commands. |
| Real-world pilot report | Research | Run a bounded workflow with anonymized inputs; report completion rate, manual interventions and cost with/without ANO; include failures and limits. |

Priorities for the first community phase: successful external runs, one real integration, reproducible failure reports and independent review. Stars and generated code volume are not acceptance criteria.

中文：欢迎快速开始体验反馈、术语翻译、重启故障复现、框架接入、真实 PostgreSQL 后端、第二语言验证和真实场景报告。较大工作请先开 Issue/RFC，避免重复或未经讨论的接口变更。
