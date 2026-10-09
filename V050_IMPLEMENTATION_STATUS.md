# ANO 0.5.0 Alpha.4 Implementation Status

## 当前结论

Alpha.4 在演化、分布式交付和外部信任平面之上增加联邦增长层：签名 policy/package 视图、独立节点 checkpoint、预算仲裁、多节点 SLO 与学习撤回传播。模型跃迁只能生成候选能力包，不拥有生产晋升权限。

Alpha.4 冻结回归共执行 151 项测试：150 通过、1 项条件跳过、0 失败。五个累计 Profile 全部 `conformant`；最高 `ANO-S` 要求 143 项，142 项通过，另 1 项为声明允许的条件测试。Evolution、Distributed、External Trust、Federation 四套专项验收分别为 11/11、11/11、13/13、15/15，Alpha 审计为 16/16。全部最终报告绑定同一实现源码摘要 `sha256:f0b7166a6cfeafbd189cddceb9ee8f0df2dd091b517cc443120b6b249aad5c4b`。

## 已实现

- Ed25519 签名且内容寻址的 Capability Package；
- 组件 generation、artifact/manifest、目标/评测器、权限、预算和来源模型绑定；
- SQLite WAL/FULL 持久 Evolution Transaction；
- `proposed → evaluated → approved → staged → active → rolled_back` 强制状态路径；
- 不同批准者阈值、目标漂移拒绝、权限和预算 ceiling；
- staged 重启不误激活、并发升级 baseline fencing；
- 激活指针与事务状态原子提交；
- 签名基线回滚和每组件可外部锚定演化哈希链；
- 模型 Advancement 到候选 Package 的无生产权限转换。
- 数据库无关 `DistributedOperationStoreAdapter` v2 协议；
- SQLite 事务操作/outbox 与幂等 inbox/effect；
- topic + tenant scope claim、单调 lease epoch 和旧 worker fencing；
- claim TTL、跨重启 requeue、不确定提交重放和 poison dead-letter；
- PostgreSQL JSONB/TIMESTAMPTZ/`FOR UPDATE SKIP LOCKED` 适配计划及诚实能力声明。
- `RemoteKmsProvider` 协议与用途/调用者/上下文绑定的 authenticated wrap/unwrap/rewrap；
- EdDSA OIDC/JWKS 轮换验证、跨重启 JTI 防重放、下游身份 proof 与 SPIFFE trust-domain 约束；
- 加密持久 Secret broker、secret 级 workload ACL、短期 lease、领取上限、撤销和 token fingerprint 泄漏处置；
- Ed25519 制品 provenance，绑定 artifact、SBOM、不可变 source commit、materials、invocation、隔离与可复现属性。
- 签名 federation bundle epoch 链、policy/package view hash、独立 failure-domain checkpoint 法定人数；
- 离线节点连续补放、同 epoch equivocation、policy rollback 和 package generation rollback 防护；
- policy hash 绑定的原子 global/tenant 预算预留与短期签名 node grant；
- 签名多节点 SLO、持久 safe-degrade、error-budget burn 和连续健康窗口恢复；
- policy-bound 学习撤回、逐节点签名覆盖收据、缺失资产检测和撤回后资产防复活。

## 当前边界

SQLite 已验证共享数据库的多进程协调，但不主张多主机。当前环境没有 PostgreSQL 驱动或服务，因此 PostgreSQL 仅完成 SQL/能力契约，`runtime_verified=false`。Alpha.3 未连接真实云 KMS/HSM、企业 OIDC、SPIRE 或独立构建/透明日志服务，`remote_transport_verified=false`、`hsm_backed=false`。Alpha.4 使用多个独立本地数据库证明联邦协议，但没有真实跨主机网络、共识或跨地域运行认证，`network_runtime_verified=false`。

## Open-source community preview

2026-10-09：补齐 Apache-2.0 许可、中英文入口、快速开始、贡献与治理、安全报告和社区任务。重新执行五档一致性、四套验收与 Alpha 审计；报告绑定当前源码摘要。GitHub CI 的实际执行结果以 Actions 页面为准。
