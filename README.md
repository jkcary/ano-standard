# ANO Standard

AI Native Organism（ANO）长期智能系统的开放工程规范与可执行一致性包。

当前实现：`0.5.0-alpha.4`。稳定基线为 `0.4.0 Reference Release`，持久自生长、分布式交付、外部信任与联邦增长增量位于 `0.5 Working Draft`。

## 当前交付范围

本仓库已实现从 `ANO-C`（Core）到 `ANO-S`（Self-Modifying）的累计垂直切片：

- JSON Schema Draft 2020-12 核心实体；
- 语言无关状态机定义；
- Python 最小参考运行时；
- 一致性测试和机器可读报告；
- 可验证示例数据。
- 持久记忆、冲突与删除投影；
- 一级承诺实体、跨重启恢复与违约预警；
- 幂等时间触发、公平调度、背压与递归/扇出边界。
- 确定性策略层级、组织风险矩阵、知情确认与职责分离；
- 委托作用域、撤权传播、聚合成本熔断与模型升级不提权；
- 哈希链审计、数据导出/删除传播、事件响应、制品门禁与租约 Fencing。
- Reflection 候选隔离、学习来源/派生资产谱系和敏感学习授权；
- 密封评测、策略回归门禁、技能完整生命周期和签名基线回滚；
- 模型能力发现、Capability Graph、候选编排与 Architecture Leverage 指标。
- L5 结构变更的提案/审批分离与受保护评测资产；
- 受限能力封套、五维灰度范围、显式权限批准和遥测门禁；
- 安全、性能或成本退化时恢复经摘要验证的基线。
- 受信隔离证明门禁与摘要固定的 Docker 沙箱后端；
- 签名批准证据、持久化遥测哈希链和崩溃后自动恢复。
- Ed25519 公钥批准、远程遥测防重放游标和外部控制面补偿；
- 显式集群上下文、摘要固定镜像和默认 dry-run 的 Kubernetes 适配器；
- 一次性 Kind + Calico 隔离集群中的网络阻断、Pod 自愈、回滚与清理实证；
- DSSE 风格独立见证签名、见证收据链和可外部锚定的追加式证据账本；
- 私钥隔离的外部见证服务、认证客户端、幂等签发和跨服务重启恢复；
- 强制客户端证书的 mTLS 传输，以及带完整性锚定的见证密钥轮换、退役和撤销策略。
- 按独立信任域计数的多见证法定人数、成员独立链头和多密钥历史归档。
- 来源签名、观察者直接拉取和聚合器复验组成的独立观察谱系。
- 来源控制域/基础设施域/上游根去重，以及持久化来源双签名取证。
- 事务型 SQLite 多租户状态层：外部签名身份、乐观并发、幂等收据、原子审计链和删除墓碑；
- 每租户 envelope encryption、KMS/DEK 双层轮换、AAD 防密文替换和密码学删除；
- 加密迁移与空目标原子导入、在线备份恢复、可替换存储协议和能力声明；
- 持久租约与 fencing、租户资源配额、SLO 时间窗评估和 0.4 端到端生产内核验收。
- 签名 Capability Package、跨重启 Evolution Transaction、独立批准、并发升级 fencing 与原子回滚。
- 事务 outbox/inbox、显式租户 claim、worker epoch fencing、崩溃重领和 poison dead-letter。
- 用途绑定 KMS wrap/rewrap、EdDSA OIDC/JWKS 与 SPIFFE 工作负载身份验证、持久 JTI 防重放和下游 verifier proof。
- 短期 Secret lease、持久撤销/泄漏检测，以及绑定 SBOM/来源/materials 的签名制品证明。
- 签名 policy/package 联邦 epoch 链、独立节点一致视图和离线连续补放。
- policy-bound 全局/租户预算仲裁、签名多节点 SLO 降级恢复和学习撤回覆盖证明。

## 目录

```text
ano-standard/
├── spec/                       # 规范正文
├── schemas/v0.3.0/             # JSON Schema 2020-12
├── schemas/v0.4.0/             # 0.4 增量生产运行 Schema
├── state-machines/v0.3.0/      # 语言无关状态机
├── reference/python/           # Python 最小参考运行时
├── examples/v0.3.0/            # 有效实体示例
├── tests/                      # Schema 与行为一致性测试
├── tools/                      # 一致性报告工具
└── reports/                    # 生成的机器可读报告
```

## 快速开始

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e .
.\.venv\Scripts\python tools\run_conformance.py --profile ANO-C
.\.venv\Scripts\python tools\run_conformance.py --profile ANO-P
.\.venv\Scripts\python tools\run_conformance.py --profile ANO-G
.\.venv\Scripts\python tools\run_conformance.py --profile ANO-A
.\.venv\Scripts\python tools\run_conformance.py --profile ANO-S
.\.venv\Scripts\python tools\run_v040_storage_demo.py
.\.venv\Scripts\python tools\run_v040_rc_demo.py
.\.venv\Scripts\python tools\audit_v040_release.py
.\.venv\Scripts\python tools\run_v050_evolution_demo.py
.\.venv\Scripts\python tools\run_v050_distributed_demo.py
.\.venv\Scripts\python tools\run_v050_external_trust_demo.py
.\.venv\Scripts\python tools\run_v050_federation_demo.py
.\.venv\Scripts\python tools\audit_v050_alpha.py
```

成功时，分档报告生成到 `reports/conformance-report-ano-c.json`、
`reports/conformance-report-ano-p.json`、`reports/conformance-report-ano-g.json`、
`reports/conformance-report-ano-a.json` 与 `reports/conformance-report-ano-s.json`；
`reports/conformance-report.json` 指向最近一次运行结果。

本机安装 Docker、kubectl 与 kind 后，可复现实验并自动销毁临时集群：

```powershell
.\tools\run_ephemeral_cluster_lab.ps1
```

机器可读实验结果写入 `reports/cluster-validation-report.json`。脚本固定 Kubernetes 节点镜像、Calico 版本与清单摘要，并在 `finally` 中删除 `ano-alpha8` 集群。

Alpha.9 将见证端和归档端拆成不同密钥边界。见证端持有 Ed25519 私钥，归档端只配置固定公钥：

```powershell
.\.venv\Scripts\python tools\witness_cluster_report.py --help
.\.venv\Scripts\python tools\archive_cluster_evidence.py --help
.\.venv\Scripts\python tools\run_witness_service.py --help
.\.venv\Scripts\python tools\request_cluster_witness.py --help
```

见证信封绑定报告摘要、消息类型、执行域、见证域、时间、序号和前驱信封；归档账本同时维护独立记录哈希链，并可用外部保存的 `expected-head` 检测整段尾部回滚。

Alpha.10 的服务端固定信任域并独占私钥，保存全部已签发运行绑定。同一报告的网络重试返回原信封；相同 `run_id` 换内容、未认证请求、状态篡改或重启后链不连续都会失败关闭。

Alpha.11 支持 TLS 1.2+ 双向认证：非 loopback 监听若未配置服务端证书、私钥和客户端 CA 会拒绝启动，客户端同时验证服务端证书链/主机名并提交受信客户端证书。见证签名仍由独立 Ed25519 密钥完成，TLS 成功不能替代证据验签。

`witness-trust-policy` 将 key ID 绑定到见证域、公钥指纹、有效期、状态和撤销模式。验证器要求预置策略 ID、最低版本和 canonical JSON 摘要，因而拒绝策略回滚或静默篡改；退役密钥只验证有效期内的历史证据，前向撤销保留撤销前证据，追溯撤销使该密钥的全部证据失效。

Alpha.12 新增 `witness-quorum-policy` 和 `cluster-evidence-quorum-bundle`。阈值按唯一成员与唯一信任域计算，同一成员的多把轮换密钥不能重复计票；策略固定阈值、必需成员、最大见证时间差和最大聚合延迟。`QuorumEvidenceLedger` 分别推进每个成员的见证链，并由独立的全局记录链和外部头摘要检测归档篡改或截断。多密钥归档入口为：

```powershell
.\.venv\Scripts\python tools\archive_quorum_evidence.py --help
```

Alpha.13 将报告输入改为独立采集：只读来源先对报告摘要、运行标识、来源 ID、来源域和签发时间进行 DSSE 风格签名；观察者从预配置 URL 主动拉取，验证来源策略、密钥生命周期与签名后，再签署来源信封摘要和采集时间。聚合器会重新验证两层签名，并同时要求观察者域和来源域互不重复：

```powershell
.\.venv\Scripts\python tools\run_report_source_service.py --help
.\.venv\Scripts\python tools\observe_cluster_report.py --help
```

Alpha.14 不再把“不同 URL”直接当作独立来源。来源策略还绑定 operator domain、infrastructure failure domain 和 upstream evidence roots；任一维度重叠都不能共同构成法定人数。同一来源为相同 `run_id` 签署不同报告摘要时，`SourceObservationRegistry` 会先把两份报告、两份来源信封和冲突关系写入 `fsync` 哈希链，再返回 equivocation 错误：

```powershell
.\.venv\Scripts\python tools\register_source_observation.py --help
```

Alpha.15 为来源注册表增加策略绑定的 Ed25519 签名 checkpoint。观察者保存已接受头部，并要求新 checkpoint 携带从旧序号开始的完整哈希链扩展；旧序号回放、同序号不同头部和断裂/伪造扩展都会 fail closed。两个被日志合法签名但互相冲突的 checkpoint 一旦 gossip 汇合，即产生可验证的 split-view 证据：

```powershell
.\.venv\Scripts\python tools\issue_source_checkpoint.py --help
.\.venv\Scripts\python tools\gossip_source_checkpoint.py --help
```

RC.1 将上述能力收敛为 MVP 验收闭环。端到端命令会实际执行受治理行动、生成反思候选、把模型能力跃升映射为候选编排、发布来源签名 checkpoint、验证连续增长并拒绝回滚；随后发布审计检查五档报告、版本、Schema 目录和机器报告是否一致：

```powershell
.\.venv\Scripts\python tools\run_mvp_demo.py
.\.venv\Scripts\python tools\audit_mvp_release.py
```

MVP 的完成边界和明确不包含项见 `MVP_RELEASE.md`。

0.4 的事务存储演示生成 `reports/v040-storage-acceptance.json`；生产内核验收生成 `reports/v040-production-kernel.json`；最终发布审计生成 `reports/v040-release-audit.json`。当前完成状态见 `V040_IMPLEMENTATION_STATUS.md`。

## 设计边界

- 模型负责概率性认知；运行时负责确定性状态和副作用控制；
- 参考实现用于证明契约可落地，不是生产平台；
- 生产实现可以使用任何语言、数据库、模型或云平台；
- 通过参考实现测试不等于安全、法律或行业合规认证。
- Alpha 删除实现保证活动投影擦除并跟踪六类副本的传播状态与例外；它不执行真实存储介质、外部备份或第三方系统的物理清除与加密销毁；
- Alpha 哈希链只能检测记录篡改，不等价于 WORM、可信时间戳或硬件根信任；
- 示例 `signature.verified` 是生产签名验证器的接口契约，不是示例实现提供了密码学验证；
- 单进程 Lease/Fencing 证明状态语义，不等价于通过多节点共识和网络分区认证。
- Alpha 密封评测证明摘要绑定和候选接口隔离；同进程 Python 参考实现不等价于生产级保密计算、独立评测服务或不可访问的留出集；
- Architecture Leverage Ratio 是版本化观测指标，不自动证明因果关系或未来指数增长。
- `StructuralSandbox` 仍只是同进程能力封套；Alpha.6 新增的 `DockerSandboxBackend` 提供容器执行参数，但只有在外部受信方正确验证宿主、镜像和运行时并签发隔离证明后，才能视为生产隔离链的一部分；
- Alpha.6 使用 HMAC 验证审批服务和隔离证明的来源完整性；共享密钥不等价于公钥签名、硬件密钥保护或法律意义上的不可抵赖性；
- `CanaryJournal` 提供单进程 JSONL、`fsync` 和哈希链恢复语义，不等价于跨节点共识、WORM 存储或远程遥测平台；
- Alpha.8 已在一次性 Kind v0.33.0 / Kubernetes v1.34.3 / Calico v3.31.6 集群执行真实验证；这是本机可复现实验，不等价于生产集群认证、独立渗透测试或多节点/网络分区证明；
- Alpha.9 的见证时间是受信见证方签名时间，不等价于 RFC 3161 时间戳机构或透明日志的独立时间证明；
- `WitnessedEvidenceLedger` 是带 `fsync`、写入锁、双重哈希链和外部头锚定检查的参考账本；没有对象锁、透明日志或外部锚点时仍不能声称真正 WORM；
- Alpha.11 保留仅限 loopback 的 HTTP 回归模式，并用真实 TLS 子进程验证双向证书认证；尚未完成真实跨主机部署、服务发现、限流或网络级抗拒绝服务测试；
- 观察窗口通过不会自动把外部流量提升到 100%；全量发布仍需要新的全范围批准协议；
- NetworkPolicy 是否真正生效仍取决于集群 CNI；Alpha.8 的通过结论只绑定报告所列 Calico 版本与清单摘要，不能外推到未测试 CNI；
- Ed25519 公钥与策略摘要仍是预置配置；参考密钥生命周期策略不等价于 KMS/HSM 托管、在线撤销分发、组织身份认证或签名策略管理平面；
- Alpha.13 已证明多个观察进程分别从不同签名来源主动拉取并形成一致报告；参考来源仍是静态只读测试服务，不等价于三套真实 Kubernetes 审计日志、独立云控制面、物理传感器或拜占庭事实共识；
- Alpha.15 的 operator、infrastructure 和 upstream 独立性仍是受锚定策略声明，尚未由组织证书、云账户证明或远程证明自动核验；签名 checkpoint 与 gossip 能在视图汇合时检出 split-view，但参考实现不是高可用全局透明日志，监视器状态仍需独立外部锚定；
- `ANO-S` 自符合性仅证明协议路径可执行，不授权无人监管的生产自修改。
- 0.4 的 SQLite WAL 后端用于证明事务、租户隔离、加密迁移和恢复语义，不等价于 PostgreSQL、多节点共识、跨地域高可用或云数据库生产认证；参考 KMS/IdP 也不等价于 HSM、OIDC 或 SPIFFE 部署。
- Alpha.3 的 KMS、OIDC/JWKS 和 SPIFFE 组件是协议参考与攻击测试工具；`remote_transport_verified=false`、`hsm_backed=false`，不等价于真实云 KMS/HSM、企业 IdP、SPIRE 或独立供应链认证。
- Alpha.4 的多个节点使用独立 SQLite 数据库验证签名历史和一致视图；`network_runtime_verified=false`，不等价于跨主机传输、共识、跨地域预算仲裁或长期可用性认证。

## 版本关系

- 基线规范：`spec/ANO_Specification_v0.3_Public_Draft.md`
- 增量规范：`spec/ANO_Specification_v0.4_Working_Draft.md`
- Schema：`schemas/v0.3.0/` + `schemas/v0.4.0/`
- 状态机：`state-machines/v0.3.0/`
- 一致性套件：`0.5.0-alpha.4`
