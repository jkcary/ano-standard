# AI Native Organism Engineering Specification v0.5 — Working Draft

状态：`0.5.0-alpha.4` 实现驱动草案  
兼容基线：`ANO 0.4.0 Reference Release`  
日期：2026-09-01

## 1. 架构目标

0.5 把 ANO 的自生长从内存候选对象提升为持久、签名、可并发、可恢复的演化事务。模型、技能、策略、编排、工具和运行时模块使用同一种 Capability Package 进入控制平面。控制平面不解释模型输出的“可信度”，只验证可机器判定的来源、摘要、目标契约、权限、预算、评测、批准、状态和证据。

## 2. Alpha.1 新增不变量

| ID | 不变量 |
|---|---|
| `INV-045` | 任何可进入生产的能力必须由受信发布者签名，且签名绑定完整 package 内容。 |
| `INV-046` | Package 必须绑定制品摘要、组件、单调 generation、目标/评测器摘要、权限集合、预算上限和来源模型；模型输出本身不是批准证据。 |
| `INV-047` | 权限和预算不能因模型、技能或结构升级而越过组件配置的确定性 ceiling。 |
| `INV-048` | 评测结果必须绑定与 package 相同的目标和评测器摘要；候选不得通过改变成功定义晋升。 |
| `INV-049` | 高影响演化必须由达到阈值的不同批准者授权；重复批准者不得重复计票。 |
| `INV-050` | `staged` 不等于 `active`；进程重启不得把未完成事务自动提升到生产。 |
| `INV-051` | 激活必须比较预期 active package；两个竞争事务最多一个可提交，失败者必须被 fencing。 |
| `INV-052` | 激活和 active pointer 更新必须原子；崩溃不得产生“事务已激活但组件仍旧”或反向状态。 |
| `INV-053` | 回滚只能恢复已签名、摘要仍有效的基线 package，并形成新的演化事件。 |
| `INV-054` | 每个组件具有独立连续的演化哈希链，并可用外部保存的头摘要发现尾部截断。 |
| `INV-055` | 更强模型只能提高候选产生和评测后的可用能力；它不能缩短状态机、降低批准阈值或扩大权限/预算。 |

## 3. Capability Package

Package 是不可变发布单元，至少包含：package ID、组件 ID、generation、kind、artifact hash、manifest hash、能力列表、权限列表、预算上限、source adapter/model、证据 ID、goal contract hash、evaluator hash、回滚 package、发布者、key ID、创建时间和 Ed25519 签名。

同一组件的 generation 必须单调；相同 package ID 换内容、签名篡改、未知发布者或未知 key 必须拒绝。注册 package 不产生生产副作用。

## 4. Evolution Transaction

状态路径为：

```text
proposed → evaluated → approved → staged → active → rolled_back
            └──────── rejected
```

每个状态变化必须持久化并产生哈希链事件。评测失败进入 `rejected`。批准必须在评测通过之后；暂存必须在批准阈值满足之后；激活必须验证 active baseline 未变化。恢复 API 只能列出未完成事务，由明确调用继续，不得猜测式晋升。

## 5. 与模型跃迁的关系

Model Advancement Manager 可以生成 `kind=model` 或 `kind=orchestration` 的候选 package，但只能获得 `registered/proposed` 状态。无论基础模型提升幅度多大，都必须通过同一 Evolution Transaction。Architecture Leverage 用于衡量架构吸收模型跃迁的倍率，不是绕过治理的授权信号。

## 6. Alpha.1 一致性要求

| 测试 ID | 要求 |
|---|---|
| `V-SCH-001` | v0.5 Schema 目录完整并符合 Draft 2020-12。 |
| `V-PKG-001` | 签名、内容、generation、权限和预算绑定不可伪造。 |
| `V-EVO-001` | 评测、批准、暂存和激活顺序强制执行。 |
| `V-REC-001` | 重启恢复不会自动激活 staged 事务。 |
| `V-INT-001` | 当前事务投影必须在读取时重新绑定签名 package 和最近演化事件。 |
| `V-FEN-001` | 并发升级由 active baseline fencing 保证最多一个提交。 |
| `V-RBK-001` | 回滚验证基线完整性并保持演化链连续。 |
| `V-MOD-001` | 模型跃迁只能生成候选 package，不能自动提权或晋升。 |

## 7. Alpha.2 分布式交付不变量

| ID | 不变量 |
|---|---|
| `INV-056` | 领域操作和其 outbox 消息必须在同一数据库事务中提交或回滚。 |
| `INV-057` | operation ID 必须绑定规范请求；同请求重放返回原消息，换内容复用必须拒绝。 |
| `INV-058` | worker claim 必须同时绑定节点、租约 epoch、期限、topic 和显式 tenant scope。 |
| `INV-059` | 新租约 epoch 必须 fencing 旧节点；网络分区恢复后的旧节点不得确认消息。 |
| `INV-060` | 过期 claim 必须可重领；崩溃或重启不得丢失 pending/claimed 消息。 |
| `INV-061` | inbox 收据、数据库副作用和 delivered 状态必须原子提交；不确定提交重试返回原收据。 |
| `INV-062` | 重试次数必须有界，达到上限的 poison message 进入 dead letter，不阻塞后续消息。 |
| `INV-063` | 适配器必须逐项声明 runtime verification、multi-process、multi-host 和 claim 算法；SQL 计划不等于运行认证。 |

SQLite 参考适配器以 `BEGIN IMMEDIATE` 串行化 claim，支持共享数据库的多进程 worker，但不主张多主机。PostgreSQL 计划规定 JSONB、TIMESTAMPTZ、事务 outbox/inbox 和 `FOR UPDATE SKIP LOCKED`；在真实 PostgreSQL 驱动与服务测试前，其 `runtime_verified` 和 `multi_host` 必须为 false。

## 8. Alpha.2 一致性要求

| 测试 ID | 要求 |
|---|---|
| `D-ADP-001` | 分布式适配器协议和能力声明真实。 |
| `D-TXO-001` | 领域状态与 outbox 原子提交，操作重放不生成新消息。 |
| `D-INB-001` | inbox、数据库 effect 和 delivered 状态 exactly-once。 |
| `D-TEN-001` | claim 缺少显式 tenant scope 时拒绝。 |
| `D-FEN-001` | 新 epoch fencing 分区旧 worker，并可重领其过期消息。 |
| `D-REC-001` | 重启恢复过期 claim 且不丢消息。 |
| `D-DLQ-001` | poison message 在有界尝试后进入 dead letter。 |
| `D-CON-001` | 两个并发 claimer 对同一消息最多一个获得 claim。 |
| `D-PGC-001` | PostgreSQL 计划使用 SKIP LOCKED，并明确保持未运行认证状态。 |
| `D-E2E-001` | 一条命令生成 Schema 有效的分布式交付验收报告。 |

## 9. Alpha.3 外部信任平面不变量

| ID | 不变量 |
|---|---|
| `INV-064` | KMS 操作必须绑定 provider、不可变 key resource、版本、调用者、用途和加密上下文；成功解密不能替代调用者授权。 |
| `INV-065` | 远程 rewrap 必须验证旧 envelope 后生成新 envelope，并以收据绑定旧/新摘要、版本、用途和上下文；业务 DEK 不得写入收据。 |
| `INV-066` | KMS 适配器必须分别声明协议运行验证、远程传输验证和 HSM backing；本地模拟器不得声明云或硬件认证。 |
| `INV-067` | OIDC/JWKS 身份只接受固定算法、issuer、audience、有效期和当前受信 key；未知 key 必须在显式 JWKS 刷新前失败关闭，JTI 消费状态必须可跨重启保持。 |
| `INV-068` | SPIFFE 身份必须验证 JWT-SVID 签名并约束 trust domain；选择器和 subject 必须成为后续授权输入而不是未验证标签。 |
| `INV-069` | Secret lease 必须先通过 secret 级 subject/audience ACL，再绑定短期、最小用途、subject、audience、到期时间和领取次数；撤销、到期、耗尽或泄漏后不得继续读取。 |
| `INV-070` | 验证后的身份对象必须携带下游可验证的 verifier proof；泄漏检测不得持久化明文 token，持久 token fingerprint 必须使重启后的 broker 继续拒绝泄漏 lease。 |
| `INV-071` | 生产候选制品必须由受信 builder 签名，并绑定制品摘要、SBOM、不可变 source commit、materials、invocation、隔离和可复现属性。 |

Alpha.3 参考 KMS 把主密钥留在 provider 边界内并实现 authenticated wrap/unwrap/rewrap、调用者与用途授权。该实现用于证明适配器契约；`remote_transport_verified=false` 且 `hsm_backed=false`。

工作负载身份参考路径使用 Ed25519 JWKS，支持 OIDC-like token 和 SPIFFE JWT-SVID Profile。验证器拒绝算法降级、签名篡改、issuer/audience 替换、超长或过期 token、跨重启 JTI 重放、旧 JWKS 与跨 trust-domain subject；输出身份带 verifier Ed25519 proof，Secret broker 在授权前重新验证该 proof，拒绝调用者篡改 subject 或 selector。

Secret broker 只持久化加密材料和 lease token 的 SHA-256 fingerprint。供应链门禁验证 builder key、制品/SBOM 摘要、允许的 source URI、40–64 位不可变 commit、唯一 materials、隔离构建和可复现声明。参考签名与策略验证不等价于第三方供应链认证。

## 10. Alpha.3 一致性要求

| 测试 ID | 要求 |
|---|---|
| `T-KMS-001` | KMS provider 契约明确区分本地协议验证、远程传输和 HSM backing。 |
| `T-KMS-002` | 调用者、用途、上下文或密文替换必须失败关闭。 |
| `T-KMS-003` | rewrap 保持 DEK，收据绑定旧/新 envelope 与主密钥版本。 |
| `T-OIDC-001` | OIDC/JWKS 验证拒绝重放、算法降级和未刷新的轮换 key。 |
| `T-SPIFFE-001` | SPIFFE subject 与 selector 受签名及 trust domain 约束。 |
| `T-SEC-001` | Secret lease 受短期、用途、audience、subject 和领取次数约束。 |
| `T-SEC-002` | 显式撤销和泄漏报告跨 broker 重启持续生效。 |
| `T-SUP-001` | 签名 provenance 绑定制品、SBOM、source、builder、materials 和 invocation。 |
| `T-SUP-002` | 制品/SBOM 替换、可变 source 和弱构建必须拒绝。 |
| `T-E2E-001` | 一条命令生成 Schema 有效的外部信任验收报告。 |

## 11. Alpha.4 联邦增长不变量

| ID | 不变量 |
|---|---|
| `INV-072` | 联邦策略和 Capability Package 活跃视图必须包含于签名 bundle；bundle epoch 单调且绑定前一 bundle hash。 |
| `INV-073` | 节点只接受连续历史；同 epoch 不同 bundle、同 policy version 换内容、同 component generation 换 package 或 generation 回退必须拒绝。 |
| `INV-074` | 离线节点必须依序验证全部缺失 epoch 后才能加入当前视图；跳过历史不能由最新快照掩盖。 |
| `INV-075` | 一致视图必须由达到阈值、节点和 failure domain 均独立的签名 checkpoint 证明，并满足外部锚定的最低可信 epoch；不同 view hash 不得合并，旧 checkpoint quorum 不得被重放为当前视图。 |
| `INV-076` | 全局与租户预算必须在同一原子仲裁器中预留；并发请求不得使任一层超配，request ID 重放只能返回原授权。 |
| `INV-077` | Budget grant 必须签名并绑定当前 policy hash、authority、node、tenant、维度和期限；不得跨节点或租户转用。 |
| `INV-078` | 多节点 SLO 只接受受信节点签名、独立 failure domain、相同 tenant/service/window 且单调 sequence 的报告；目标必须来自当前签名 policy。 |
| `INV-079` | SLO 证据缺少法定人数时必须持久进入 safe-degraded；恢复必须经过 policy 规定数量的连续新健康窗口，不能重放旧窗口。 |
| `INV-080` | 学习来源撤回必须签名并绑定 federation/policy hash、source version、必需节点和预期派生资产；每个节点返回签名覆盖收据。 |
| `INV-081` | 撤回后新注册的同源资产必须立即 invalidated；缺失节点/资产、伪造收据、版本倒退或同版本冲突不能形成完成证明。 |

联邦 release bundle 是完整签名视图，不是节点间“最后写入获胜”的配置消息。节点分别持久保存 bundle 链；checkpoint reconciler 按唯一节点和唯一 failure domain 计数，只在 epoch、bundle hash 和 view hash 完全一致时输出一致视图。

预算 authority 从同一 policy hash 派生 global/tenant ceiling，以 `BEGIN IMMEDIATE` 串行化并发预留并签发短期 node/tenant grant。多节点 SLO controller 使用 policy 内密封目标计算 error-budget burn；缺失或不可信观测只能触发/保持降级，不能作为健康证据。

学习撤回事件显式列出每个必需节点的资产覆盖集合。节点会使该 source 的全部本地资产失效并签名 receipt；reconciler 要求所有必需节点无 unresolved asset。节点已记录撤回后，迟到的同源资产注册即处于 `invalidated`，避免派生资产复活。

## 12. Alpha.4 一致性要求

| 测试 ID | 要求 |
|---|---|
| `F-POL-001` | 签名 policy/package view 可由独立节点 checkpoint 形成一致法定人数。 |
| `F-VIEW-001` | epoch 冲突、历史缺口、策略静默改写、package generation 冲突和分裂视图失败关闭。 |
| `F-OFF-001` | 离线节点必须补放所有连续 epoch。 |
| `F-BUD-001` | 预算授权幂等并强制 global/tenant/policy/node 绑定。 |
| `F-BUD-002` | 并发租户不能超额预留全局容量。 |
| `F-SLO-001` | 签名多节点 error budget 触发降级，并经连续健康窗口恢复。 |
| `F-SLO-002` | 缺失、伪造、序号重放或窗口重放不能触发正常模式。 |
| `F-LRN-001` | 签名来源撤回在所有必需节点失效预期资产。 |
| `F-LRN-002` | 不完整、伪造、倒序撤回及撤回后资产复活失败关闭。 |
| `F-E2E-001` | 一条命令生成 Schema 有效的联邦增长验收报告。 |

## 13. 当前边界

Alpha.2 已证明 SQLite 共享数据库多进程交付协议；本机没有 PostgreSQL 驱动或服务，因此不声称 PostgreSQL runtime、多主机、网络分区数据库一致性或 failover 已认证。Alpha.3 已证明远程 KMS 契约、OIDC/JWKS 与 SPIFFE 验证语义、持久 Secret lease 以及签名制品来源策略；它没有连接真实云 KMS/HSM、企业 IdP、SPIRE Server、透明日志或独立构建服务。Alpha.4 使用多个独立 SQLite 节点数据库证明签名分发、离线补放、预算/SLO 和撤回覆盖协议，但未运行真实跨主机传输、拜占庭共识、跨地域仲裁或长期容量测试，`network_runtime_verified=false`。
