# ANO 0.5 Development Roadmap

状态：`0.5.0-alpha.4` 开发中  
基线：`ANO 0.4.0 Reference Release`

## 版本主题

0.5 的主题是“可部署的自生长分布式运行层”。系统必须把更强模型、技能、策略、编排和运行时组件统一视为候选能力包；模型能力可以非线性增长，但生产状态只能经确定性的签名、评测、批准、预算、灰度、证据和回滚协议改变。

## 阶段与完成门

### Alpha.1 — Persistent Evolution Kernel

- 签名 Capability Package 与来源/制品/目标契约绑定；
- 跨重启 Evolution Transaction；
- 密封评测、独立批准、权限与预算上限；
- 暂存不等于激活、并发升级 fencing、原子激活与回滚；
- 每组件演化哈希链和外部头验证。

完成门：攻击测试覆盖签名篡改、目标漂移、权限扩张、批准串谋、重启误激活、并发晋升和回滚基线损坏。

### Alpha.2 — Distributed State and Coordination

- 数据库无关事务适配器 v2；
- PostgreSQL 参考适配器及 SQLite/PostgreSQL 行为一致性；
- 数据库持久租约、leader fencing、outbox/inbox 和故障恢复；
- 网络分区、主节点切换与重复投递测试。

### Alpha.3 — External Trust Plane

- Cloud KMS/HSM provider contract 与远程 rewrap；
- OIDC/JWKS 与 SPIFFE 工作负载身份；
- 短期 Secret lease、用途绑定、撤销和泄漏检测；
- 制品签名、构建来源和 SBOM/证明策略。

### Alpha.4 — Federated Growth Operations

- 策略和能力包的签名分发与多节点一致视图；
- 自治预算分配、全局与租户级资源仲裁；
- 多节点 SLO、错误预算、自动降级与恢复；
- 学习来源撤回在节点和派生资产间的可验证传播。

### RC — Governed Self-Growing Cluster

- 一条命令执行能力发现、候选生成、隔离评测、双人批准、灰度、故障注入、推广或回滚；
- 模型替换不改控制平面；模型跃迁能提升端到端能力并输出 Architecture Leverage 证据；
- 五档累计一致性、0.4 兼容、0.5 机器验收和发布审计全部通过。

## 非主张

Alpha 阶段的参考实现不自动等价于云服务认证、多地域容灾、HSM 合规、真实组织 OIDC、供应链安全认证或无人监督自修改。每项能力只有在对应适配器和故障测试通过后才进入发布主张。
