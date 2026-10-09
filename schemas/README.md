# ANO Schemas

当前 Schema 使用 JSON Schema Draft 2020-12。

`v0.3.0` 是公开基线；`v0.4.0` 是增量工作草案，当前覆盖事务型多租户存储、租户审计和迁移导出。两个目录并存，0.4 不静默覆盖 0.3 实体。

## 标识符

Schema 使用稳定 URN：

```text
urn:ano:schema:<spec-version>:<schema-name>
```

例如：

```text
urn:ano:schema:0.3.0:action
```

0.4 增量示例：

```text
urn:ano:schema:0.4.0:tenant-state-object
```

URN 表示规范内的逻辑标识，不依赖任何尚未注册的公共域名。

## 兼容性

- 文件目录版本与规范版本一致；
- 同一版本内字段语义不得静默改变；
- Public Draft 阶段允许破坏性修改，但必须更新目录版本和迁移记录；
- 安全相关 Schema 默认 `additionalProperties: false`；
- 领域 Action 的 `parameters` 必须由该 Capability 自己的扩展 Schema 进一步约束。

## 验证

```powershell
.\.venv\Scripts\python tools\run_conformance.py --profile ANO-S
```

## Profile 覆盖

- `ANO-C`：Identity、Event、State、Model、Goal、Decision、Permission、Action、Observation、Verification；
- `ANO-P`：累计包含 `ANO-C`，并增加 Memory、Commitment 与 Schedule。
- `ANO-G`：累计包含 `ANO-P`，并增加 Policy、Risk Assessment、Approval、Delegation、Incident、Artifact、Deletion Request 与 Audit Record。
- `ANO-A`：累计包含 `ANO-G`，并增加 Reflection、Change Proposal、Skill Package、Evaluation Report、Model Advancement、Capability Graph、Learning Source 与 Model Leverage Metrics。
- `ANO-S`：累计包含 `ANO-A`，并增加 Sandbox Execution、Canary Deployment、Rollback Record、Structural Approval Evidence、Isolation Attestation、Canary Checkpoint、Telemetry Envelope/Cursor、Deployment Receipt 与 Traffic Route。
- `0.4.0`：在五档基线上增加事务多租户、外部身份、信封加密与密钥生命周期、迁移恢复、持久租约、配额、SLO 和机器发布审计；对应测试使用 `O-*` 标识。
- `0.5 Alpha.1`：增加签名 Capability Package、Persistent Evolution Transaction、独立批准、baseline fencing、原子激活/回滚和组件演化链；对应测试使用 `V-*` 标识。
- `0.5 Alpha.2`：增加事务 outbox/inbox、租户作用域 claim、worker epoch fencing、崩溃恢复和 dead-letter；对应测试使用 `D-*` 标识。
- `0.5 Alpha.3`：增加远程 KMS 契约、OIDC/JWKS、SPIFFE、短期 Secret lease 和签名制品来源/SBOM 门禁；对应测试使用 `T-*` 标识。
- `0.5 Alpha.4`：增加签名联邦视图、离线 epoch 补放、全局/租户预算仲裁、多节点 SLO 和学习撤回传播；对应测试使用 `F-*` 标识。
