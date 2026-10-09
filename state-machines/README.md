# ANO State Machines

状态机以语言无关 JSON 表示，并由 `state-machine.schema.json` 验证。

每个 Transition 由以下四部分组成：

```text
from + event + guards → to
```

`guards` 是规范性前置条件名称。实现可以采用任意语言和规则引擎，但不得在缺少 Guard 时执行状态转移。

状态机定义禁止：

- 未声明状态；
- 同一 `from + event` 对应多个目标；
- 从终态继续转换；
- 用自然语言自由判断代替强制 Guard。

当前定义覆盖 Identity、Goal、Action、Memory、Commitment、Approval、Incident、Deletion、Skill、Change Proposal、Model Advancement 与 Canary Deployment。Commitment 明确区分
`executed`、`verified` 和 `completed`，禁止把“动作已调用”虚报为“承诺已履行”。

Approval 的批准需要参数不变、未过期、角色齐备和职责分离；Incident 与 Deletion
状态机禁止跳过证据保全、恢复验证或删除例外报告。

Skill、Change Proposal 与 Model Advancement 必须依次经过隔离、评测、审批、受限发布和监控；
回归时只能恢复完整性摘要仍匹配的基线版本。

Canary Deployment 必须从独立审批、完整五维范围和已演练回滚开始；只有遥测护栏通过且观察窗口完成后才能提升，退化时恢复并验证基线。
