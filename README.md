# 请求策略执行引擎

这是一个可嵌入 Go 业务进程的请求准入计算库，不包含角色、用户、后台或外部依赖。

## 判定语义

- 规则按 `Priority` 降序执行；同优先级按提交批处理中的公开顺序升序执行。
- 引擎从排序后的规则中选择第一个条件明确成立的规则，其 `Effect` 就是最终决策。
- 没有任何规则命中时默认拒绝。
- 缺失属性是“未知”，不是假，更不是满足；`NOT 未知` 仍为未知。
- `all` 中出现未知且没有明确失败时整体未知；`any` 中出现未知且没有明确成功时整体未知。
- `ref` 只复用另一条规则的条件，不继承该规则的 `Effect`。
- 证据只包含实际产生决策的那一条规则及命中条件说明，不罗列全部规则。

### 多个独立规则组

规则可通过 `Rule.Group` 分配到独立规则组（`NewEngineWithGroups`、`CompileRuleGroups`、`PublishRuleGroups`）。未填写组名的规则进入 `default` 组。组之间按 `RuleGroup.Priority` 降序裁决，同优先级按提交批处理的公开顺序。

每个组先独立得出一种结论：`allow`、`deny`、`unknown`（必要属性缺失等）或“无结论”。最终裁决规则：

- 优先级最高的明确裁决组若为 `deny`，最终拒绝；任何其他组的未知都不能掩盖这条明确拒绝依据。
- 明确 `allow` 只有在没有更高优先级未知组时才生效；未知永远不会被统一当作允许。
- 没有任何明确裁决时默认拒绝，`Decision.Status` 为 `indeterminate`。
- `Decision.Contributions` 保留每个组各自的贡献（结论、命中规则、未知原因）；`Decision.UnknownReasons` 汇总导致无法放行的缺失原因。

支持的原子操作：`eq`、`ne`、`gt`、`gte`、`lt`、`lte`、`in`、`contains`、`prefix`、`suffix`、`exists`。组合节点为 `All`、`Any`、`Not`、`Ref`，一个条件节点只能包含一种形态。

## 版本切换

`ReplaceRules` 对整批规则执行验证，全部通过后才原子发布新 `RuleSet`。以下问题都会导致整批失败并保留旧版：

- 规则 ID 为空或重复；
- Effect 非法；
- 条件节点为空、形态混合或操作符不支持；
- `Ref` 指向不存在的规则（包括跨组引用）；
- 规则引用形成循环；
- 规则被分配给未声明的规则组、规则组 ID 为空或重复；
- 空规则批。

`RuleSet` 在发布时不可变；调用方可先通过 `ActiveSet()` 固定一个快照，再执行 `Evaluate`，确保一次判断始终使用同一个版本。`Engine` 的判断和换版可并发调用。

## 影响预演与发布历史

`PreviewRules` 只编译候选规则并对保存的人工请求执行旧版/候选版双跑，不会改变当前判断。报告为每个请求保留两边的 `Decision` 与证据，并把决策差异归因到：新增/删除/修改的条件、被 `ref` 复用且发生变化的条件、优先级变化或同优先级公开顺序重排。

候选批验证失败时不会生成发布记录，也不会影响当前 `RuleSet`。预演中缺失属性继续保持三值逻辑中的“未知”，不会为了便于比较而转成 false、命中或默认允许；两边都无规则明确命中时，该请求不会被报告为决策变化。

`PreviewRuleGroups` 对多组候选做同样的双跑比较。只想调整一个组并查看影响时使用 `PreviewGroupAdjustment(groups, rules, groupID, requests)`：报告为每个请求保留该组在旧版/候选版下各自的贡献（`BeforeGroup`、`AfterGroup`，含未知原因）以及最终决策差异，未调整的组可直接对照贡献确认没有被改变。

### 候选暂存、放弃与回退

`StageRules` / `StageRuleGroups` 只编译并暂存候选，不改变当前判断；`PublishStaged` 发布暂存候选；`AbandonStaged` 放弃候选并追加独立的 `abandon` 记录（不发布、不影响线上）。撤回记录 `withdraw` 与放弃记录彼此独立，均保留在 `History()` 中。

规则与条件在发布时深拷贝，请求属性在判定时也做防御性拷贝；发布后外部修改原始条件对象或请求 map，都不会改变任何已发布快照（包括旧快照）的判断。

`PublishRules` 在候选验证通过后原子发布并追加 `ReleaseRecord`。已经开始的判断应持有 `ActiveSet()` 返回的快照；发布后该快照仍按旧版本执行，直到业务流程显式重新取快照。`WithdrawRules` 会恢复当前发布记录中的上一版，同时保留发布与撤回记录；撤回后再次发布使用新的单调版本号。

## 使用示例

```go
engine, err := policy.NewEngine([]policy.Rule{{
	ID:       "vip-allow",
	Priority: 100,
	Effect:   policy.EffectAllow,
	Condition: &policy.Condition{All: []*policy.Condition{
		{Field: "tier", Op: policy.OpEqual, Value: "vip"},
		{Field: "risk", Op: policy.OpLess, Value: 50},
	}},
}})
if err != nil {
	return err
}

decision := engine.Evaluate(map[string]any{"tier": "vip", "risk": 10})
if !decision.Allowed {
	return fmt.Errorf("denied by %s", decision.Evidence.Rule.ID)
}
```

发布前校验候选版本；正式发布使用带历史的 `PublishRules`：

```go
if _, err := engine.PreviewRules(rules, nil); err != nil {
	// 当前版本和已保存历史不受影响。
	return err
}
if _, err := engine.PublishRules(rules); err != nil {
	return err
}
```

保存人工请求并预演候选规则：

```go
report, err := engine.PreviewRules(candidateRules, []policy.SavedRequest{{
	ID:         "case-001",
	Description: "高风险 VIP，复用黑名单条件",
	Attributes: map[string]any{"tier": "vip", "risk": "high"},
}})
if err != nil {
	return err
}
for _, impact := range report.Requests {
	if !impact.Changed {
		continue
	}
	for _, cause := range impact.Causes {
		log.Printf("%s: %s %s", impact.Request.ID, cause.RuleID, cause.Message)
	}
}

if _, err := engine.PublishRules(candidateRules); err != nil {
	return err
}
if _, err := engine.WithdrawRules(); err != nil {
	return err
}
history := engine.History()
```

多个独立规则组、只调整一个组预演，以及暂存/放弃候选：

```go
engine, err := policy.NewEngineWithGroups(
	[]policy.RuleGroup{{ID: "security", Priority: 100}, {ID: "business", Priority: 10}},
	[]policy.Rule{
		{ID: "blocked", Group: "security", Effect: policy.EffectDeny, Condition: blockedCond},
		{ID: "vip", Group: "business", Effect: policy.EffectAllow, Condition: vipCond},
	})

// 只调整 business 组，查看该组贡献与最终差异；security 组保持不变。
report, err := engine.PreviewGroupAdjustment(nextGroups, nextRules, "business", savedRequests)

candidate, err := engine.StageRuleGroups(nextGroups, nextRules)
if reject {
	_ = engine.AbandonStaged(candidate, "rejected in review") // 独立 abandon 记录
} else {
	_, _ = engine.PublishStaged(candidate)
}
```

也可以直接调用 `engine.ReplaceRules(rules)`，该方法内部执行相同的“先验证、后原子切换”流程。

## 验证

```sh
go test ./...
go test -race ./...
go vet ./...
```
