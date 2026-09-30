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

支持的原子操作：`eq`、`ne`、`gt`、`gte`、`lt`、`lte`、`in`、`contains`、`prefix`、`suffix`、`exists`。组合节点为 `All`、`Any`、`Not`、`Ref`，一个条件节点只能包含一种形态。

## 版本切换

`ReplaceRules` 对整批规则执行验证，全部通过后才原子发布新 `RuleSet`。以下问题都会导致整批失败并保留旧版：

- 规则 ID 为空或重复；
- Effect 非法；
- 条件节点为空、形态混合或操作符不支持；
- `Ref` 指向不存在的规则；
- 规则引用形成循环；
- 空规则批。

`RuleSet` 在发布时不可变；调用方可先通过 `ActiveSet()` 固定一个快照，再执行 `Evaluate`，确保一次判断始终使用同一个版本。`Engine` 的判断和换版可并发调用。

## 影响预演

发布候选规则前，可以把人工保存的真实请求同时回放到旧版和候选版：

```go
engine.SaveRequest(policy.SavedRequest{
	ID:          "vip-risk-review",
	Description: "人工复核过的 VIP 请求",
	Attributes:  map[string]any{"tier": "vip", "risk": 15},
})

preview, err := engine.PreviewCandidate(candidateRules)
if err != nil {
	// 候选规则校验失败；当前版本和正在执行的请求均不受影响。
	return err
}
for _, change := range preview.RequestChanges {
	// change.Old / change.New 包含完整决策与每条规则的 matched、failed、unknown 轨迹。
	// change.Reasons 标明变化来自原子条件、ref 复用的条件、优先级、同优先级公开顺序或 effect。
	_ = change
}
```

也可以直接使用 `PreviewRules(candidateRules, requests)` 临时传入请求。预演会先完整编译候选 `RuleSet`，编译失败不会替换当前版本；预演返回的候选集也是独立不可变快照。

缺失属性始终记录为 `unknown`，不会为了比较方便归类为 `false` 或默认允许。同优先级规则只调整公开顺序时，报告会保留 `public_order` 原因；对那些相关规则仍为 `unknown` 的请求，`Changed` 仍为 false，避免把元数据重排误报为决策影响。

## 发布历史与撤回

`WithdrawLastPublish()` 会恢复发布前活动的规则集，并向历史追加一条 `withdrawn` 记录；原来的发布记录不会删除，可通过 `History()` 审计。撤回后再次发布会获得新的版本号，不覆盖历史版本。

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

发布前校验下一版：

```go
next, err := policy.CompileRules(engine.Version()+1, rules)
if err != nil {
	// 当前 engine.Version() 和旧规则不受影响。
	return err
}
if err := engine.LoadSet(next); err != nil {
	return err
}
```

也可以直接调用 `engine.ReplaceRules(rules)`，该方法内部执行相同的“先验证、后原子切换”流程。

## 验证

```sh
go test ./...
go test -race ./...
go vet ./...
```
