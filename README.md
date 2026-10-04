# 请求策略执行引擎

这是一个可嵌入 Go 业务进程的请求准入计算库，不包含角色、用户、后台或外部依赖。

## 判定语义

- 一个策略由多个**相互独立的规则组**（`RuleGroup`）共同参与判断；组间按 `Priority` 降序裁决，组内规则按 `Priority` 降序、同优先级按公开顺序升序选出首个明确成立的规则。
- 每个组给出三值结论之一：`allow`、`deny` 或 `unknown`。裁决时从高优先级组开始，第一个明确结论成为最终决策；**某组未知不能当成允许，也不能掩盖低优先级组已经给出的明确拒绝（或允许）**。
- 所有组的结论都会保留在 `Decision.Contributions` 中；因缺失/不可用属性而未知的规则 ID 保留在 `GroupContribution.UnknownFor`，可读原因汇总在 `Decision.UnknownReasons`。所有组都未知时最终拒绝（`Matched=false, Unknown=true`），绝不默认允许。
- 规则按 `Priority` 降序执行；同优先级按提交批处理中的公开顺序升序执行。
- 引擎从排序后的规则中选择第一个条件明确成立的规则，其 `Effect` 就是最终决策。
- 没有任何规则命中时默认拒绝。
- 缺失属性是“未知”，不是假，更不是满足；`NOT 未知` 仍为未知。
- `all` 中出现未知且没有明确失败时整体未知；`any` 中出现未知且没有明确成功时整体未知。
- `ref` 只复用另一条规则的条件，不继承该规则的 `Effect`。
- `ref` 只能引用**同一规则组内**的规则；跨组引用、引用冲突（指向不存在目标）或引用形成循环都会令整个候选批验证失败，正式版本保持可用。
- 证据只包含实际产生决策的那一条规则及命中条件说明，不罗列全部规则。

支持的原子操作：`eq`、`ne`、`gt`、`gte`、`lt`、`lte`、`in`、`contains`、`prefix`、`suffix`、`exists`。组合节点为 `All`、`Any`、`Not`、`Ref`，一个条件节点只能包含一种形态。

## 版本切换

多组场景使用 `ReplaceGroups`/`PublishGroups`（单批 API 等价于只含 `default` 组）。引擎对整批评测，全部通过后才原子发布新 `RuleSet`。以下问题都会导致整批失败并保留旧版：

- 规则组 ID 为空或重复、规则组为空；
- 规则 ID 为空或重复；
- Effect 非法；
- 条件节点为空、形态混合或操作符不支持；
- `Ref` 指向不存在的规则；
- 规则引用形成循环；
- 空规则批。

`RuleSet` 在发布时不可变；编译时会深拷贝全部规则、条件与值，调用方在发布后修改原始条件对象不会影响任何已发布判断。调用方可先通过 `ActiveSet()` 固定一个快照，再执行 `Evaluate`，确保一次判断始终使用同一个版本。`Engine` 的判断和换版可并发调用。旧快照、被放弃的候选预演、发布记录与 `WithdrawRules` 回退记录彼此独立。

## 影响预演与发布历史

`PreviewRules` / `PreviewGroups` 只编译候选规则并对保存的人工请求执行旧版/候选版双跑，不会改变当前判断。报告为每个请求保留两边的 `Decision` 与证据，并把决策差异归因到：新增/删除/修改的条件、被 `ref` 复用且发生变化的条件、优先级变化、同优先级公开顺序重排，或某个独立规则组贡献变化（`group_modified`）。`RequestImpact.GroupImpacts` 按组列出各自的贡献差异，用户可据此只调整一个组。

`PreviewGroup(groupID, rules, requests)` 与 `PublishGroup(groupID, rules)` 只替换一个独立规则组，其余组沿用当前正式版本，因此可以只改一组并查看该批请求的最终差异；候选验证失败（含跨组引用、冲突、循环）时不会发布，也不会写入发布历史。

候选批验证失败时不会生成发布记录，也不会影响当前 `RuleSet`。预演中缺失属性继续保持三值逻辑中的“未知”，不会为了便于比较而转成 false、命中或默认允许；两边都无规则明确命中时，该请求不会被报告为决策变化。

`PublishRules` 在候选验证通过后原子发布并追加 `ReleaseRecord`。已经开始的判断应持有 `ActiveSet()` 返回的快照；发布后该快照仍按旧版本执行，直到业务流程显式重新取快照。`WithdrawRules` 会恢复当前发布记录中的上一版，同时保留发布与撤回记录；撤回后再次发布使用新的单调版本号。

## 候选观察期

`PreviewRules` 适合一次性离线双跑；当维护者需要在**真实流量副本**上长期核对新旧规则、而又完全不影响业务裁决时，使用候选观察期：

- `OpenCandidate(id, groups)` / `OpenCandidateGroup(id, groupID, rules)` 校验并登记一个候选规则集；观察期内当前规则照常裁决，候选规则只做影子计算。
- `Observe(candidateID, request)` 对同一请求同时记录当前规则与候选规则的 `Decision` 与各自的规则组贡献（`GroupContribution`）。**只有返回的当前规则结论可用于业务裁决**，候选结论仅作为观察证据。请求属性在记录时深拷贝，调用方事后修改入参或导出的记录都不能改写历史。
- `Observations(candidateID)` / `Observation(...)` 只读导出冻结记录；查询和导出永远不会反过来修改记录。
- 观察期间其他独立规则组仍可通过 `PublishGroups`/`PublishGroup` 调整。一旦某条观察所依赖的正式规则组在记录后发生变化，该记录会被标记 `Stale=true` 并列出 `ChangedDependencies`；记录里的历史结论保持原值不变。`PublishCandidate` 会拒绝任何带过期记录的发布——**不能以过期结论直接发布**，需要在新正式版本上补采新鲜观察。
- `CompareCandidates(candidateA, candidateB, requests)` 让两个候选在同一批历史请求上对照（不传请求时使用两个候选共同观察过的请求）。差异分两类：`explicit_change`（双方都有明确裁决但结论不同，`ExplicitDenyChanged` 标明是否包含明确拒绝）与 `unknown_change`（至少一方因信息未知而无明确裁决），不会把“信息未知”混同为“明确拒绝变化”。
- `AbandonCandidate(id, reason)` 放弃候选但保留全部观察与放弃理由；`ReopenCandidate(id)` 重开后沿用已确认的观察和放弃历史；同 ID 但内容不同的重新定义会被拒绝。
- `PublishCandidate(id)` 只在没有过期记录时发布，并在发布记录 `ReleaseRecord.Basis` 中说明实际采用的依据范围：采用了哪些观察/请求、覆盖的正式版本区间、以及之前保留的放弃说明。

```go
id := "risk-low-deny"
if _, err := engine.OpenCandidateGroup(id, "risk", candidateRiskRules); err != nil {
	return err
}

// 在真实处理路径上：formal 是唯一用于业务裁决的结论。
formal, observation, err := engine.Observe(id, policy.SavedRequest{
	ID:         traceID,
	Attributes: attributes,
})
if err != nil {
	return err
}
if !formal.Allowed {
	return fmt.Errorf("denied by %s", formal.Evidence.Rule.ID)
}
_ = observation // 候选侧结论只做核对，不参与放行或拒绝

// 另一个组在观察期间照常调整；受影响的旧观察会自动带上 Stale 标记。
comparison, err := engine.CompareCandidates("candidate-a", "candidate-b", nil)
if err != nil {
	return err
}
_ = comparison

// 放弃后理由保留；重开沿用既有观察。
_ = engine.AbandonCandidate(id, "缺少边界用例覆盖")
_, _ = engine.ReopenCandidate(id)

// 没有过期记录才能发布，发布记录会带上 Basis。
if _, basis, err := engine.PublishCandidate(id); err != nil {
	return err
} else {
	log.Print(basis.Summary)
}
```

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

也可以直接调用 `engine.ReplaceRules(rules)`，该方法内部执行相同的“先验证、后原子切换”流程。

## 验证

```sh
go test ./...
go test -race ./...
go vet ./...
```
