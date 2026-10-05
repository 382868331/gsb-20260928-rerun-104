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

`StartObservation(candidateID, groups)` 编译一组候选规则并开始影子观察，不影响业务裁决。之后每个真实请求调用 `Observe(candidateID, requestID, attrs)`：返回的 `Decision` 永远来自当前正式规则（唯一业务裁决），同时把同一请求在当前与候选规则下各自的结论与规则组贡献写入一条 `ObservationRecord`。

- 观察记录在写入时深拷贝请求当时可用的属性与两侧 `Decision`；`ObservationRecords` 只返回深拷贝，查询或导出不会改写历史事实。
- 观察期间其他规则组仍可正常调整。任何正式发布/撤回（`PublishRules`/`PublishGroups`/`PublishGroup`/`WithdrawRules`）或 `UpdateObservationCandidate` 修改候选本身，都会在变更发生时把依赖已移动的记录标记为 `Stale` 并注明原因；过期记录不能被 `ConfirmObservations` 确认，`PublishObservation` 也拒绝直接采用含过期结论的确认依据。
- `CompareObservations(a, b)` 把两个候选对齐到双方都观察过的同一批历史请求上，差异分为 `explicit_deny_change`（两侧均有确定结论且至少一侧为明确拒绝）、`explicit_change`（其他确定结论差异）与 `unknown_difference`（至少一侧因信息不足未知）。
- `AbandonObservation(candidateID, reason)` 放弃候选但保留全部记录与放弃理由；`ResumeObservation` 重开后沿用已确认的观察与放弃状态，已标记过期的记录保持过期。
- `PublishObservation(candidateID)` 要求至少一条已确认且未过期的观察，发布记录说明实际采用的依据范围（确认记录数与其对应的基线版本）。

```go
if err := engine.StartObservation("cand-1", candidateGroups); err != nil {
	return err
}
decision, err := engine.Observe("cand-1", requestID, attrs) // decision 仍由当前规则裁决
if err != nil {
	return err
}
records, _ := engine.ObservationRecords("cand-1")
comparison, _ := engine.CompareObservations("cand-1", "cand-2")
if err := engine.ConfirmObservations("cand-1"); err != nil {
	return err
}
if _, err := engine.PublishObservation("cand-1"); err != nil {
	return err
}
```

## 使用示例

## 限定范围发布

观察期之外，维护者可以为候选批准一份**限定范围**的发布计划（`RolloutPlan`）：按请求属性划定互不混淆的试用群组（`TrialGroups`）、最大业务暴露量（`MaxExposure`）以及必须保留原规则的范围（`ProtectedScopes`）。范围条件只使用原子/组合条件，不允许 `ref`。

- `ComputeRolloutImpact(candidateID)` 先用有效（未过期）观察记录计算哪些请求可能受到明确拒绝变化（`DenyChanges`）或未知属性影响（`UnknownAffected`），再据此批准分组方案。
- `ApproveRollout(candidateID, plan)` 校验并深拷贝计划；批准后 `Adjudicate(candidateID, requestID, attrs)` 对恰好落入一个试用群组、不触及保护范围且归属可确定的请求由候选裁决，其余请求继续原规则。
- 同一 `requestID` 重复处理返回已记录的裁决，不增加暴露计数、不改变归属；归属冲突（命中多个群组）或归属未知一律回退原规则且不计暴露。
- 暴露量耗尽、依赖规则变化（正式发布/撤回、候选更新）或 `WithdrawRollout` 紧急撤回都会停止新的候选采用；已记录的裁决及其当时版本保留并继续对重复请求生效。
- `RolloutInfo` / `RolloutAssignments` 只返回深拷贝，用于核对真实裁决归属与范围上限。

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
