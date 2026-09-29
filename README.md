# 请求策略执行引擎

一个无外部依赖、可直接嵌入 Go 服务的请求准入计算库。它只负责根据当前规则版本对请求属性做判定并给出证据，不包含角色、用户、资源等后台管理能力。

## 规则语义

- 规则按 `priority` 从高到低评估；同优先级按 `publication_order` 从晚到早评估，即后公开的同优先级规则覆盖先公开规则。
- 第一条命中的规则直接决定 `allow` 或 `deny`，证据只记录这一条实际命中的规则。
- 没有规则命中时返回 `deny/no_matching_rule`；未加载版本时返回 `deny/no_rule_version_loaded`。
- 条件树支持 `all`、`any`、`not` 和命名条件引用。
- 缺失属性产生三值逻辑中的“未知”，不会被当作满足；`not` 遇到缺失属性也不会反向命中。
- 重叠规则不是发布错误；矛盾重叠由优先级和公开顺序稳定裁决。
- 命名条件引用不存在或形成循环会导致整批发布失败。

## 快速使用

```go
policyEngine, err := engine.NewEngine("v1", engine.RuleSet{
	Rules: []engine.Rule{{
		ID:               "internal-write",
		Priority:         100,
		PublicationOrder: 1,
		Effect:           engine.DecisionAllow,
		Condition: engine.Condition{All: []engine.Condition{
			{Field: "source.network", Op: engine.OpEqual, Value: "internal"},
			{Field: "request.method", Op: engine.OpIn, Value: []any{"POST", "PUT"}},
		}},
	}},
})
if err != nil {
	return err
}

result := policyEngine.Evaluate(map[string]any{
	"source":  map[string]any{"network": "internal"},
	"request": map[string]any{"method": "POST"},
})
// result.Decision == engine.DecisionAllow
```

支持的比较操作符：`eq`、`ne`、`lt`、`le`、`gt`、`ge`、`in`、`not_in`、`contains`、`starts_with`、`ends_with`。字段名支持点路径，例如 `request.method`。

## 版本切换

`Replace` 会先完整编译和验证新批次；验证通过后才通过一次原子指针交换启用。任何未知引用、引用循环、重复规则 ID、非法效果或非法条件都会返回错误，当前旧版本继续提供判断。

每次判断在开始时读取一个不可变版本快照，因此即使其他 goroutine 同时发布新版本，本次判断使用的规则和证据中的 `version_id` 都来自同一个版本。
