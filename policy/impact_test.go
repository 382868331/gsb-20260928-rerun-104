package policy

import "testing"

func TestPreviewDoesNotActivateInvalidCandidateAndPreservesUnknown(t *testing.T) {
	engine, err := NewEngine([]Rule{{
		ID:        "safe-only",
		Effect:    EffectAllow,
		Condition: field("safe", OpEqual, true),
	}})
	if err != nil {
		t.Fatal(err)
	}
	requests := []SavedRequest{{
		ID:         "missing-safe",
		Attributes: map[string]any{},
	}}

	_, err = engine.PreviewRules([]Rule{{
		ID:     "invalid",
		Effect: EffectAllow,
	}}, requests)
	if err == nil {
		t.Fatal("expected candidate validation failure")
	}
	if engine.Version() != 1 {
		t.Fatalf("invalid candidate changed active version to %d", engine.Version())
	}
	if len(engine.History()) != 1 {
		t.Fatalf("failed candidate validation must not create release history: %+v", engine.History())
	}
	if decision := engine.Evaluate(map[string]any{}); decision.Matched || decision.Allowed {
		t.Fatalf("unknown attribute must not be treated as satisfied or default allow: %+v", decision)
	}

	report, err := engine.PreviewRules([]Rule{{
		ID:        "unsafe-preview",
		Effect:    EffectAllow,
		Condition: field("safe", OpEqual, false),
	}}, requests)
	if err != nil {
		t.Fatal(err)
	}
	if engine.Version() != 1 {
		t.Fatal("preview must not publish candidate")
	}
	if len(report.Requests) != 1 || report.Requests[0].Before.Matched || report.Requests[0].After.Matched {
		t.Fatalf("missing attribute must remain unknown on both sets: %+v", report.Requests)
	}
}

func TestPreviewAttributesChangeToReferencedCondition(t *testing.T) {
	base, err := CompileRules(1, []Rule{{
		ID:        "gate",
		Effect:    EffectAllow,
		Condition: &Condition{Ref: "shared"},
	}, {
		ID:        "shared",
		Effect:    EffectDeny,
		Condition: field("risk", OpEqual, "low"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := CompileRules(2, []Rule{{
		ID:        "gate",
		Effect:    EffectAllow,
		Condition: &Condition{Ref: "shared"},
	}, {
		ID:        "shared",
		Effect:    EffectDeny,
		Condition: field("risk", OpEqual, "high"),
	}})
	if err != nil {
		t.Fatal(err)
	}

	report := PreviewSets(base, candidate, []SavedRequest{{
		ID:         "request",
		Attributes: map[string]any{"risk": "high"},
	}})
	impact := report.Requests[0]
	if !impact.Changed || impact.Before.Matched || !impact.After.Matched {
		t.Fatalf("expected referenced condition to change decision: %+v", impact)
	}
	if !hasCause(impact.Causes, ChangeConditionModified, "shared") {
		t.Fatalf("expected change on referenced rule shared, got %+v", impact.Causes)
	}
}

func TestPreviewAttributesSamePriorityReorder(t *testing.T) {
	rules := []Rule{{
		ID:        "allow-first",
		Priority:  10,
		Effect:    EffectAllow,
		Condition: field("kind", OpEqual, "shared"),
	}, {
		ID:        "deny-second",
		Priority:  10,
		Effect:    EffectDeny,
		Condition: field("kind", OpEqual, "shared"),
	}}
	base, err := CompileRules(1, rules)
	if err != nil {
		t.Fatal(err)
	}
	candidateRules := []Rule{rules[1], rules[0]}
	candidate, err := CompileRules(2, candidateRules)
	if err != nil {
		t.Fatal(err)
	}

	impact := PreviewSets(base, candidate, []SavedRequest{{
		ID:         "request",
		Attributes: map[string]any{"kind": "shared"},
	}}).Requests[0]
	if !impact.Changed || impact.After.Effect != EffectDeny {
		t.Fatalf("expected reordered tie to deny: %+v", impact)
	}
	if !hasCause(impact.Causes, ChangeSamePriorityOrder, "deny-second") {
		t.Fatalf("expected same-priority reorder cause, got %+v", impact.Causes)
	}
}

func TestPreviewAttributesPriorityChange(t *testing.T) {
	rules := []Rule{{
		ID:        "low-allow",
		Priority:  1,
		Effect:    EffectAllow,
		Condition: field("kind", OpEqual, "shared"),
	}, {
		ID:        "high-deny",
		Priority:  10,
		Effect:    EffectDeny,
		Condition: field("kind", OpEqual, "shared"),
	}}
	base, err := CompileRules(1, rules)
	if err != nil {
		t.Fatal(err)
	}
	candidateRules := []Rule{{
		ID:        "low-allow",
		Priority:  20,
		Effect:    EffectAllow,
		Condition: field("kind", OpEqual, "shared"),
	}, rules[1]}
	candidate, err := CompileRules(2, candidateRules)
	if err != nil {
		t.Fatal(err)
	}

	impact := PreviewSets(base, candidate, []SavedRequest{{
		ID:         "request",
		Attributes: map[string]any{"kind": "shared"},
	}}).Requests[0]
	if !impact.Changed || impact.After.Effect != EffectAllow {
		t.Fatalf("expected priority change to allow: %+v", impact)
	}
	if !hasCause(impact.Causes, ChangePriorityModified, "low-allow") {
		t.Fatalf("expected priority-modified cause, got %+v", impact.Causes)
	}
}

func TestPublishWithdrawKeepsHistoryAndSnapshot(t *testing.T) {
	engine, err := NewEngine([]Rule{{
		ID:        "v1",
		Effect:    EffectAllow,
		Condition: field("version", OpEqual, 1),
	}})
	if err != nil {
		t.Fatal(err)
	}
	fixed := engine.ActiveSet()
	if _, err := engine.PublishRules([]Rule{{
		ID:        "v2",
		Effect:    EffectDeny,
		Condition: field("version", OpEqual, 1),
	}}); err != nil {
		t.Fatal(err)
	}

	if decision := fixed.Evaluate(map[string]any{"version": 1}); !decision.Allowed || decision.Version != 1 {
		t.Fatalf("in-flight snapshot changed: %+v", decision)
	}
	if _, err := engine.WithdrawRules(); err != nil {
		t.Fatal(err)
	}
	if decision := engine.Evaluate(map[string]any{"version": 1}); !decision.Allowed || engine.Version() != 1 {
		t.Fatalf("withdrawal did not restore v1: %+v version %d", decision, engine.Version())
	}
	history := engine.History()
	if len(history) != 3 || history[0].Action != ReleaseActionPublish || history[1].Action != ReleaseActionPublish || history[2].Action != ReleaseActionWithdraw {
		t.Fatalf("withdrawal must retain publish and withdrawal history, got %+v", history)
	}
}

func hasCause(causes []ImpactCause, kind ChangeKind, ruleID string) bool {
	for _, cause := range causes {
		if cause.Kind == kind && cause.RuleID == ruleID {
			return true
		}
	}
	return false
}
