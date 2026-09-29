package policy

import (
	"sync"
	"testing"
)

func field(name string, op Operator, value any) *Condition {
	return &Condition{Field: name, Op: op, Value: value}
}

func TestPriorityAndPublicOrder(t *testing.T) {
	rules := []Rule{
		{ID: "lower-deny", Priority: 1, Effect: EffectDeny, Condition: field("tier", OpEqual, "vip")},
		{ID: "higher-allow", Priority: 10, Effect: EffectAllow, Condition: field("tier", OpEqual, "vip")},
	}
	engine, err := NewEngine(rules)
	if err != nil {
		t.Fatal(err)
	}

	decision := engine.Evaluate(map[string]any{"tier": "vip"})
	if !decision.Allowed || decision.Evidence == nil || decision.Evidence.Rule.ID != "higher-allow" {
		t.Fatalf("expected higher priority allow, got %+v", decision)
	}

	tied := []Rule{
		{ID: "first-allow", Priority: 5, Effect: EffectAllow, Condition: field("tier", OpEqual, "vip")},
		{ID: "second-deny", Priority: 5, Effect: EffectDeny, Condition: field("tier", OpEqual, "vip")},
	}
	if err := engine.ReplaceRules(tied); err != nil {
		t.Fatal(err)
	}
	decision = engine.Evaluate(map[string]any{"tier": "vip"})
	if !decision.Allowed || decision.Evidence.Rule.ID != "first-allow" {
		t.Fatalf("expected earlier public rule to win tie, got %+v", decision)
	}
}

func TestMissingAttributesDoNotSatisfyConditions(t *testing.T) {
	rules := []Rule{
		{
			ID:        "not-missing-is-not-true",
			Effect:    EffectAllow,
			Condition: &Condition{Not: field("risk", OpEqual, "high")},
		},
		{
			ID:     "any-with-missing",
			Effect: EffectAllow,
			Condition: &Condition{Any: []*Condition{
				field("missing", OpEqual, true),
				field("risk", OpEqual, "low"),
			}},
		},
		{
			ID:     "all-with-missing",
			Effect: EffectAllow,
			Condition: &Condition{All: []*Condition{
				field("tier", OpEqual, "free"),
				field("quota", OpAtLeast, 1),
			}},
		},
	}
	engine, err := NewEngine(rules)
	if err != nil {
		t.Fatal(err)
	}

	for name, request := range map[string]map[string]any{
		"empty":              {},
		"partially matching": {"tier": "free"},
	} {
		t.Run(name, func(t *testing.T) {
			decision := engine.Evaluate(request)
			if decision.Allowed || decision.Matched {
				t.Fatalf("missing attributes must not match, got %+v", decision)
			}
		})
	}

	negationSet, err := CompileRules(1, []Rule{{
		ID:        "negated-missing",
		Effect:    EffectAllow,
		Condition: &Condition{Not: field("risk", OpEqual, "high")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if decision := negationSet.Evaluate(map[string]any{}); decision.Matched || decision.Allowed {
		t.Fatalf("not(missing) must remain unknown, got %+v", decision)
	}
}

func TestCombinationAndReferenceEvidence(t *testing.T) {
	rules := []Rule{
		{
			ID:       "vip",
			Priority: 1,
			Effect:   EffectAllow,
			Condition: &Condition{All: []*Condition{
				field("tier", OpEqual, "vip"),
				{Ref: "not-blocked"},
			}},
		},
		{
			ID:        "blocked",
			Priority:  100,
			Effect:    EffectDeny,
			Condition: field("blocked", OpEqual, true),
		},
		{
			ID:        "not-blocked-definition",
			Effect:    EffectDeny,
			Condition: &Condition{Not: field("blocked", OpEqual, true)},
		},
	}
	// The last definition is only condition storage under the referenced ID.
	rules[2].ID = "not-blocked"
	engine, err := NewEngine(rules)
	if err != nil {
		t.Fatal(err)
	}

	decision := engine.Evaluate(map[string]any{"tier": "vip", "blocked": false})
	if !decision.Allowed || decision.Evidence.Rule.ID != "vip" {
		t.Fatalf("expected referenced combination to allow, got %+v", decision)
	}
	if len(decision.Evidence.Explanation) == 0 {
		t.Fatal("expected actual-match evidence")
	}

	decision = engine.Evaluate(map[string]any{"tier": "vip", "blocked": true})
	if decision.Allowed || decision.Evidence.Rule.ID != "blocked" {
		t.Fatalf("expected high-priority deny, got %+v", decision)
	}
}

func TestInvalidBatchKeepsPreviousVersion(t *testing.T) {
	engine, err := NewEngine([]Rule{{
		ID:       "old-allow",
		Effect:   EffectAllow,
		Priority: 1,
		Condition: &Condition{All: []*Condition{
			field("tier", OpEqual, "vip"),
			{Ref: "safe"},
		}},
	}, {
		ID:        "safe",
		Effect:    EffectDeny,
		Condition: field("safe", OpEqual, true),
	}})
	if err != nil {
		t.Fatal(err)
	}

	invalid := []Rule{
		{ID: "dup", Effect: EffectAllow, Condition: field("a", OpEqual, 1)},
		{ID: "dup", Effect: EffectDeny, Condition: field("b", OpEqual, 2)},
		{ID: "cycle-a", Effect: EffectAllow, Condition: &Condition{Ref: "cycle-b"}},
		{ID: "cycle-b", Effect: EffectAllow, Condition: &Condition{Ref: "cycle-a"}},
		{ID: "missing-ref", Effect: EffectAllow, Condition: &Condition{Ref: "missing"}},
		{ID: "bad-effect", Effect: Effect("maybe"), Condition: field("x", OpEqual, 1)},
	}
	if err := engine.ReplaceRules(invalid); err == nil {
		t.Fatal("expected batch validation to fail")
	}

	if engine.Version() != 1 {
		t.Fatalf("expected old version 1, got %d", engine.Version())
	}
	decision := engine.Evaluate(map[string]any{"tier": "vip", "safe": true})
	if !decision.Allowed || decision.Evidence.Rule.ID != "old-allow" {
		t.Fatalf("old rules must remain active, got %+v", decision)
	}
}

func TestConcurrentEvaluationAndReplacement(t *testing.T) {
	engine, err := NewEngine([]Rule{{
		ID:        "v1",
		Effect:    EffectAllow,
		Condition: field("version", OpEqual, 1),
	}})
	if err != nil {
		t.Fatal(err)
	}

	var wait sync.WaitGroup
	versions := make(chan int, 1<<16)
	wait.Add(3)
	go func() {
		defer wait.Done()
		for i := 0; i < 200; i++ {
			next := 2 + i
			err := engine.ReplaceRules([]Rule{{
				ID:        "v",
				Effect:    EffectAllow,
				Condition: field("version", OpEqual, next),
			}})
			if err != nil {
				t.Error(err)
				return
			}
		}
	}()
	for worker := 0; worker < 2; worker++ {
		go func() {
			defer wait.Done()
			for i := 0; i < 500; i++ {
				set := engine.ActiveSet()
				decision := set.Evaluate(map[string]any{"version": set.Version()})
				if decision.Version != set.Version() || !decision.Allowed || decision.Evidence == nil {
					t.Errorf("inconsistent snapshot decision: %+v", decision)
					return
				}
				versions <- decision.Version
			}
		}()
	}
	wait.Wait()
	close(versions)
	if len(versions) == 0 {
		t.Fatal("expected concurrent evaluations")
	}
}
