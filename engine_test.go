package engine

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func field(name string, op Operator, value any) Condition {
	return Condition{Field: name, Op: op, Value: value}
}

func TestCompositeConditionsAndEvidence(t *testing.T) {
	engine, err := NewEngine("v1", RuleSet{Rules: []Rule{{
		ID:       "authenticated-internal-write",
		Effect:   DecisionAllow,
		Priority: 100,
		Condition: Condition{All: []Condition{
			field("user.authenticated", OpEqual, true),
			field("source.network", OpEqual, "internal"),
			Condition{Any: []Condition{
				field("request.method", OpIn, []any{"POST", "PUT"}),
				field("request.read_only", OpEqual, true),
			}},
		}},
	}}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	evidence := engine.Evaluate(map[string]any{
		"user":    map[string]any{"authenticated": true},
		"source":  map[string]any{"network": "internal"},
		"request": map[string]any{"method": "POST", "read_only": false},
	})
	if evidence.Decision != DecisionAllow {
		t.Fatalf("Decision = %q, want allow: %+v", evidence.Decision, evidence)
	}
	if evidence.MatchedRuleID != "authenticated-internal-write" {
		t.Fatalf("MatchedRuleID = %q", evidence.MatchedRuleID)
	}
	if evidence.VersionID != "v1" || evidence.Reason != "rule_matched" {
		t.Fatalf("unexpected evidence: %+v", evidence)
	}
}

func TestMissingAttributeDoesNotSatisfyCondition(t *testing.T) {
	engine, err := NewEngine("v1", RuleSet{Rules: []Rule{{
		ID:        "missing-role-must-not-allow",
		Effect:    DecisionAllow,
		Condition: field("role", OpEqual, "admin"),
	}}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	evidence := engine.Evaluate(map[string]any{})
	if evidence.Decision != DecisionDeny {
		t.Fatalf("Decision = %q, want deny", evidence.Decision)
	}
	if evidence.MatchedRuleID != "" || evidence.Reason != "no_matching_rule" {
		t.Fatalf("missing attribute unexpectedly matched: %+v", evidence)
	}
	if len(evidence.Missing) != 1 || evidence.Missing[0] != "role" {
		t.Fatalf("Missing = %v, want [role]", evidence.Missing)
	}
}

func TestNegatedMissingConditionStaysUnknown(t *testing.T) {
	engine, err := NewEngine("v1", RuleSet{Rules: []Rule{{
		ID:        "not-missing-does-not-match",
		Effect:    DecisionAllow,
		Condition: Condition{Not: ptr(field("role", OpEqual, "admin"))},
	}}})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	evidence := engine.Evaluate(map[string]any{})
	if evidence.Decision != DecisionDeny || evidence.MatchedRuleID != "" {
		t.Fatalf("NOT on missing field matched: %+v", evidence)
	}
}

func TestPriorityAndPublicationOrderResolveOverlap(t *testing.T) {
	broadMatch := field("request.kind", OpEqual, "api")
	rules := RuleSet{Rules: []Rule{
		{ID: "old-deny", Priority: 10, PublicationOrder: 1, Effect: DecisionDeny, Condition: broadMatch},
		{ID: "later-allow", Priority: 10, PublicationOrder: 2, Effect: DecisionAllow, Condition: broadMatch},
		{ID: "higher-allow", Priority: 20, PublicationOrder: 9, Effect: DecisionAllow, Condition: broadMatch},
	}}
	engine, err := NewEngine("v1", rules)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	evidence := engine.Evaluate(map[string]any{"request": map[string]any{"kind": "api"}})
	if evidence.MatchedRuleID != "higher-allow" {
		t.Fatalf("priority winner = %q, want higher-allow", evidence.MatchedRuleID)
	}

	rules.Rules = rules.Rules[:2]
	engine, err = NewEngine("v2", rules)
	if err != nil {
		t.Fatalf("NewEngine(v2) error = %v", err)
	}
	evidence = engine.Evaluate(map[string]any{"request": map[string]any{"kind": "api"}})
	if evidence.MatchedRuleID != "later-allow" || evidence.Decision != DecisionAllow {
		t.Fatalf("publication winner = %q/%q, want later-allow/allow", evidence.MatchedRuleID, evidence.Decision)
	}
}

func TestInvalidBatchKeepsOldVersion(t *testing.T) {
	old := RuleSet{Rules: []Rule{{
		ID:       "v1-rule",
		Effect:   DecisionAllow,
		Priority: 1,
		Condition: Condition{All: []Condition{
			{Ref: "is-admin"},
			field("request.kind", OpEqual, "api"),
		}},
	}}, NamedConditions: []NamedCondition{{
		Name:      "is-admin",
		Condition: field("user.role", OpEqual, "admin"),
	}}}
	engine, err := NewEngine("v1", old)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	invalid := RuleSet{NamedConditions: []NamedCondition{
		{Name: "a", Condition: Condition{Ref: "b"}},
		{Name: "b", Condition: Condition{Ref: "a"}},
	}, Rules: []Rule{{
		ID:        "v2-rule",
		Effect:    DecisionAllow,
		Condition: Condition{Ref: "a"},
	}}}
	err = engine.Replace("v2", invalid)
	if !errors.As(err, new(ReferenceCycleError)) && !errors.Is(err, ReferenceCycleError{}) {
		var cycle ReferenceCycleError
		if !errors.As(err, &cycle) {
			t.Fatalf("Replace() error = %v, want reference cycle", err)
		}
	}
	if current := engine.CurrentVersion(); current == nil || current.ID != "v1" {
		t.Fatalf("current version = %v, want v1", current)
	}

	evidence := engine.Evaluate(map[string]any{
		"user":    map[string]any{"role": "admin"},
		"request": map[string]any{"kind": "api"},
	})
	if evidence.VersionID != "v1" || evidence.MatchedRuleID != "v1-rule" {
		t.Fatalf("evaluation after failed publish = %+v", evidence)
	}
}

func TestUnknownReferenceAndEmptyBatchRejected(t *testing.T) {
	_, err := Compile("v1", time.Time{}, RuleSet{Rules: []Rule{{
		ID:        "bad-ref",
		Effect:    DecisionAllow,
		Condition: Condition{Ref: "missing"},
	}}})
	var validation ValidationError
	if !errors.As(err, &validation) || validation.Reason != "unknown_condition_reference" {
		t.Fatalf("error = %v, want unknown_condition_reference ValidationError", err)
	}

	if _, err := Compile("v2", time.Time{}, RuleSet{}); err == nil {
		t.Fatal("empty rule batch compiled successfully")
	}

	if _, err := Compile("v3", time.Time{}, RuleSet{Rules: []Rule{{
		ID:        "empty-group",
		Effect:    DecisionAllow,
		Condition: Condition{All: []Condition{}},
	}}}); err == nil {
		t.Fatal("empty condition group compiled successfully")
	}
}

func TestConcurrentEvaluationUsesOneVersionSnapshot(t *testing.T) {
	broadMatch := field("request.kind", OpEqual, "api")
	makeRules := func(ruleID string) RuleSet {
		return RuleSet{Rules: []Rule{{ID: ruleID, Effect: DecisionAllow, Condition: broadMatch}}}
	}
	engine, err := NewEngine("v1", makeRules("rule-v1"))
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	attributes := map[string]any{"request": map[string]any{"kind": "api"}}
	var group sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		group.Add(2)
		go func() {
			defer group.Done()
			for index := 0; index < 200; index++ {
				evidence := engine.Evaluate(attributes)
				switch evidence.VersionID {
				case "v1":
					if evidence.MatchedRuleID != "rule-v1" {
						t.Errorf("v1 matched %q", evidence.MatchedRuleID)
					}
				case "v2":
					if evidence.MatchedRuleID != "rule-v2" {
						t.Errorf("v2 matched %q", evidence.MatchedRuleID)
					}
				default:
					t.Errorf("unexpected version %q", evidence.VersionID)
				}
			}
		}()
		go func(worker int) {
			defer group.Done()
			for index := 0; index < 100; index++ {
				next := "v1"
				rule := "rule-v1"
				if (worker+index)%2 == 0 {
					next = "v2"
					rule = "rule-v2"
				}
				_ = engine.Replace(next, makeRules(rule))
			}
		}(worker)
	}
	group.Wait()
}

func TestCompiledVersionDoesNotShareMutableInputs(t *testing.T) {
	values := []any{"GET", "POST"}
	input := RuleSet{Rules: []Rule{{
		ID:        "methods",
		Effect:    DecisionAllow,
		Condition: field("request.method", OpIn, values),
	}}}
	version, err := Compile("v1", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), input)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	values[0] = "DELETE"
	input.Rules[0].ID = "mutated"

	rule, ok := version.Rule("methods")
	if !ok {
		t.Fatalf("RuleIDs = %v, want methods", version.RuleIDs())
	}
	evidence := version.evaluate(map[string]any{"request": map[string]any{"method": "GET"}})
	if evidence.Decision != DecisionAllow || evidence.MatchedRuleID != rule.ID {
		t.Fatalf("compiled version was mutated: %+v", evidence)
	}
}

func ptr[T any](value T) *T {
	return &value
}
