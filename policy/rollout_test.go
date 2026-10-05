package policy

import (
	"fmt"
	"sync"
	"testing"
)

func rolloutEngine(t *testing.T) *Engine {
	t.Helper()
	engine, err := NewEngine([]Rule{{
		ID:       "vip-allow",
		Priority: 10,
		Effect:   EffectAllow,
		Condition: &Condition{All: []*Condition{
			{Field: "tier", Op: OpEqual, Value: "vip"},
			{Field: "risk", Op: OpLess, Value: 50},
		}},
	}})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	candidate := []RuleGroup{{
		ID:       DefaultGroupID,
		Priority: 0,
		Rules: []Rule{{
			ID:       "vip-deny",
			Priority: 10,
			Effect:   EffectDeny,
			Condition: &Condition{All: []*Condition{
				{Field: "tier", Op: OpEqual, Value: "vip"},
				{Field: "risk", Op: OpLess, Value: 50},
			}},
		}},
	}}
	if err := engine.StartObservation("cand", candidate); err != nil {
		t.Fatalf("StartObservation: %v", err)
	}
	return engine
}

func betaPlan(maxExposure int) RolloutPlan {
	return RolloutPlan{
		MaxExposure: maxExposure,
		TrialGroups: []TrialGroup{{
			ID:        "beta",
			Condition: &Condition{Field: "cohort", Op: OpEqual, Value: "beta"},
		}},
	}
}

func TestRolloutAdjudicatesOnlyApprovedScope(t *testing.T) {
	engine := rolloutEngine(t)
	if _, err := engine.Observe("cand", "obs-1", map[string]any{"tier": "vip", "risk": 10, "cohort": "beta"}); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	impact, err := engine.ComputeRolloutImpact("cand")
	if err != nil {
		t.Fatalf("ComputeRolloutImpact: %v", err)
	}
	if impact.ValidRecords != 1 || len(impact.DenyChanges) != 1 || impact.DenyChanges[0] != "obs-1" {
		t.Fatalf("unexpected impact: %+v", impact)
	}
	if err := engine.ApproveRollout("cand", betaPlan(10)); err != nil {
		t.Fatalf("ApproveRollout: %v", err)
	}

	inScope := map[string]any{"tier": "vip", "risk": 10, "cohort": "beta"}
	decision, err := engine.Adjudicate("cand", "req-1", inScope)
	if err != nil {
		t.Fatalf("Adjudicate: %v", err)
	}
	if decision.Allowed || decision.Effect != EffectDeny {
		t.Fatalf("in-scope request should be denied by candidate, got %+v", decision)
	}

	outOfScope := map[string]any{"tier": "vip", "risk": 10, "cohort": "stable"}
	decision, err = engine.Adjudicate("cand", "req-2", outOfScope)
	if err != nil {
		t.Fatalf("Adjudicate: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("out-of-scope request should keep original allow, got %+v", decision)
	}

	info, err := engine.RolloutInfo("cand")
	if err != nil {
		t.Fatalf("RolloutInfo: %v", err)
	}
	if info.Exposure != 1 || info.AdoptedAssignments != 1 || info.Assignments != 2 {
		t.Fatalf("unexpected rollout info: %+v", info)
	}
}

func TestRolloutRepeatRequestIsIdempotent(t *testing.T) {
	engine := rolloutEngine(t)
	if err := engine.ApproveRollout("cand", betaPlan(5)); err != nil {
		t.Fatalf("ApproveRollout: %v", err)
	}
	attrs := map[string]any{"tier": "vip", "risk": 10, "cohort": "beta"}
	first, err := engine.Adjudicate("cand", "req-1", attrs)
	if err != nil {
		t.Fatalf("Adjudicate: %v", err)
	}
	second, err := engine.Adjudicate("cand", "req-1", attrs)
	if err != nil {
		t.Fatalf("Adjudicate repeat: %v", err)
	}
	if first.Allowed != second.Allowed || first.Effect != second.Effect {
		t.Fatalf("repeat request changed decision: %+v vs %+v", first, second)
	}
	info, _ := engine.RolloutInfo("cand")
	if info.Exposure != 1 || info.Assignments != 1 {
		t.Fatalf("repeat request must not add exposure or assignments: %+v", info)
	}
}

func TestRolloutQuotaExhaustionStopsAdoption(t *testing.T) {
	engine := rolloutEngine(t)
	if err := engine.ApproveRollout("cand", betaPlan(1)); err != nil {
		t.Fatalf("ApproveRollout: %v", err)
	}
	attrs := map[string]any{"tier": "vip", "risk": 10, "cohort": "beta"}
	first, _ := engine.Adjudicate("cand", "req-1", attrs)
	if first.Allowed {
		t.Fatalf("first request should be adopted by candidate")
	}
	second, _ := engine.Adjudicate("cand", "req-2", attrs)
	if !second.Allowed {
		t.Fatalf("quota exhausted: second request must keep original allow")
	}
	info, _ := engine.RolloutInfo("cand")
	if info.Status != RolloutHalted || info.Exposure != 1 {
		t.Fatalf("rollout should halt at quota, got %+v", info)
	}
	third, _ := engine.Adjudicate("cand", "req-3", attrs)
	if !third.Allowed {
		t.Fatalf("halted rollout must keep original rules for new requests")
	}
}

func TestRolloutWithdrawKeepsRecordedDecisions(t *testing.T) {
	engine := rolloutEngine(t)
	if err := engine.ApproveRollout("cand", betaPlan(10)); err != nil {
		t.Fatalf("ApproveRollout: %v", err)
	}
	attrs := map[string]any{"tier": "vip", "risk": 10, "cohort": "beta"}
	adopted, _ := engine.Adjudicate("cand", "req-1", attrs)
	if adopted.Allowed {
		t.Fatalf("expected candidate deny before withdraw")
	}
	if err := engine.WithdrawRollout("cand", "emergency stop"); err != nil {
		t.Fatalf("WithdrawRollout: %v", err)
	}
	fresh, _ := engine.Adjudicate("cand", "req-2", attrs)
	if !fresh.Allowed {
		t.Fatalf("withdrawn rollout must not adopt new requests")
	}
	replayed, _ := engine.Adjudicate("cand", "req-1", attrs)
	if replayed.Allowed {
		t.Fatalf("recorded decision must be retained after withdraw")
	}
	info, _ := engine.RolloutInfo("cand")
	if info.Status != RolloutWithdrawn || info.Exposure != 1 {
		t.Fatalf("unexpected info after withdraw: %+v", info)
	}
}

func TestRolloutOverlappingGroupsKeepOriginal(t *testing.T) {
	engine := rolloutEngine(t)
	plan := RolloutPlan{
		MaxExposure: 10,
		TrialGroups: []TrialGroup{
			{ID: "a", Condition: &Condition{Field: "cohort", Op: OpEqual, Value: "beta"}},
			{ID: "b", Condition: &Condition{Field: "tier", Op: OpEqual, Value: "vip"}},
		},
	}
	if err := engine.ApproveRollout("cand", plan); err != nil {
		t.Fatalf("ApproveRollout: %v", err)
	}
	decision, err := engine.Adjudicate("cand", "req-1", map[string]any{"tier": "vip", "risk": 10, "cohort": "beta"})
	if err != nil {
		t.Fatalf("Adjudicate: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("overlapping groups must keep original rules")
	}
	assignments, _ := engine.RolloutAssignments("cand")
	if len(assignments) != 1 || assignments[0].Adopted || assignments[0].GroupID != "" {
		t.Fatalf("unexpected assignment: %+v", assignments)
	}
	info, _ := engine.RolloutInfo("cand")
	if info.Exposure != 0 {
		t.Fatalf("overlap must not consume exposure: %+v", info)
	}
}

func TestRolloutMissingAttributesKeepOriginal(t *testing.T) {
	engine := rolloutEngine(t)
	if err := engine.ApproveRollout("cand", betaPlan(10)); err != nil {
		t.Fatalf("ApproveRollout: %v", err)
	}
	// cohort attribute missing: membership cannot be determined.
	decision, err := engine.Adjudicate("cand", "req-1", map[string]any{"tier": "vip", "risk": 10})
	if err != nil {
		t.Fatalf("Adjudicate: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("unknown membership must keep original rules")
	}
	info, _ := engine.RolloutInfo("cand")
	if info.Exposure != 0 {
		t.Fatalf("unknown membership must not consume exposure: %+v", info)
	}
}

func TestRolloutProtectedScopeKeepsOriginal(t *testing.T) {
	engine := rolloutEngine(t)
	plan := betaPlan(10)
	plan.ProtectedScopes = []ProtectedScope{{
		ID:        "internal",
		Condition: &Condition{Field: "internal", Op: OpEqual, Value: true},
	}}
	if err := engine.ApproveRollout("cand", plan); err != nil {
		t.Fatalf("ApproveRollout: %v", err)
	}
	decision, err := engine.Adjudicate("cand", "req-1", map[string]any{
		"tier": "vip", "risk": 10, "cohort": "beta", "internal": true,
	})
	if err != nil {
		t.Fatalf("Adjudicate: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("protected scope must keep original rules")
	}
	info, _ := engine.RolloutInfo("cand")
	if info.Exposure != 0 {
		t.Fatalf("protected request must not consume exposure: %+v", info)
	}
}

func TestRolloutStopsOnFormalRuleChange(t *testing.T) {
	engine := rolloutEngine(t)
	if err := engine.ApproveRollout("cand", betaPlan(10)); err != nil {
		t.Fatalf("ApproveRollout: %v", err)
	}
	attrs := map[string]any{"tier": "vip", "risk": 10, "cohort": "beta"}
	adopted, _ := engine.Adjudicate("cand", "req-1", attrs)
	if adopted.Allowed {
		t.Fatalf("expected candidate deny before rule change")
	}
	if _, err := engine.PublishGroup(DefaultGroupID, []Rule{{
		ID:       "vip-allow-v2",
		Priority: 10,
		Effect:   EffectAllow,
		Condition: &Condition{All: []*Condition{
			{Field: "tier", Op: OpEqual, Value: "vip"},
		}},
	}}); err != nil {
		t.Fatalf("PublishGroup: %v", err)
	}
	info, _ := engine.RolloutInfo("cand")
	if info.Status != RolloutHalted {
		t.Fatalf("rule change must halt rollout, got %+v", info)
	}
	fresh, _ := engine.Adjudicate("cand", "req-2", attrs)
	if !fresh.Allowed {
		t.Fatalf("halted rollout must not adopt new requests")
	}
	replayed, _ := engine.Adjudicate("cand", "req-1", attrs)
	if replayed.Allowed {
		t.Fatalf("recorded candidate decision must be retained after rule change")
	}
}

func TestRolloutConcurrentArrivalRespectsQuota(t *testing.T) {
	engine := rolloutEngine(t)
	if err := engine.ApproveRollout("cand", betaPlan(5)); err != nil {
		t.Fatalf("ApproveRollout: %v", err)
	}
	attrs := map[string]any{"tier": "vip", "risk": 10, "cohort": "beta"}
	var wait sync.WaitGroup
	for index := 0; index < 50; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			if _, err := engine.Adjudicate("cand", fmt.Sprintf("req-%d", index), attrs); err != nil {
				t.Errorf("Adjudicate: %v", err)
			}
		}(index)
	}
	// Same request id arriving concurrently must resolve to one assignment.
	for index := 0; index < 20; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if _, err := engine.Adjudicate("cand", "req-dup", attrs); err != nil {
				t.Errorf("Adjudicate dup: %v", err)
			}
		}()
	}
	wait.Wait()
	info, _ := engine.RolloutInfo("cand")
	if info.Exposure > 5 {
		t.Fatalf("exposure exceeded quota: %+v", info)
	}
	if info.Status != RolloutHalted {
		t.Fatalf("rollout should halt once quota is exhausted: %+v", info)
	}
	assignments, _ := engine.RolloutAssignments("cand")
	seen := map[string]bool{}
	adopted := 0
	for _, assignment := range assignments {
		if seen[assignment.RequestID] {
			t.Fatalf("duplicate assignment for %q", assignment.RequestID)
		}
		seen[assignment.RequestID] = true
		if assignment.Adopted {
			adopted++
		}
	}
	if adopted != info.Exposure {
		t.Fatalf("adopted assignments %d != exposure %d", adopted, info.Exposure)
	}
}

func TestRolloutImpactClassifiesUnknown(t *testing.T) {
	engine := rolloutEngine(t)
	if _, err := engine.Observe("cand", "obs-unknown", map[string]any{"tier": "vip"}); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	impact, err := engine.ComputeRolloutImpact("cand")
	if err != nil {
		t.Fatalf("ComputeRolloutImpact: %v", err)
	}
	if len(impact.UnknownAffected) != 1 || impact.UnknownAffected[0] != "obs-unknown" {
		t.Fatalf("missing attribute should surface as unknown-affected: %+v", impact)
	}
	if len(impact.DenyChanges) != 0 {
		t.Fatalf("no explicit deny change expected: %+v", impact)
	}
}

func TestRolloutPlanValidation(t *testing.T) {
	engine := rolloutEngine(t)
	if err := engine.ApproveRollout("cand", RolloutPlan{MaxExposure: 0, TrialGroups: betaPlan(1).TrialGroups}); err == nil {
		t.Fatalf("expected max exposure validation error")
	}
	if err := engine.ApproveRollout("cand", RolloutPlan{MaxExposure: 1}); err == nil {
		t.Fatalf("expected missing trial group error")
	}
	overlappingIDs := RolloutPlan{
		MaxExposure: 1,
		TrialGroups: []TrialGroup{
			{ID: "a", Condition: &Condition{Field: "x", Op: OpEqual, Value: 1}},
			{ID: "a", Condition: &Condition{Field: "y", Op: OpEqual, Value: 1}},
		},
	}
	if err := engine.ApproveRollout("cand", overlappingIDs); err == nil {
		t.Fatalf("expected duplicate group id error")
	}
	withRef := RolloutPlan{
		MaxExposure: 1,
		TrialGroups: []TrialGroup{
			{ID: "a", Condition: &Condition{Ref: "other"}},
		},
	}
	if err := engine.ApproveRollout("cand", withRef); err == nil {
		t.Fatalf("expected ref rejection in scope conditions")
	}
}
