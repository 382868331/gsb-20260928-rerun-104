package policy

import (
	"fmt"
	"sync"
	"testing"
)

func rolloutSpec(candidateID string, maxExposure int) ScopedRolloutSpec {
	return ScopedRolloutSpec{
		CandidateID: candidateID,
		Groups: []TrialGroup{
			{ID: "beta", Condition: field("segment", OpEqual, "beta")},
			{ID: "internal", Condition: field("segment", OpEqual, "internal")},
		},
		Reserved: []TrialGroup{
			{ID: "payments", Condition: field("channel", OpEqual, "payment")},
		},
		MaxExposure: maxExposure,
	}
}

func newRolloutEngine(t *testing.T) *Engine {
	t.Helper()
	engine := newObservedEngine(t)
	if _, err := engine.Observe("cand-1", "obs-beta", map[string]any{"segment": "beta", "risk": "med", "tier": "vip"}); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Observe("cand-1", "obs-internal", map[string]any{"segment": "internal", "risk": "med"}); err != nil {
		t.Fatal(err)
	}
	if err := engine.ConfirmObservations("cand-1"); err != nil {
		t.Fatal(err)
	}
	return engine
}

func TestPlanScopedRolloutComputesImpactsFromValidObservations(t *testing.T) {
	engine := newRolloutEngine(t)

	plan, err := engine.PlanScopedRollout(rolloutSpec("cand-1", 10))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Eligible) != 2 {
		t.Fatalf("expected 2 eligible requests, got %v", plan.Eligible)
	}
	if len(plan.Impacts) != 2 {
		t.Fatalf("expected 2 impacts, got %+v", plan.Impacts)
	}
	kinds := map[string]DifferenceKind{}
	for _, impact := range plan.Impacts {
		kinds[impact.RequestID] = impact.Kind
	}
	if kinds["obs-beta"] != DifferenceExplicitDeny {
		t.Fatalf("expected deny change for obs-beta, got %s", kinds["obs-beta"])
	}
	if kinds["obs-internal"] != DifferenceUnknownDriven {
		t.Fatalf("expected unknown difference for obs-internal, got %s", kinds["obs-internal"])
	}
}

func TestAdjudicateOnlyAfterApprovalAndWithinScope(t *testing.T) {
	engine := newRolloutEngine(t)
	if _, err := engine.PlanScopedRollout(rolloutSpec("cand-1", 10)); err != nil {
		t.Fatal(err)
	}

	attrs := map[string]any{"segment": "beta", "risk": "med", "tier": "vip"}
	decision, err := engine.Adjudicate("cand-1", "req-1", attrs)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed {
		t.Fatal("before approval the original rules must adjudicate")
	}

	if err := engine.ApproveScopedRollout("cand-1"); err != nil {
		t.Fatal(err)
	}
	decision, err = engine.Adjudicate("cand-1", "req-2", attrs)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed || decision.Evidence.Rule.ID != "risk-med-deny" {
		t.Fatalf("eligible request must be adjudicated by the candidate, got %+v", decision)
	}

	reserved, err := engine.Adjudicate("cand-1", "req-3", map[string]any{"segment": "beta", "channel": "payment", "risk": "med", "tier": "vip"})
	if err != nil {
		t.Fatal(err)
	}
	if !reserved.Allowed {
		t.Fatal("reserved scope must keep the original rules")
	}

	unknown, err := engine.Adjudicate("cand-1", "req-4", map[string]any{"risk": "med", "tier": "vip"})
	if err != nil {
		t.Fatal(err)
	}
	if !unknown.Allowed {
		t.Fatal("request without a matching trial group must keep the original rules")
	}

	records, err := engine.RolloutRecords("cand-1")
	if err != nil {
		t.Fatal(err)
	}
	byRequest := map[string]RolloutRecord{}
	for _, record := range records {
		byRequest[record.RequestID] = record
	}
	if byRequest["req-2"].AdjudicatedBy != AdjudicatedByCandidate || byRequest["req-2"].GroupID != "beta" {
		t.Fatalf("req-2 attribution wrong: %+v", byRequest["req-2"])
	}
	for _, id := range []string{"req-1", "req-3", "req-4"} {
		if byRequest[id].AdjudicatedBy != AdjudicatedByOriginal {
			t.Fatalf("%s must be attributed to original rules: %+v", id, byRequest[id])
		}
	}
}

func TestAdjudicateRepeatRequestIsIdempotent(t *testing.T) {
	engine := newRolloutEngine(t)
	if _, err := engine.PlanScopedRollout(rolloutSpec("cand-1", 10)); err != nil {
		t.Fatal(err)
	}
	if err := engine.ApproveScopedRollout("cand-1"); err != nil {
		t.Fatal(err)
	}

	attrs := map[string]any{"segment": "beta", "risk": "med", "tier": "vip"}
	first, err := engine.Adjudicate("cand-1", "req-1", attrs)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		again, err := engine.Adjudicate("cand-1", "req-1", attrs)
		if err != nil {
			t.Fatal(err)
		}
		if again.Allowed != first.Allowed || again.Evidence.Rule.ID != first.Evidence.Rule.ID {
			t.Fatalf("repeat adjudication changed: %+v vs %+v", first, again)
		}
	}
	infos := engine.RolloutInfos()
	if len(infos) != 1 || infos[0].Exposure != 1 {
		t.Fatalf("repeats must not increase exposure, got %+v", infos)
	}
}

func TestOverlappingTrialGroupsFallBackToOriginal(t *testing.T) {
	engine := newRolloutEngine(t)
	spec := rolloutSpec("cand-1", 10)
	spec.Groups = append(spec.Groups, TrialGroup{ID: "also-beta", Condition: field("segment", OpEqual, "beta")})

	plan, err := engine.PlanScopedRollout(spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Conflicts) != 1 || plan.Conflicts[0] != "obs-beta" {
		t.Fatalf("expected obs-beta as conflict, got %+v", plan.Conflicts)
	}
	if err := engine.ApproveScopedRollout("cand-1"); err != nil {
		t.Fatal(err)
	}
	decision, err := engine.Adjudicate("cand-1", "req-1", map[string]any{"segment": "beta", "risk": "med", "tier": "vip"})
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed {
		t.Fatal("confusable request must keep the original rules")
	}
	if info := engine.RolloutInfos()[0]; info.Exposure != 0 {
		t.Fatalf("conflicts must not consume exposure, got %d", info.Exposure)
	}
}

func TestExposureQuotaStopsNewAdoptions(t *testing.T) {
	engine := newRolloutEngine(t)
	if _, err := engine.PlanScopedRollout(rolloutSpec("cand-1", 1)); err != nil {
		t.Fatal(err)
	}
	if err := engine.ApproveScopedRollout("cand-1"); err != nil {
		t.Fatal(err)
	}
	attrs := map[string]any{"segment": "beta", "risk": "med", "tier": "vip"}
	first, err := engine.Adjudicate("cand-1", "req-1", attrs)
	if err != nil {
		t.Fatal(err)
	}
	if first.Allowed {
		t.Fatal("first request should be adjudicated by the candidate")
	}
	second, err := engine.Adjudicate("cand-1", "req-2", attrs)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Allowed {
		t.Fatal("quota exhausted: new requests must keep the original rules")
	}
	info := engine.RolloutInfos()[0]
	if info.Status != RolloutHalted || info.Exposure != 1 {
		t.Fatalf("expected halted rollout with exposure 1, got %+v", info)
	}
}

func TestDependencyChangeHaltsRolloutButRetainsAdjudications(t *testing.T) {
	engine := newRolloutEngine(t)
	if _, err := engine.PlanScopedRollout(rolloutSpec("cand-1", 10)); err != nil {
		t.Fatal(err)
	}
	if err := engine.ApproveScopedRollout("cand-1"); err != nil {
		t.Fatal(err)
	}
	attrs := map[string]any{"segment": "beta", "risk": "med", "tier": "vip"}
	before, err := engine.Adjudicate("cand-1", "req-1", attrs)
	if err != nil {
		t.Fatal(err)
	}
	if before.Allowed {
		t.Fatal("expected candidate adjudication before the dependency change")
	}

	if _, err := engine.PublishGroup("vip", []Rule{
		{ID: "vip-allow", Effect: EffectAllow, Condition: field("tier", OpEqual, "vip")},
	}); err != nil {
		t.Fatal(err)
	}

	after, err := engine.Adjudicate("cand-1", "req-2", attrs)
	if err != nil {
		t.Fatal(err)
	}
	if !after.Allowed {
		t.Fatal("after a dependency change new requests must keep the original rules")
	}
	retained, err := engine.Adjudicate("cand-1", "req-1", attrs)
	if err != nil {
		t.Fatal(err)
	}
	if retained.Allowed || retained.Evidence.Rule.ID != "risk-med-deny" {
		t.Fatalf("past adjudication must be retained, got %+v", retained)
	}
	if info := engine.RolloutInfos()[0]; info.Status != RolloutHalted {
		t.Fatalf("expected halted rollout, got %+v", info)
	}
}

func TestWithdrawRolloutStopsAdoptions(t *testing.T) {
	engine := newRolloutEngine(t)
	if _, err := engine.PlanScopedRollout(rolloutSpec("cand-1", 10)); err != nil {
		t.Fatal(err)
	}
	if err := engine.ApproveScopedRollout("cand-1"); err != nil {
		t.Fatal(err)
	}
	if err := engine.WithdrawRollout("cand-1", "emergency: fraud spike"); err != nil {
		t.Fatal(err)
	}
	decision, err := engine.Adjudicate("cand-1", "req-1", map[string]any{"segment": "beta", "risk": "med", "tier": "vip"})
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed {
		t.Fatal("withdrawn rollout must leave requests on the original rules")
	}
	info := engine.RolloutInfos()[0]
	if info.Status != RolloutWithdrawn || info.Reason != "emergency: fraud spike" {
		t.Fatalf("unexpected rollout info %+v", info)
	}
}

func TestConcurrentAdjudicationKeepsAttributionAndQuota(t *testing.T) {
	engine := newRolloutEngine(t)
	if _, err := engine.PlanScopedRollout(rolloutSpec("cand-1", 5)); err != nil {
		t.Fatal(err)
	}
	if err := engine.ApproveScopedRollout("cand-1"); err != nil {
		t.Fatal(err)
	}

	var wait sync.WaitGroup
	decisions := make([]Decision, 40)
	for i := range decisions {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			id := "req-shared"
			if index >= 20 {
				id = fmt.Sprintf("req-%d", index)
			}
			decision, err := engine.Adjudicate("cand-1", id, map[string]any{"segment": "beta", "risk": "med", "tier": "vip"})
			if err != nil {
				t.Error(err)
				return
			}
			decisions[index] = decision
		}(i)
	}
	wait.Wait()

	for i := 0; i < 20; i++ {
		if decisions[i].Allowed || decisions[i].Evidence.Rule.ID != "risk-med-deny" {
			t.Fatalf("shared request got divergent adjudication at %d: %+v", i, decisions[i])
		}
	}
	info := engine.RolloutInfos()[0]
	if info.Exposure > 5 {
		t.Fatalf("exposure %d exceeds quota 5", info.Exposure)
	}
	candidateCount := 0
	for i := 20; i < 40; i++ {
		if !decisions[i].Allowed {
			candidateCount++
		}
	}
	if info.Exposure != 1+candidateCount {
		t.Fatalf("exposure %d does not match distinct candidate adjudications %d", info.Exposure, 1+candidateCount)
	}
}
