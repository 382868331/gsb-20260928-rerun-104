package policy

import "testing"

func observeEngine(t *testing.T) *Engine {
	t.Helper()
	engine, err := NewEngineGroups([]RuleGroup{
		{ID: "risk", Priority: 10, Rules: []Rule{{
			ID: "deny-high", Priority: 10, Effect: EffectDeny,
			Condition: &Condition{Field: "risk", Op: OpEqual, Value: "high"},
		}}},
		{ID: "tier", Priority: 5, Rules: []Rule{{
			ID: "allow-vip", Priority: 5, Effect: EffectAllow,
			Condition: &Condition{Field: "tier", Op: OpEqual, Value: "vip"},
		}}},
	})
	if err != nil {
		t.Fatalf("NewEngineGroups: %v", err)
	}
	return engine
}

func TestObserveShadowNeverAdjudicates(t *testing.T) {
	engine := observeEngine(t)
	err := engine.StartObservation("cand", []RuleGroup{{ID: "tier", Priority: 5, Rules: []Rule{{
		ID: "allow-all", Priority: 100, Effect: EffectAllow,
		Condition: &Condition{Field: "tier", Op: OpExists},
	}}}})
	if err != nil {
		t.Fatalf("StartObservation: %v", err)
	}

	decision := engine.Observe(map[string]any{"tier": "gold"})
	if decision.Allowed {
		t.Fatalf("authoritative decision must stay denied, got %+v", decision)
	}
	records, err := engine.ExplainCandidate("cand")
	if err != nil {
		t.Fatalf("ExplainCandidate: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	record := records[0]
	if decision.Allowed {
		t.Fatalf("unmatched request must stay denied, got %+v", decision)
	}
	if !record.Candidate.Allowed {
		t.Fatalf("shadow candidate should allow, got %+v", record.Candidate)
	}
	if !record.Changed || record.Difference != DifferenceVerdict {
		t.Fatalf("expected verdict_change, got %v (changed=%v)", record.Difference, record.Changed)
	}
	if record.Attributes["tier"] != "gold" {
		t.Fatalf("attributes not preserved: %+v", record.Attributes)
	}
	if len(record.Current.Contributions) != 2 || len(record.Candidate.Contributions) != 2 {
		t.Fatalf("group contributions missing: %+v", record)
	}
	if len(record.Causes) == 0 {
		t.Fatalf("expected attribution causes")
	}
}

func TestObserveClassifiesUnknownDrivenChange(t *testing.T) {
	engine := observeEngine(t)
	err := engine.StartObservation("cand", []RuleGroup{{ID: "tier", Priority: 5, Rules: []Rule{{
		ID: "deny-unknown-region", Priority: 20, Effect: EffectDeny,
		Condition: &Condition{Field: "region", Op: OpEqual, Value: "eu"},
	}}}})
	if err != nil {
		t.Fatalf("StartObservation: %v", err)
	}
	engine.Observe(map[string]any{"tier": "vip"})
	records, _ := engine.ExplainCandidate("cand")
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Difference != DifferenceUnknown {
		t.Fatalf("expected unknown_change, got %v", records[0].Difference)
	}
}

func TestDependedGroupChangeStalesObservations(t *testing.T) {
	engine := observeEngine(t)
	if err := engine.StartObservation("cand", []RuleGroup{{ID: "tier", Priority: 5, Rules: []Rule{{
		ID: "allow-vip2", Priority: 5, Effect: EffectAllow,
		Condition: &Condition{Field: "tier", Op: OpEqual, Value: "vip"},
	}}}}); err != nil {
		t.Fatalf("StartObservation: %v", err)
	}
	engine.Observe(map[string]any{"tier": "vip"})

	// Adjust another group the candidate depends on.
	if _, err := engine.PublishGroup("risk", []Rule{{
		ID: "deny-high", Priority: 10, Effect: EffectDeny,
		Condition: &Condition{Field: "risk", Op: OpEqual, Value: "critical"},
	}}); err != nil {
		t.Fatalf("PublishGroup: %v", err)
	}

	records, _ := engine.ExplainCandidate("cand")
	if !records[0].Stale {
		t.Fatalf("record should be stale after depended group changed")
	}
	if records[0].StaleReason == "" {
		t.Fatalf("stale reason should name the changed groups")
	}
	if _, err := engine.PublishCandidate("cand"); err == nil {
		t.Fatalf("publishing from stale conclusions only must fail")
	}

	// Fresh observation after the change resumes a clean basis.
	engine.Observe(map[string]any{"tier": "vip"})
	set, err := engine.PublishCandidate("cand")
	if err != nil {
		t.Fatalf("PublishCandidate after fresh observation: %v", err)
	}
	history := engine.History()
	last := history[len(history)-1]
	if last.Basis == nil || last.Basis.CandidateID != "cand" {
		t.Fatalf("release record must carry the observation basis: %+v", last)
	}
	if last.Basis.StaleExcluded != 1 || last.Basis.RecordCount != 1 {
		t.Fatalf("basis should exclude stale records: %+v", last.Basis)
	}
	if last.Basis.FromSequence != 2 || last.Basis.ToSequence != 2 {
		t.Fatalf("basis range should cover only the fresh record: %+v", last.Basis)
	}
	if set.Version() != last.Version {
		t.Fatalf("published set version mismatch")
	}
}

func TestCompareCandidatesOnSharedHistory(t *testing.T) {
	engine := observeEngine(t)
	allowVip := []RuleGroup{{ID: "tier", Priority: 5, Rules: []Rule{{
		ID: "allow-vip", Priority: 5, Effect: EffectAllow,
		Condition: &Condition{Field: "tier", Op: OpEqual, Value: "vip"},
	}}}}
	denyVip := []RuleGroup{{ID: "tier", Priority: 5, Rules: []Rule{{
		ID: "deny-vip", Priority: 5, Effect: EffectDeny,
		Condition: &Condition{Field: "tier", Op: OpEqual, Value: "vip"},
	}}}}
	if err := engine.StartObservation("a", allowVip); err != nil {
		t.Fatalf("StartObservation a: %v", err)
	}
	if err := engine.StartObservation("b", denyVip); err != nil {
		t.Fatalf("StartObservation b: %v", err)
	}
	engine.Observe(map[string]any{"tier": "vip"})

	report, err := engine.CompareCandidates("a", "b")
	if err != nil {
		t.Fatalf("CompareCandidates: %v", err)
	}
	if report.ChangedRequests == 0 {
		t.Fatalf("candidates should diverge on the shared history")
	}
	for _, entry := range report.Requests {
		if entry.First.Effect == entry.Second.Effect && entry.Changed {
			t.Fatalf("inconsistent comparison entry: %+v", entry)
		}
	}
}

func TestAbandonedCandidateStaysExplainable(t *testing.T) {
	engine := observeEngine(t)
	if err := engine.StartObservation("cand", []RuleGroup{{ID: "tier", Priority: 5, Rules: []Rule{{
		ID: "allow-all", Priority: 100, Effect: EffectAllow,
		Condition: &Condition{Field: "tier", Op: OpExists},
	}}}}); err != nil {
		t.Fatalf("StartObservation: %v", err)
	}
	engine.Observe(map[string]any{"risk": "high", "tier": "vip"})
	if err := engine.AbandonCandidate("cand"); err != nil {
		t.Fatalf("AbandonCandidate: %v", err)
	}
	engine.Observe(map[string]any{"tier": "vip"})
	records, err := engine.ExplainCandidate("cand")
	if err != nil {
		t.Fatalf("abandoned candidate must stay explainable: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("abandoned candidate must stop recording, got %d records", len(records))
	}
	if _, err := engine.PublishCandidate("cand"); err == nil {
		t.Fatalf("abandoned candidate must not publish")
	}
}

func TestResumeObservationContinuesBasis(t *testing.T) {
	engine := observeEngine(t)
	candidate := []RuleGroup{{ID: "tier", Priority: 5, Rules: []Rule{{
		ID: "allow-vip", Priority: 5, Effect: EffectAllow,
		Condition: &Condition{Field: "tier", Op: OpEqual, Value: "vip"},
	}}}}
	if err := engine.StartObservation("cand", candidate); err != nil {
		t.Fatalf("StartObservation: %v", err)
	}
	engine.Observe(map[string]any{"tier": "vip"})
	snapshot, err := engine.ExportObservation("cand")
	if err != nil {
		t.Fatalf("ExportObservation: %v", err)
	}
	if err := engine.AbandonCandidate("cand"); err != nil {
		t.Fatalf("AbandonCandidate: %v", err)
	}

	// Simulate a restart: resume onto a fresh engine with the same rules.
	restarted := observeEngine(t)
	if err := restarted.ResumeObservation(snapshot); err != nil {
		t.Fatalf("ResumeObservation: %v", err)
	}
	restarted.Observe(map[string]any{"tier": "vip"})
	if _, err := restarted.PublishCandidate("cand"); err != nil {
		t.Fatalf("PublishCandidate after resume: %v", err)
	}
	history := restarted.History()
	basis := history[len(history)-1].Basis
	if basis == nil {
		t.Fatalf("basis missing after resume")
	}
	if basis.RecordCount != 2 || basis.FromSequence != 1 || basis.ToSequence != 2 {
		t.Fatalf("resumed basis should cover the full sequence range: %+v", basis)
	}
}
