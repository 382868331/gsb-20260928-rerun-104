package policy

import (
	"reflect"
	"testing"
)

func observationGroups() []RuleGroup {
	return []RuleGroup{
		{
			ID:       "risk",
			Priority: 100,
			Rules: []Rule{
				{ID: "risk-high-deny", Effect: EffectDeny, Condition: field("risk", OpEqual, "high")},
			},
		},
		{
			ID:       "vip",
			Priority: 10,
			Rules: []Rule{
				{ID: "vip-allow", Effect: EffectAllow, Condition: field("tier", OpEqual, "vip")},
			},
		},
	}
}

func candidateRiskLowDeny() []RuleGroup {
	groups := observationGroups()
	groups[0].Rules[0].Condition = field("risk", OpEqual, "low")
	return groups
}

func TestObserveKeepsFormalAdjudicationAndRecordsBothSides(t *testing.T) {
	engine, err := NewEngineGroups(observationGroups())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.OpenCandidate("c1", candidateRiskLowDeny()); err != nil {
		t.Fatal(err)
	}

	attrs := map[string]any{"risk": "low", "tier": "vip"}
	formal, record, err := engine.Observe("c1", SavedRequest{ID: "req-1", Attributes: attrs})
	if err != nil {
		t.Fatal(err)
	}

	// Only current rules adjudicate: low risk is not denied by formal risk group.
	if !formal.Allowed || formal.Evidence.Rule.ID != "vip-allow" {
		t.Fatalf("formal decision must come from current rules, got %+v", formal)
	}
	if engine.Version() != 1 {
		t.Fatalf("observation must not publish candidate, version=%d", engine.Version())
	}
	// Candidate would deny on low risk.
	if record.Candidate.Allowed || record.Candidate.Evidence.Rule.ID != "risk-high-deny" {
		t.Fatalf("candidate shadow verdict should deny, got %+v", record.Candidate)
	}
	if !record.Changed || record.Kind != ObservationExplicitChange || !record.ExplicitDenyChanged {
		t.Fatalf("explicit allow->deny change mislabeled: %+v", record)
	}
	if len(record.Formal.Contributions) != 2 || len(record.Candidate.Contributions) != 2 {
		t.Fatalf("both sides must retain group contributions: %+v", record)
	}
	if record.Formal.Contributions[0].Verdict != GroupUnknown || record.Candidate.Contributions[0].Verdict != GroupDeny {
		t.Fatalf("risk contribution should be unknown formally but deny in candidate: %+v %+v", record.Formal.Contributions, record.Candidate.Contributions)
	}
}

func TestObserveDeepCopiesAttributesAndExportCannotRewriteHistory(t *testing.T) {
	engine, _ := NewEngineGroups(observationGroups())
	if _, err := engine.OpenCandidate("c1", candidateRiskLowDeny()); err != nil {
		t.Fatal(err)
	}
	request := SavedRequest{ID: "req-1", Attributes: map[string]any{"risk": "high"}}
	if _, _, err := engine.Observe("c1", request); err != nil {
		t.Fatal(err)
	}

	// Mutate caller data after observation.
	request.Attributes["risk"] = "low"
	request.Attributes["injected"] = true

	records, err := engine.Observations("c1")
	if err != nil {
		t.Fatal(err)
	}
	if records[0].Attributes["risk"] != "high" {
		t.Fatalf("stored attributes were mutated: %+v", records[0].Attributes)
	}
	if _, exists := records[0].Attributes["injected"]; exists {
		t.Fatalf("post-hoc attribute injection rewrote history: %+v", records[0].Attributes)
	}

	// Mutating an exported record must not affect a subsequent export.
	records[0].Attributes["risk"] = "tampered"
	records[0].Formal.Allowed = true
	again, _ := engine.Observations("c1")
	if again[0].Attributes["risk"] != "high" || again[0].Formal.Allowed {
		t.Fatalf("query/export rewrote historical facts: %+v", again[0])
	}
}

func TestOtherGroupCanChangeAndStaleRecordsAreMarked(t *testing.T) {
	engine, _ := NewEngineGroups(observationGroups())
	// Candidate changes only the risk group; vip stays as formal.
	if _, err := engine.OpenCandidateGroup("c1", "risk", candidateRiskLowDeny()[0].Rules); err != nil {
		t.Fatal(err)
	}
	if _, _, err := engine.Observe("c1", SavedRequest{ID: "req-1", Attributes: map[string]any{"risk": "low"}}); err != nil {
		t.Fatal(err)
	}

	// During observation, a different independent group (vip) is adjusted.
	newGroups := observationGroups()
	newGroups[1].Rules[0].Condition = field("tier", OpEqual, "platinum")
	if _, err := engine.PublishGroups(newGroups); err != nil {
		t.Fatal(err)
	}

	records, _ := engine.Observations("c1")
	if !records[0].Stale || !reflect.DeepEqual(records[0].ChangedDependencies, []string{"vip"}) {
		t.Fatalf("record must be marked stale with changed dependency vip, got %+v", records[0])
	}
	// Historical verdicts themselves stay frozen at their original values.
	if records[0].Formal.Version != 1 {
		t.Fatalf("historical verdict must not be rewritten, got version %d", records[0].Formal.Version)
	}
	if _, _, err := engine.PublishCandidate("c1"); err == nil {
		t.Fatal("publishing an expired conclusion must be rejected")
	}

	// A fresh observation against the new formal vip removes staleness for new evidence.
	if _, _, err := engine.Observe("c1", SavedRequest{ID: "req-2", Attributes: map[string]any{"risk": "low", "tier": "platinum"}}); err != nil {
		t.Fatal(err)
	}
	records, _ = engine.Observations("c1")
	if records[1].Stale {
		t.Fatalf("new record should be fresh, got %+v", records[1])
	}
	if _, _, err := engine.PublishCandidate("c1"); err == nil {
		t.Fatal("any stale record must still block publication")
	}
}

func TestTwoCandidatesCompareOnSameRequestsAndSeparateUnknown(t *testing.T) {
	engine, _ := NewEngineGroups(observationGroups())

	// Candidate A: denies low risk (explicit change).
	if _, err := engine.OpenCandidate("a", candidateRiskLowDeny()); err != nil {
		t.Fatal(err)
	}
	// Candidate B: allows based on a not-yet-available "score" attribute.
	groupsB := observationGroups()
	groupsB[0].Rules = []Rule{{ID: "score-gate", Effect: EffectAllow, Condition: field("score", OpAtLeast, 80)}}
	if _, err := engine.OpenCandidate("b", groupsB); err != nil {
		t.Fatal(err)
	}

	batch := []SavedRequest{
		{ID: "explicit", Attributes: map[string]any{"risk": "low", "tier": "vip"}},
		// A denies explicitly on low risk; B has no score and no tier, so all
		// its groups stay unknown. The difference is driven by missing info.
		{ID: "unknown", Attributes: map[string]any{"risk": "low"}},
	}
	report, err := engine.CompareCandidates("a", "b", batch)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Requests) != 2 || report.ChangedRequests != 2 {
		t.Fatalf("expected both comparisons, got %+v", report)
	}
	if report.Requests[0].Kind != ObservationExplicitChange || !report.Requests[0].ExplicitDenyChanged {
		t.Fatalf("low-risk case is an explicit deny change, got %+v", report.Requests[0])
	}
	if report.Requests[1].Kind != ObservationUnknownChange || report.Requests[1].ExplicitDenyChanged {
		t.Fatalf("missing score must be unknown-driven, got %+v", report.Requests[1])
	}
}

func TestAbandonKeepsExplanationAndReopenReusesState(t *testing.T) {
	engine, _ := NewEngineGroups(observationGroups())
	if _, err := engine.OpenCandidate("c1", candidateRiskLowDeny()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := engine.Observe("c1", SavedRequest{ID: "req-1", Attributes: map[string]any{"risk": "low"}}); err != nil {
		t.Fatal(err)
	}
	if err := engine.AbandonCandidate("c1", "missing edge case coverage"); err != nil {
		t.Fatal(err)
	}
	if info, _ := engine.Candidate("c1"); info.Status != CandidateAbandoned || len(info.Abandonments) != 1 {
		t.Fatalf("abandonment not recorded: %+v", info)
	}
	// Records remain available after abandonment.
	records, _ := engine.Observations("c1")
	if len(records) != 1 {
		t.Fatalf("abandonment must retain explanatory records, got %d", len(records))
	}
	if _, _, err := engine.Observe("c1", SavedRequest{ID: "x", Attributes: map[string]any{}}); err == nil {
		t.Fatal("abandoned candidate must not accept new observations")
	}

	// Reopen with the same definition keeps confirmed observations and state.
	reopened, err := engine.OpenCandidate("c1", candidateRiskLowDeny())
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Status != CandidateObserving || reopened.ObservationCount != 1 || len(reopened.Abandonments) != 1 {
		t.Fatalf("reopen must carry observations and abandonment: %+v", reopened)
	}
	if _, err := engine.OpenCandidate("c1", observationGroups()); err == nil {
		t.Fatal("redefining an existing candidate id must be rejected")
	}
}

func TestPublishCandidateDocumentsActualBasisRange(t *testing.T) {
	engine, _ := NewEngineGroups(observationGroups())
	if _, err := engine.OpenCandidate("c1", candidateRiskLowDeny()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := engine.Observe("c1", SavedRequest{ID: "req-1", Attributes: map[string]any{"risk": "low"}}); err != nil {
		t.Fatal(err)
	}
	// Another formal release that does not change group content keeps evidence fresh.
	if _, err := engine.PublishGroups(observationGroups()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := engine.Observe("c1", SavedRequest{ID: "req-2", Attributes: map[string]any{"risk": "low", "tier": "vip"}}); err != nil {
		t.Fatal(err)
	}
	if err := engine.AbandonCandidate("c1", "first attempt parked"); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.ReopenCandidate("c1"); err != nil {
		t.Fatal(err)
	}
	set, basis, err := engine.PublishCandidate("c1")
	if err != nil {
		t.Fatal(err)
	}
	if set == nil || len(basis.RecordIDs) != 2 {
		t.Fatalf("basis must list the two fresh records: %+v", basis)
	}
	if basis.FormalVersionRange != [2]int{1, 2} {
		t.Fatalf("basis range should span formal versions 1..2, got %v", basis.FormalVersionRange)
	}
	if len(basis.PreviouslyAbandoned) != 1 {
		t.Fatalf("prior abandonment must travel into the release basis: %+v", basis)
	}
	last := engine.History()[len(engine.History())-1]
	if last.Basis == nil || last.Basis.CandidateID != "c1" {
		t.Fatalf("release record must document the adopted basis: %+v", last)
	}

	// The new formal version now denies low risk as observed.
	d := engine.Evaluate(map[string]any{"risk": "low"})
	if d.Allowed || d.Evidence.Rule.ID != "risk-high-deny" {
		t.Fatalf("candidate should now be the formal rule, got %+v", d)
	}
}

func TestPublishRequiresObservations(t *testing.T) {
	engine, _ := NewEngineGroups(observationGroups())
	if _, err := engine.OpenCandidate("empty", candidateRiskLowDeny()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := engine.PublishCandidate("empty"); err == nil {
		t.Fatal("candidate without observations must not publish")
	}
}

func TestObserveRunsConcurrentlyWithEvaluationAndPublishing(t *testing.T) {
	engine, _ := NewEngineGroups(observationGroups())
	if _, err := engine.OpenCandidate("c1", candidateRiskLowDeny()); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for index := 0; index < 100; index++ {
			engine.Evaluate(map[string]any{"risk": "high"})
		}
	}()
	for index := 0; index < 100; index++ {
		if _, _, err := engine.Observe("c1", SavedRequest{
			ID:         "req",
			Attributes: map[string]any{"risk": "low"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	<-done
	records, _ := engine.Observations("c1")
	if len(records) != 100 {
		t.Fatalf("expected 100 frozen records, got %d", len(records))
	}
}
