package policy

import (
	"strings"
	"testing"
)

func observationBaseGroups() []RuleGroup {
	return []RuleGroup{
		{ID: "risk", Priority: 100, Rules: []Rule{
			{ID: "risk-high-deny", Effect: EffectDeny, Condition: field("risk", OpEqual, "high")},
		}},
		{ID: "vip", Priority: 10, Rules: []Rule{
			{ID: "vip-allow", Effect: EffectAllow, Condition: field("tier", OpEqual, "vip")},
		}},
	}
}

func observationCandidateGroups() []RuleGroup {
	return []RuleGroup{
		{ID: "risk", Priority: 100, Rules: []Rule{
			{ID: "risk-high-deny", Effect: EffectDeny, Condition: field("risk", OpEqual, "high")},
			{ID: "risk-med-deny", Effect: EffectDeny, Condition: field("risk", OpEqual, "med")},
		}},
		{ID: "vip", Priority: 10, Rules: []Rule{
			{ID: "vip-allow", Effect: EffectAllow, Condition: field("tier", OpEqual, "vip")},
		}},
	}
}

func newObservedEngine(t *testing.T) *Engine {
	t.Helper()
	engine, err := NewEngineGroups(observationBaseGroups())
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.StartObservation("cand-1", observationCandidateGroups()); err != nil {
		t.Fatal(err)
	}
	return engine
}

func TestObserveRecordsBothSidesAndOnlyCurrentAdjudicates(t *testing.T) {
	engine := newObservedEngine(t)

	decision, err := engine.Observe("cand-1", "req-1", map[string]any{"risk": "med", "tier": "vip"})
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed || decision.Evidence.Rule.ID != "vip-allow" {
		t.Fatalf("business adjudication must come from current rules, got %+v", decision)
	}

	records, err := engine.ObservationRecords("cand-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("expected one record, got %d", len(records))
	}
	record := records[0]
	if !record.Current.Allowed || record.Candidate.Allowed || record.Candidate.Evidence.Rule.ID != "risk-med-deny" {
		t.Fatalf("expected current allow vs candidate deny, got %+v", record)
	}
	if len(record.Current.Contributions) != 2 || len(record.Candidate.Contributions) != 2 {
		t.Fatalf("expected group contributions on both sides, got %+v", record)
	}
	if record.Candidate.Contributions[0].Verdict != GroupDeny {
		t.Fatalf("expected candidate risk group deny contribution, got %+v", record.Candidate.Contributions[0])
	}
}

func TestObservationRecordsKeepRequestTimeAttributesAndStayImmutable(t *testing.T) {
	engine := newObservedEngine(t)
	attrs := map[string]any{"risk": "med", "tier": "vip"}
	if _, err := engine.Observe("cand-1", "req-1", attrs); err != nil {
		t.Fatal(err)
	}
	attrs["risk"] = "low"

	records, err := engine.ObservationRecords("cand-1")
	if err != nil {
		t.Fatal(err)
	}
	if records[0].Attributes["risk"] != "med" {
		t.Fatalf("record must keep request-time attributes, got %+v", records[0].Attributes)
	}

	// Mutating the exported copy must not rewrite stored history.
	records[0].Attributes["risk"] = "low"
	records[0].Candidate.Effect = EffectAllow
	records[0].Stale = true
	again, err := engine.ObservationRecords("cand-1")
	if err != nil {
		t.Fatal(err)
	}
	if again[0].Attributes["risk"] != "med" || again[0].Candidate.Effect != EffectDeny || again[0].Stale {
		t.Fatalf("exported copies must be isolated from stored records, got %+v", again[0])
	}
}

func TestFormalChangesMarkObservationRecordsStale(t *testing.T) {
	engine := newObservedEngine(t)
	if _, err := engine.Observe("cand-1", "req-1", map[string]any{"risk": "med", "tier": "vip"}); err != nil {
		t.Fatal(err)
	}
	if err := engine.ConfirmObservations("cand-1"); err != nil {
		t.Fatal(err)
	}

	// Other rule groups may still be adjusted during the observation period.
	if _, err := engine.PublishGroup("vip", []Rule{
		{ID: "vip-allow", Effect: EffectAllow, Condition: field("tier", OpEqual, "vip")},
	}); err != nil {
		t.Fatal(err)
	}

	records, err := engine.ObservationRecords("cand-1")
	if err != nil {
		t.Fatal(err)
	}
	if !records[0].Stale || records[0].StaleReason == "" {
		t.Fatalf("expected record marked stale after dependency change, got %+v", records[0])
	}
	if _, err := engine.PublishObservation("cand-1"); err == nil ||
		!strings.Contains(err.Error(), "stale") {
		t.Fatalf("stale conclusions must not publish directly, got %v", err)
	}
}

func TestCandidateUpdateMarksRecordsStale(t *testing.T) {
	engine := newObservedEngine(t)
	if _, err := engine.Observe("cand-1", "req-1", map[string]any{"risk": "med"}); err != nil {
		t.Fatal(err)
	}
	if err := engine.UpdateObservationCandidate("cand-1", observationBaseGroups()); err != nil {
		t.Fatal(err)
	}
	records, err := engine.ObservationRecords("cand-1")
	if err != nil {
		t.Fatal(err)
	}
	if !records[0].Stale {
		t.Fatalf("candidate dependency change must stale prior records, got %+v", records[0])
	}
	if err := engine.ConfirmObservations("cand-1"); err == nil {
		t.Fatal("stale records must not be confirmable")
	}
}

func TestCompareObservationsDistinguishesDenyFromUnknown(t *testing.T) {
	engine := newObservedEngine(t)
	// Second candidate: no risk-med-deny (so "med" requests flip from a
	// definite deny to a definite allow), and it cannot decide at all when
	// the tier attribute is absent.
	candidateB := []RuleGroup{
		{ID: "risk", Priority: 100, Rules: []Rule{
			{ID: "risk-high-deny", Effect: EffectDeny, Condition: field("risk", OpEqual, "high")},
		}},
		{ID: "vip", Priority: 10, Rules: []Rule{
			{ID: "vip-allow", Effect: EffectAllow, Condition: field("tier", OpEqual, "vip")},
		}},
	}
	if err := engine.StartObservation("cand-2", candidateB); err != nil {
		t.Fatal(err)
	}

	requests := []map[string]any{
		{"risk": "med", "tier": "vip"}, // cand-1 denies, cand-2 allows: explicit deny change
		{"risk": "low", "tier": "vip"}, // both allow: no difference
		{"risk": "med"},                // cand-1 denies, cand-2 cannot decide: unknown-driven
	}
	for index, attrs := range requests {
		for _, candidate := range []string{"cand-1", "cand-2"} {
			if _, err := engine.Observe(candidate, string(rune('a'+index)), attrs); err != nil {
				t.Fatal(err)
			}
		}
	}

	comparison, err := engine.CompareObservations("cand-1", "cand-2")
	if err != nil {
		t.Fatal(err)
	}
	if comparison.Shared != 3 {
		t.Fatalf("expected 3 shared requests, got %d", comparison.Shared)
	}
	kinds := map[string]DifferenceKind{}
	for _, difference := range comparison.Differences {
		kinds[difference.RequestID] = difference.Kind
	}
	if kinds["a"] != DifferenceExplicitDeny {
		t.Fatalf("request a: expected explicit deny change, got %s", kinds["a"])
	}
	if kinds["b"] != DifferenceNone {
		t.Fatalf("request b: expected no difference, got %s", kinds["b"])
	}
	if kinds["c"] != DifferenceUnknownDriven {
		t.Fatalf("request c: expected unknown-driven difference, got %s", kinds["c"])
	}
}

func TestAbandonKeepsBasisAndResumeReusesConfirmedObservations(t *testing.T) {
	engine := newObservedEngine(t)
	if _, err := engine.Observe("cand-1", "req-1", map[string]any{"risk": "med", "tier": "vip"}); err != nil {
		t.Fatal(err)
	}
	if err := engine.ConfirmObservations("cand-1"); err != nil {
		t.Fatal(err)
	}
	if err := engine.AbandonObservation("cand-1", "waiting for risk team review"); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Observe("cand-1", "req-2", map[string]any{"risk": "low"}); err == nil {
		t.Fatal("abandoned candidate must not accept new observations")
	}

	infos := engine.ObservationInfos()
	if len(infos) != 1 || infos[0].Status != ObservationAbandoned ||
		infos[0].AbandonReason != "waiting for risk team review" || infos[0].ConfirmedRecords != 1 {
		t.Fatalf("abandon must retain explanation basis, got %+v", infos)
	}

	if err := engine.ResumeObservation("cand-1"); err != nil {
		t.Fatal(err)
	}
	records, err := engine.ObservationRecords("cand-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || !records[0].Confirmed {
		t.Fatalf("resume must reuse confirmed observations, got %+v", records)
	}
	infos = engine.ObservationInfos()
	if infos[0].Status != ObservationActive || infos[0].AbandonReason == "" {
		t.Fatalf("resume must keep abandon state for explanation, got %+v", infos[0])
	}
}

func TestPublishObservationStatesBasisScope(t *testing.T) {
	engine := newObservedEngine(t)
	if _, err := engine.Observe("cand-1", "req-1", map[string]any{"risk": "med", "tier": "vip"}); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.PublishObservation("cand-1"); err == nil {
		t.Fatal("publish without confirmed observations must fail")
	}
	if err := engine.ConfirmObservations("cand-1"); err != nil {
		t.Fatal(err)
	}
	set, err := engine.PublishObservation("cand-1")
	if err != nil {
		t.Fatal(err)
	}
	if got := set.Evaluate(map[string]any{"risk": "med", "tier": "vip"}); got.Allowed {
		t.Fatalf("published candidate must now adjudicate, got %+v", got)
	}
	history := engine.History()
	last := history[len(history)-1]
	if !strings.Contains(last.Reason, "cand-1") || !strings.Contains(last.Reason, "1 confirmed observations") {
		t.Fatalf("release record must state the actual basis scope, got %q", last.Reason)
	}
	infos := engine.ObservationInfos()
	if infos[0].Status != ObservationPublished {
		t.Fatalf("expected published status, got %+v", infos[0])
	}
}
