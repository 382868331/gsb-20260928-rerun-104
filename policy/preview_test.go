package policy

import "testing"

func TestCandidatePreviewExplainsConditionRefAndTieOrderChanges(t *testing.T) {
	baseRules := []Rule{
		{
			ID:       "vip-allow",
			Priority: 20,
			Effect:   EffectAllow,
			Condition: &Condition{All: []*Condition{
				field("tier", OpEqual, "vip"),
				{Ref: "safe-request"},
			}},
		},
		{ID: "risk-deny", Priority: 10, Effect: EffectDeny, Condition: field("risk", OpAtLeast, 5)},
		{ID: "risk-allow", Priority: 10, Effect: EffectAllow, Condition: field("risk", OpAtLeast, 5)},
		{ID: "safe-request", Priority: 0, Effect: EffectDeny, Condition: field("risk", OpAtMost, 20)},
	}
	engine, err := NewEngine(baseRules)
	if err != nil {
		t.Fatal(err)
	}

	candidateRules := []Rule{
		baseRules[0],
		baseRules[2],
		baseRules[1],
		{ID: "safe-request", Priority: 0, Effect: EffectDeny, Condition: field("risk", OpAtMost, 5)},
	}
	referenceRequest := map[string]any{"tier": "vip", "risk": 15}
	tieOrderRequest := map[string]any{"risk": 10}
	missingAttributeRequest := map[string]any{}
	preview, err := engine.PreviewRules(candidateRules, []map[string]any{
		referenceRequest,
		tieOrderRequest,
		missingAttributeRequest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if engine.Version() != 1 {
		t.Fatalf("candidate preview changed active version: %d", engine.Version())
	}
	if preview.Candidate == nil || preview.Candidate.Version() != 2 {
		t.Fatalf("expected immutable candidate version 2, got %+v", preview.Candidate)
	}
	if len(preview.RequestChanges) != 3 {
		t.Fatalf("expected three request reports, got %d", len(preview.RequestChanges))
	}

	refChange := preview.RequestChanges[0]
	if refChange.Old.Decision.Evidence == nil || refChange.Old.Decision.Evidence.Rule.ID != "vip-allow" {
		t.Fatalf("expected old vip evidence, got %+v", refChange.Old.Decision)
	}
	if refChange.New.Decision.Evidence == nil || refChange.New.Decision.Evidence.Rule.ID != "risk-allow" {
		t.Fatalf("expected candidate reordered allow evidence, got %+v", refChange.New.Decision)
	}
	if !hasReasonPath(refChange.Reasons, ChangeCondition, "safe-request", "$.all[1].ref(safe-request)") {
		t.Fatalf("expected reused ref condition to be identified, got %+v", refChange.Reasons)
	}

	tieChange := preview.RequestChanges[1]
	if tieChange.Old.Decision.Evidence.Rule.ID != "risk-deny" || tieChange.New.Decision.Evidence.Rule.ID != "risk-allow" {
		t.Fatalf("expected same-priority reorder to change winner, old=%+v new=%+v", tieChange.Old.Decision, tieChange.New.Decision)
	}
	if !tieChange.Changed || !hasReason(tieChange.Reasons, ChangeOrder, "risk-allow", "") {
		t.Fatalf("expected public-order reason, got %+v", tieChange.Reasons)
	}

	unknownChange := preview.RequestChanges[2]
	if unknownChange.Changed || unknownChange.Old.Decision.Matched || unknownChange.New.Decision.Matched || unknownChange.Old.Decision.Allowed || unknownChange.New.Decision.Allowed {
		t.Fatalf("missing attributes must remain unknown and denied by default: %+v", unknownChange)
	}
	if !traceOutcome(unknownChange.Old, "vip-allow", OutcomeUnknown) || !traceOutcome(unknownChange.New, "vip-allow", OutcomeUnknown) {
		t.Fatalf("missing attributes must not be recorded as failed: %+v / %+v", unknownChange.Old.Rules, unknownChange.New.Rules)
	}
}

func TestInvalidCandidateDoesNotAffectCurrentRequests(t *testing.T) {
	engine, err := NewEngine([]Rule{{
		ID:        "current",
		Priority:  1,
		Effect:    EffectAllow,
		Condition: field("tier", OpEqual, "vip"),
	}})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := engine.PreviewRules([]Rule{{
		ID:        "cycle-a",
		Effect:    EffectAllow,
		Condition: &Condition{Ref: "cycle-b"},
	}, {
		ID:        "cycle-b",
		Effect:    EffectAllow,
		Condition: &Condition{Ref: "cycle-a"},
	}}, []map[string]any{{"tier": "vip"}}); err == nil {
		t.Fatal("expected invalid candidate validation")
	}

	decision := engine.Evaluate(map[string]any{"tier": "vip"})
	if !decision.Allowed || decision.Version != 1 || decision.Evidence.Rule.ID != "current" {
		t.Fatalf("current decision must remain on version 1, got %+v", decision)
	}
}

func TestPublishWithdrawKeepsHistoryAndFixedSnapshot(t *testing.T) {
	engine, err := NewEngine([]Rule{{
		ID:        "v1",
		Effect:    EffectAllow,
		Condition: field("version", OpEqual, 1),
	}})
	if err != nil {
		t.Fatal(err)
	}
	inFlight := engine.ActiveSet()

	if err := engine.ReplaceRules([]Rule{{
		ID:        "v2",
		Effect:    EffectAllow,
		Condition: field("version", OpEqual, 2),
	}}); err != nil {
		t.Fatal(err)
	}
	if !inFlight.Evaluate(map[string]any{"version": 1}).Allowed {
		t.Fatal("in-flight snapshot must keep evaluating version 1")
	}
	if !engine.Evaluate(map[string]any{"version": 2}).Allowed {
		t.Fatal("published engine should evaluate version 2")
	}

	withdrawn, err := engine.WithdrawLastPublish()
	if err != nil {
		t.Fatal(err)
	}
	if withdrawn.Version() != 1 || engine.Version() != 1 {
		t.Fatalf("expected withdrawal to restore version 1, got %d/%d", withdrawn.Version(), engine.Version())
	}
	history := engine.History()
	if len(history) < 3 || history[len(history)-1].Action != ReleaseWithdrawn {
		t.Fatalf("withdrawal must append preserved history, got %+v", history)
	}
	if history[len(history)-2].Action != ReleasePublished || history[len(history)-2].Version != 2 {
		t.Fatalf("expected original v2 publication to remain in history, got %+v", history)
	}
}

func TestSavedRequestPreview(t *testing.T) {
	engine, err := NewEngine([]Rule{{
		ID:        "v1",
		Effect:    EffectAllow,
		Condition: field("tier", OpEqual, "vip"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.SaveRequest(SavedRequest{ID: "vip", Description: "human reviewed VIP", Attributes: map[string]any{"tier": "vip"}}); err != nil {
		t.Fatal(err)
	}
	preview, err := engine.PreviewCandidate([]Rule{{
		ID:        "v2",
		Effect:    EffectDeny,
		Condition: field("tier", OpEqual, "vip"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.RequestChanges) != 1 || preview.RequestChanges[0].RequestID != "vip" || !preview.RequestChanges[0].Changed {
		t.Fatalf("expected saved request change report, got %+v", preview.RequestChanges)
	}
}

func hasReason(reasons []ChangeReason, kind ChangeKind, ruleID, path string) bool {
	for _, reason := range reasons {
		if reason.Kind == kind && reason.RuleID == ruleID && (path == "" || reason.Path == path) {
			return true
		}
	}
	return false
}

func hasReasonPath(reasons []ChangeReason, kind ChangeKind, ruleID, path string) bool {
	for _, reason := range reasons {
		if reason.Kind == kind && reason.RuleID == ruleID && reason.Path == path {
			return true
		}
	}
	return false
}

func traceOutcome(reply ReplayDecision, ruleID string, outcome Outcome) bool {
	for _, trace := range reply.Rules {
		if trace.Rule.ID == ruleID {
			return trace.Outcome == outcome
		}
	}
	return false
}
