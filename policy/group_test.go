package policy

import "testing"

func riskGroups() []RuleGroup {
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

func TestIndependentGroupsAdjudicateByPriorityAndRecordContributions(t *testing.T) {
	engine, err := NewEngineGroups(riskGroups())
	if err != nil {
		t.Fatal(err)
	}

	// Risk group explicitly denies; the lower-priority VIP allow cannot mask it.
	denied := engine.Evaluate(map[string]any{"risk": "high", "tier": "vip"})
	if denied.Allowed || denied.Matched != true || denied.Evidence.Rule.ID != "risk-high-deny" {
		t.Fatalf("expected high-priority risk deny, got %+v", denied)
	}
	if len(denied.Contributions) != 2 ||
		denied.Contributions[0].Verdict != GroupDeny ||
		denied.Contributions[1].Verdict != GroupAllow {
		t.Fatalf("expected deny and allow contributions preserved, got %+v", denied.Contributions)
	}

	allowed := engine.Evaluate(map[string]any{"risk": "low", "tier": "vip"})
	if !allowed.Allowed || allowed.Evidence.Rule.ID != "vip-allow" {
		t.Fatalf("expected lower group to allow once risk group has no verdict, got %+v", allowed)
	}
}

func TestUnknownGroupDoesNotBecomeAllowOrMaskExplicitDeny(t *testing.T) {
	groups := []RuleGroup{
		{
			ID:       "missing-attr",
			Priority: 100,
			Rules: []Rule{
				{ID: "needs-score", Effect: EffectAllow, Condition: field("score", OpAtLeast, 10)},
			},
		},
		{
			ID:       "blocklist",
			Priority: 10,
			Rules: []Rule{
				{ID: "blocked", Effect: EffectDeny, Condition: field("blocked", OpEqual, true)},
			},
		},
	}
	engine, err := NewEngineGroups(groups)
	if err != nil {
		t.Fatal(err)
	}

	d := engine.Evaluate(map[string]any{"blocked": true})
	if d.Allowed || !d.Matched || d.Evidence.Rule.ID != "blocked" {
		t.Fatalf("unknown high group must not mask explicit deny, got %+v", d)
	}
	if len(d.UnknownReasons) == 0 || d.UnknownReasons[0] == "" {
		t.Fatalf("unknown reason must be retained, got %+v", d.UnknownReasons)
	}
	if d.Contributions[0].Verdict != GroupUnknown || len(d.Contributions[0].UnknownFor) != 1 {
		t.Fatalf("expected unknown contribution with reason, got %+v", d.Contributions)
	}

	allUnknown := engine.Evaluate(map[string]any{})
	if allUnknown.Allowed || allUnknown.Matched || !allUnknown.Unknown {
		t.Fatalf("all groups unknown must deny without becoming allow, got %+v", allUnknown)
	}
}

func TestCrossGroupReferenceConflictAndCyclesRejectCandidate(t *testing.T) {
	engine, err := NewEngineGroups(riskGroups())
	if err != nil {
		t.Fatal(err)
	}

	bad := riskGroups()
	// A rule in vip may only reference rules inside the vip group.
	bad[1].Rules[0].Condition = &Condition{Ref: "risk-high-deny"}
	if err := engine.ReplaceGroups(bad); err == nil {
		t.Fatal("expected cross-group reference conflict to reject candidate")
	}

	cyclic := riskGroups()
	cyclic[0].Rules = append(cyclic[0].Rules,
		Rule{ID: "cycle-a", Effect: EffectAllow, Condition: &Condition{Ref: "cycle-b"}},
		Rule{ID: "cycle-b", Effect: EffectAllow, Condition: &Condition{Ref: "cycle-a"}},
	)
	if err := engine.ReplaceGroups(cyclic); err == nil {
		t.Fatal("expected cycle to reject candidate")
	}
	if engine.Version() != 1 {
		t.Fatalf("formal version must remain usable, got version %d", engine.Version())
	}
	if d := engine.Evaluate(map[string]any{"risk": "high"}); d.Allowed {
		t.Fatalf("formal set changed after rejected candidates: %+v", d)
	}
}

func TestPreviewAndPublishSingleGroupShowsScopedImpact(t *testing.T) {
	engine, err := NewEngineGroups(riskGroups())
	if err != nil {
		t.Fatal(err)
	}
	requests := []SavedRequest{{
		ID:         "case",
		Attributes: map[string]any{"risk": "medium", "tier": "vip"},
	}}

	// Loosen only the risk group; vip group stays untouched.
	report, err := engine.PreviewGroup("risk", []Rule{
		{ID: "risk-not-low-deny", Effect: EffectDeny, Condition: field("risk", OpNotEqual, "low")},
	}, requests)
	if err != nil {
		t.Fatal(err)
	}
	if engine.Version() != 1 {
		t.Fatal("abandoned preview must not change the formal version")
	}
	impact := report.Requests[0]
	if !impact.Changed || impact.After.Allowed {
		t.Fatalf("expected single-group edit to flip decision to deny, got %+v", impact)
	}
	var sawRisk, sawVip bool
	for _, groupImpact := range impact.GroupImpacts {
		switch groupImpact.GroupID {
		case "risk":
			sawRisk = groupImpact.Changed && groupImpact.After.Verdict == GroupDeny
		case "vip":
			sawVip = !groupImpact.Changed && groupImpact.After.Verdict == GroupAllow
		}
	}
	if !sawRisk || !sawVip {
		t.Fatalf("expected only risk group contribution to change, got %+v", impact.GroupImpacts)
	}

	if _, err := engine.PublishGroup("missing", nil); err == nil {
		t.Fatal("expected unknown group replacement to fail")
	}
	if _, err := engine.PublishGroup("risk", []Rule{
		{ID: "risk-not-low-deny", Effect: EffectDeny, Condition: field("risk", OpNotEqual, "low")},
	}); err != nil {
		t.Fatal(err)
	}
	if d := engine.Evaluate(map[string]any{"risk": "medium", "tier": "vip"}); d.Allowed || d.Evidence.Rule.ID != "risk-not-low-deny" {
		t.Fatalf("single group publish failed, got %+v", d)
	}
	if groups := engine.ActiveSet().Groups(); len(groups) != 2 {
		t.Fatalf("other groups must remain present, got %v", groups)
	}
}

func TestPublishedSnapshotIgnoresExternalConditionMutation(t *testing.T) {
	condition := field("tier", OpEqual, "vip")
	rules := []Rule{{ID: "r", Effect: EffectAllow, Condition: condition}}
	engine, err := NewEngineGroups([]RuleGroup{{ID: DefaultGroupID, Rules: rules}})
	if err != nil {
		t.Fatal(err)
	}
	fixed := engine.ActiveSet()

	condition.Field = "mutated"
	condition.Op = OpEqual
	condition.Value = "hacker"
	rules[0].ID = "externally-renamed"

	if d := fixed.Evaluate(map[string]any{"tier": "vip"}); !d.Allowed || d.Evidence.Rule.ID != "r" {
		t.Fatalf("published judgment changed after mutating source objects: %+v", d)
	}
}
