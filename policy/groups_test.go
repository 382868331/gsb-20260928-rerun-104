package policy

import (
	"reflect"
	"testing"
)

func TestIndependentGroupsAdjudication(t *testing.T) {
	groups := []RuleGroup{
		{ID: "security", Priority: 100},
		{ID: "business", Priority: 10},
	}
	rules := []Rule{
		// Security group: deny when blocked, unknown when the flag is missing.
		{ID: "blocked-deny", Group: "security", Effect: EffectDeny,
			Condition: field("blocked", OpEqual, true)},
		// Business group: allow VIPs.
		{ID: "vip-allow", Group: "business", Priority: 10, Effect: EffectAllow,
			Condition: field("tier", OpEqual, "vip")},
	}
	engine, err := NewEngineWithGroups(groups, rules)
	if err != nil {
		t.Fatal(err)
	}

	// Explicit deny from the high-priority group masks a lower explicit allow.
	decision := engine.Evaluate(map[string]any{"tier": "vip", "blocked": true})
	if decision.Allowed || decision.Status != StatusDeny || decision.Evidence.Rule.ID != "blocked-deny" {
		t.Fatalf("expected security deny to win, got %+v", decision)
	}
	contrib := contribution(decision, "security")
	if contrib.Outcome != GroupDeny {
		t.Fatalf("expected security deny contribution, got %+v", contrib)
	}

	// Missing security flag keeps unknown; lower allow must not be honored.
	decision = engine.Evaluate(map[string]any{"tier": "vip"})
	if decision.Allowed || decision.Status != StatusIndeterminate || decision.Matched {
		t.Fatalf("higher unknown must mask lower allow, got %+v", decision)
	}
	if len(decision.UnknownReasons) == 0 {
		t.Fatal("expected retained unknown reasons")
	}
	contrib = contribution(decision, "security")
	if contrib.Outcome != GroupUnknown || len(contrib.UnknownReasons) == 0 {
		t.Fatalf("expected unknown reason retained, got %+v", contrib)
	}
	contrib = contribution(decision, "business")
	if contrib.Outcome != GroupAllow || contrib.MatchedRuleID != "vip-allow" {
		t.Fatalf("business group still independently allowed, got %+v", contrib)
	}

	// Security resolves to false: business allow stands.
	decision = engine.Evaluate(map[string]any{"tier": "vip", "blocked": false})
	if !decision.Allowed || decision.Status != StatusAllow || decision.Evidence.Rule.ID != "vip-allow" {
		t.Fatalf("expected business allow after security cleared, got %+v", decision)
	}

	// Nothing known anywhere: denied by default, not allowed.
	decision = engine.Evaluate(map[string]any{})
	if decision.Allowed || decision.Matched || decision.Status != StatusIndeterminate {
		t.Fatalf("unknown groups must default-deny, got %+v", decision)
	}
}

func TestExplicitDenySurvivesUnknownGroup(t *testing.T) {
	// Lower-priority group explicitly denies while a higher group is unknown.
	groups := []RuleGroup{{ID: "risk", Priority: 100}, {ID: "ops", Priority: 1}}
	rules := []Rule{
		{ID: "risk-allow", Group: "risk", Effect: EffectAllow, Condition: field("risk", OpEqual, "low")},
		{ID: "ops-deny", Group: "ops", Effect: EffectDeny, Condition: field("flagged", OpEqual, true)},
	}
	set, err := CompileRuleGroups(1, groups, rules)
	if err != nil {
		t.Fatal(err)
	}
	decision := set.Evaluate(map[string]any{"flagged": true})
	if decision.Allowed || decision.Status != StatusDeny || decision.Evidence.Rule.ID != "ops-deny" {
		t.Fatalf("unknown higher group must not mask explicit deny basis, got %+v", decision)
	}
}

func TestCrossGroupConflictAndCycleRejectCandidate(t *testing.T) {
	engine, err := NewEngineWithGroups(
		[]RuleGroup{{ID: "a", Priority: 1}, {ID: "b", Priority: 2}},
		[]Rule{{ID: "a1", Group: "a", Effect: EffectAllow, Condition: field("x", OpEqual, 1)}})
	if err != nil {
		t.Fatal(err)
	}

	// Rule references a rule in another group that does not exist.
	_, err = engine.PreviewRuleGroups(
		[]RuleGroup{{ID: "a", Priority: 1}, {ID: "b", Priority: 2}},
		[]Rule{
			{ID: "a1", Group: "a", Effect: EffectAllow, Condition: &Condition{Ref: "b1"}},
			{ID: "a2", Group: "a", Effect: EffectDeny, Condition: field("x", OpEqual, 1)},
		}, nil)
	if err == nil {
		t.Fatal("expected missing cross-group reference to fail")
	}

	// Cross-group cycle rejects the candidate.
	_, err = engine.PreviewRuleGroups(
		[]RuleGroup{{ID: "a", Priority: 1}, {ID: "b", Priority: 2}},
		[]Rule{
			{ID: "a1", Group: "a", Effect: EffectAllow, Condition: &Condition{Ref: "b1"}},
			{ID: "b1", Group: "b", Effect: EffectDeny, Condition: &Condition{Ref: "a1"}},
		}, nil)
	if err == nil {
		t.Fatal("expected cross-group reference cycle to fail")
	}

	// Published version stays usable.
	decision := engine.Evaluate(map[string]any{"x": 1})
	if !decision.Allowed || engine.Version() != 1 {
		t.Fatalf("published version must remain usable, got %+v version %d", decision, engine.Version())
	}

	// Rule assigned to an undeclared group fails as well.
	_, err = engine.PreviewRuleGroups(
		[]RuleGroup{{ID: "a", Priority: 1}},
		[]Rule{{ID: "ghost", Group: "missing", Effect: EffectAllow, Condition: field("x", OpEqual, 1)}}, nil)
	if err == nil {
		t.Fatal("expected unknown group assignment to fail")
	}
}

func TestPreviewSingleGroupAdjustment(t *testing.T) {
	groups := []RuleGroup{{ID: "security", Priority: 100}, {ID: "business", Priority: 10}}
	engine, err := NewEngineWithGroups(groups, []Rule{
		{ID: "blocked-deny", Group: "security", Effect: EffectDeny, Condition: field("blocked", OpEqual, true)},
		{ID: "vip-allow", Group: "business", Effect: EffectAllow, Condition: field("tier", OpEqual, "vip")},
	})
	if err != nil {
		t.Fatal(err)
	}
	requests := []SavedRequest{{ID: "case-1", Attributes: map[string]any{"tier": "vip", "blocked": true}}}

	// Tighten only the business group: VIP now also requires quota.
	tightened := []Rule{
		{ID: "blocked-deny", Group: "security", Effect: EffectDeny, Condition: field("blocked", OpEqual, true)},
		{ID: "vip-allow", Group: "business", Effect: EffectAllow, Condition: &Condition{All: []*Condition{
			field("tier", OpEqual, "vip"),
			field("quota", OpAtLeast, 100),
		}}},
	}
	report, err := engine.PreviewGroupAdjustment(groups, tightened, "business", requests)
	if err != nil {
		t.Fatal(err)
	}
	if report.FocusGroup != "business" || len(report.Requests) != 1 {
		t.Fatalf("bad report: %+v", report)
	}
	impact := report.Requests[0]
	if impact.BeforeGroup.MatchedRuleID != "vip-allow" || impact.AfterGroup.Outcome != GroupUnknown {
		t.Fatalf("expected business contribution to change, before %+v after %+v", impact.BeforeGroup, impact.AfterGroup)
	}
	if len(impact.AfterGroup.UnknownReasons) == 0 {
		t.Fatal("expected unknown reason from tightened group")
	}
	// Security contribution must be identical (deny both sides).
	if !impact.Changed {
		t.Fatal("final decision still denies, but group contribution changed; expected Changed")
	}
	if !hasCause(impact.Causes, ChangeConditionModified, "vip-allow") {
		t.Fatalf("expected condition-modified cause, got %+v", impact.Causes)
	}
}

func TestStagedAbandonAndWithdrawRecordsIndependent(t *testing.T) {
	engine, err := NewEngine([]Rule{{ID: "v1", Effect: EffectAllow, Condition: field("version", OpEqual, 1)}})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := engine.StageRules([]Rule{{ID: "v2", Effect: EffectDeny, Condition: field("version", OpEqual, 1)}})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.AbandonStaged(candidate, "superseded"); err != nil {
		t.Fatal(err)
	}
	if engine.Version() != 1 {
		t.Fatalf("abandon must not change active version, got %d", engine.Version())
	}
	if decision := engine.Evaluate(map[string]any{"version": 1}); !decision.Allowed {
		t.Fatal("abandoned candidate must not take effect")
	}
	if err := engine.AbandonStaged(candidate, "again"); err == nil {
		t.Fatal("abandoned candidate cannot be abandoned again")
	}

	next, err := engine.StageRules([]Rule{{ID: "v3", Effect: EffectDeny, Condition: field("version", OpEqual, 1)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.PublishStaged(next); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.WithdrawRules(); err != nil {
		t.Fatal(err)
	}
	history := engine.History()
	if len(history) != 4 ||
		history[0].Action != ReleaseActionPublish ||
		history[1].Action != ReleaseActionAbandon ||
		history[2].Action != ReleaseActionPublish ||
		history[3].Action != ReleaseActionWithdraw {
		t.Fatalf("abandon and withdraw records must stay independent, got %+v", history)
	}
	if history[1].Reason != "superseded" {
		t.Fatalf("abandon reason not preserved: %+v", history[1])
	}
}

func TestPublishedSnapshotImmuneToExternalMutation(t *testing.T) {
	condition := field("tier", OpEqual, "vip")
	original := []Rule{{ID: "vip", Effect: EffectAllow, Condition: condition}}
	engine, err := NewEngine(original)
	if err != nil {
		t.Fatal(err)
	}
	fixed := engine.ActiveSet()

	// Mutate the caller's condition object and request after publication.
	condition.Op = OpEqual
	condition.Field = "evil"
	condition.Value = "evil"
	request := map[string]any{"tier": "vip"}
	decision := fixed.Evaluate(request)
	if !decision.Allowed || decision.Evidence.Rule.ID != "vip" {
		t.Fatalf("published judgment must not change with source condition: %+v", decision)
	}
	request["tier"] = "evil"
	decision = fixed.Evaluate(map[string]any{"tier": "vip"})
	if !decision.Allowed {
		t.Fatalf("re-evaluation should stay independent: %+v", decision)
	}

	// Ref-based deep copy across the published structure.
	rules := []Rule{
		{ID: "gate", Effect: EffectAllow, Condition: &Condition{Ref: "shared"}},
		{ID: "shared", Effect: EffectDeny, Condition: field("risk", OpEqual, "low")},
	}
	engine2, err := NewEngine(rules)
	if err != nil {
		t.Fatal(err)
	}
	rules[1].Condition.Field = "mutated"
	decision = engine2.ActiveSet().Evaluate(map[string]any{"risk": "low"})
	if !decision.Allowed || decision.Evidence.Rule.ID != "gate" {
		t.Fatalf("published ref condition must be frozen, got %+v", decision)
	}
}

func TestGroupContributionsAllRecorded(t *testing.T) {
	groups := []RuleGroup{{ID: "g1", Priority: 100}, {ID: "g2", Priority: 50}, {ID: "g3", Priority: 1}}
	set, err := CompileRuleGroups(1, groups, []Rule{
		{ID: "r1", Group: "g1", Effect: EffectAllow, Condition: field("a", OpEqual, 1)},
		{ID: "r2", Group: "g2", Effect: EffectDeny, Condition: field("b", OpEqual, 1)},
		{ID: "r3", Group: "g3", Effect: EffectAllow, Condition: field("c", OpEqual, 1)},
	})
	if err != nil {
		t.Fatal(err)
	}
	decision := set.Evaluate(map[string]any{"b": 1, "c": 1})
	if len(decision.Contributions) != 3 {
		t.Fatalf("expected 3 group contributions, got %+v", decision.Contributions)
	}
	if decision.Status != StatusDeny || decision.Evidence.Rule.ID != "r2" {
		t.Fatalf("expected g2 explicit deny, got %+v", decision)
	}
	outcomes := map[string]GroupOutcome{}
	for _, c := range decision.Contributions {
		outcomes[c.GroupID] = c.Outcome
	}
	if !reflect.DeepEqual(outcomes, map[string]GroupOutcome{"g1": GroupUnknown, "g2": GroupDeny, "g3": GroupAllow}) {
		t.Fatalf("unexpected contributions: %+v", outcomes)
	}
}

func contribution(decision Decision, group string) GroupContribution {
	for _, contribution := range decision.Contributions {
		if contribution.GroupID == group {
			return contribution
		}
	}
	return GroupContribution{}
}
