package policy

import (
	"fmt"
	"reflect"
)

// SavedRequest is a representative request retained for rule-change rehearsal.
type SavedRequest struct {
	ID          string
	Description string
	Attributes  map[string]any
}

// ChangeKind describes why a decision changed during an impact preview.
type ChangeKind string

const (
	ChangeConditionAdded    ChangeKind = "condition_added"
	ChangeConditionRemoved  ChangeKind = "condition_removed"
	ChangeConditionModified ChangeKind = "condition_modified"
	ChangePriorityModified  ChangeKind = "priority_modified"
	ChangeSamePriorityOrder ChangeKind = "same_priority_reordered"
	ChangeEffectModified    ChangeKind = "effect_modified"
	ChangeGroupModified     ChangeKind = "group_modified"
)

// ImpactCause attributes a decision difference to a rule condition or ordering.
type ImpactCause struct {
	Kind    ChangeKind
	RuleID  string
	Message string
}

// RequestImpact compares one saved request on the old and candidate rule sets.
type RequestImpact struct {
	Request       SavedRequest
	Before        Decision
	After         Decision
	Changed       bool
	Causes        []ImpactCause
	GroupImpacts  []GroupRequestImpact
	ChangedGroups []string
}

// GroupRequestImpact shows one independent group's contribution before/after.
type GroupRequestImpact struct {
	GroupID string
	Before  GroupContribution
	After   GroupContribution
	Changed bool
}

// ImpactReport is a complete candidate rehearsal against saved requests.
type ImpactReport struct {
	BaseVersion      int
	CandidateVersion int
	Requests         []RequestImpact
	ChangedRequests  int
}

// PreviewRules compiles a candidate without activating it and rehearses requests.
func (e *Engine) PreviewRules(rules []Rule, requests []SavedRequest) (*ImpactReport, error) {
	return e.PreviewGroups([]RuleGroup{{ID: DefaultGroupID, Priority: 0, Rules: rules}}, requests)
}

// PreviewGroups compiles candidate groups without activating them and rehearses
// requests against the formal and candidate sets side by side.
func (e *Engine) PreviewGroups(groups []RuleGroup, requests []SavedRequest) (*ImpactReport, error) {
	e.mu.Lock()
	candidateVersion := e.nextVersionLocked()
	e.mu.Unlock()
	candidate, err := CompileGroups(candidateVersion, groups)
	if err != nil {
		return nil, err
	}
	var base *RuleSet
	if active := e.ActiveSet(); active != nil {
		base = active
	}
	return PreviewSets(base, candidate, requests), nil
}

// PreviewSets compares two immutable rule sets without changing an engine.
func PreviewSets(base, candidate *RuleSet, requests []SavedRequest) *ImpactReport {
	report := &ImpactReport{}
	if base != nil {
		report.BaseVersion = base.version
	}
	if candidate != nil {
		report.CandidateVersion = candidate.version
	}
	for _, saved := range requests {
		impact := RequestImpact{Request: saved}
		if base != nil {
			impact.Before = base.Evaluate(saved.Attributes)
		}
		if candidate != nil {
			impact.After = candidate.Evaluate(saved.Attributes)
		}
		impact.Changed = !decisionsEquivalent(impact.Before, impact.After)
		if impact.Changed {
			report.ChangedRequests++
		}
		impact.GroupImpacts, impact.ChangedGroups = groupImpacts(saved, base, candidate)
		impact.Causes = attributeImpact(saved.Attributes, base, candidate, impact)
		report.Requests = append(report.Requests, impact)
	}
	return report
}

func groupImpacts(saved SavedRequest, base, candidate *RuleSet) ([]GroupRequestImpact, []string) {
	var impacts []GroupRequestImpact
	var changed []string
	groups := unionGroupIDs(base, candidate)
	for _, id := range groups {
		entry := GroupRequestImpact{GroupID: id}
		if base != nil {
			entry.Before = base.GroupDecision(id, saved.Attributes)
		}
		if candidate != nil {
			entry.After = candidate.GroupDecision(id, saved.Attributes)
		}
		entry.Changed = !contributionsEquivalent(entry.Before, entry.After)
		if entry.Changed {
			changed = append(changed, id)
		}
		impacts = append(impacts, entry)
	}
	return impacts, changed
}

func unionGroupIDs(base, candidate *RuleSet) []string {
	seen := map[string]bool{}
	var ids []string
	for _, set := range []*RuleSet{base, candidate} {
		if set == nil {
			continue
		}
		for _, group := range set.groups {
			if !seen[group.id] {
				seen[group.id] = true
				ids = append(ids, group.id)
			}
		}
	}
	return ids
}

func contributionsEquivalent(left, right GroupContribution) bool {
	if left.Verdict != right.Verdict || left.GroupID != right.GroupID {
		return false
	}
	leftID := ""
	rightID := ""
	if left.Evidence != nil {
		leftID = left.Evidence.Rule.ID
	}
	if right.Evidence != nil {
		rightID = right.Evidence.Rule.ID
	}
	return leftID == rightID
}

func decisionsEquivalent(left, right Decision) bool {
	return left.Allowed == right.Allowed && left.Effect == right.Effect && left.Matched == right.Matched &&
		((left.Evidence == nil && right.Evidence == nil) ||
			(left.Evidence != nil && right.Evidence != nil && left.Evidence.Rule.ID == right.Evidence.Rule.ID))
}

func attributeImpact(request map[string]any, base, candidate *RuleSet, impact RequestImpact) []ImpactCause {
	var causes []ImpactCause
	beforeID := matchedRuleID(impact.Before)
	afterID := matchedRuleID(impact.After)

	switch {
	case beforeID == "" && afterID == "":
		return nil
	case beforeID == "":
		causes = append(causes, winnerCause(request, "", afterID, base, candidate, true)...)
	case afterID == "":
		causes = append(causes, winnerCause(request, matchedGroupID(impact.Before), beforeID, base, candidate, false)...)
	case beforeID == afterID:
		causes = append(causes, sameRuleCauses(matchedGroupID(impact.Before), beforeID, base, candidate)...)
	default:
		causes = append(causes, differentWinnerCauses(request, matchedGroupID(impact.Before), beforeID, matchedGroupID(impact.After), afterID, base, candidate)...)
	}
	for _, id := range impact.ChangedGroups {
		causes = append(causes, ImpactCause{Kind: ChangeGroupModified, RuleID: beforeID, Message: fmt.Sprintf("group %q contribution changed", id)})
	}
	return dedupeCauses(causes)
}

func matchedGroupID(decision Decision) string {
	for _, contribution := range decision.Contributions {
		if contribution.Evidence != nil && decision.Evidence != nil && contribution.Evidence == decision.Evidence {
			return contribution.GroupID
		}
	}
	return ""
}

func matchedRuleID(decision Decision) string {
	if decision.Evidence == nil {
		return ""
	}
	return decision.Evidence.Rule.ID
}

func winnerCause(request map[string]any, groupHint, id string, base, candidate *RuleSet, winnerInCandidate bool) []ImpactCause {
	oldRule, oldExists := findRule(base, groupHint, id)
	newRule, newExists := findRule(candidate, groupHint, id)
	switch {
	case !oldExists && newExists:
		return []ImpactCause{{Kind: ChangeConditionAdded, RuleID: id, Message: fmt.Sprintf("rule %q and its condition are added", id)}}
	case oldExists && !newExists:
		return []ImpactCause{{Kind: ChangeConditionRemoved, RuleID: id, Message: fmt.Sprintf("rule %q and its condition are removed", id)}}
	case oldExists && newExists && !reflect.DeepEqual(oldRule.rule.Condition, newRule.rule.Condition):
		causes := []ImpactCause{{Kind: ChangeConditionModified, RuleID: id, Message: fmt.Sprintf("rule %q condition changed", id)}}
		causes = append(causes, referencedConditionCauses(groupHint, oldRule.rule.Condition, base, candidate, request)...)
		return causes
	default:
		if newExists {
			if causes := referencedConditionCauses(groupHint, newRule.rule.Condition, base, candidate, request); len(causes) > 0 {
				return causes
			}
		}
		if winnerInCandidate {
			before := ruleSetDecision(base, request)
			return orderingCauses(matchedGroupID(before), matchedRuleID(before), groupHint, id, base, candidate)
		}
		after := ruleSetDecision(candidate, request)
		return orderingCauses(groupHint, id, matchedGroupID(after), matchedRuleID(after), base, candidate)
	}
}

func sameRuleCauses(groupID, id string, base, candidate *RuleSet) []ImpactCause {
	oldRule, oldOK := findRule(base, groupID, id)
	newRule, newOK := findRule(candidate, groupID, id)
	if !oldOK || !newOK {
		return nil
	}
	var causes []ImpactCause
	if !reflect.DeepEqual(oldRule.rule.Condition, newRule.rule.Condition) {
		causes = append(causes, ImpactCause{Kind: ChangeConditionModified, RuleID: id, Message: fmt.Sprintf("rule %q condition changed", id)})
	}
	if oldRule.rule.Effect != newRule.rule.Effect {
		causes = append(causes, ImpactCause{Kind: ChangeEffectModified, RuleID: id, Message: fmt.Sprintf("rule %q effect changed from %s to %s", id, oldRule.rule.Effect, newRule.rule.Effect)})
	}
	return causes
}

func differentWinnerCauses(request map[string]any, beforeGroup, beforeID, afterGroup, afterID string, base, candidate *RuleSet) []ImpactCause {
	oldBefore, oldBeforeExists := findRule(base, beforeGroup, beforeID)
	newBefore, newBeforeExists := findRule(candidate, beforeGroup, beforeID)
	oldAfter, oldAfterExists := findRule(base, afterGroup, afterID)
	newAfter, newAfterExists := findRule(candidate, afterGroup, afterID)

	if !oldAfterExists && newAfterExists {
		return []ImpactCause{{Kind: ChangeConditionAdded, RuleID: afterID, Message: fmt.Sprintf("added rule %q now matches first", afterID)}}
	}
	if oldBeforeExists && !newBeforeExists {
		return []ImpactCause{{Kind: ChangeConditionRemoved, RuleID: beforeID, Message: fmt.Sprintf("removed former winner %q", beforeID)}}
	}
	if !oldBeforeExists || !newBeforeExists || !oldAfterExists || !newAfterExists {
		return nil
	}

	var causes []ImpactCause
	oldAfterMatched := ruleDefinitelyMatches(afterID, base, request)
	newBeforeMatched := ruleDefinitelyMatches(beforeID, candidate, request)
	if !oldAfterMatched && reflect.DeepEqual(oldAfter.rule.Condition, newAfter.rule.Condition) {
		causes = append(causes, referencedConditionCauses(afterGroup, newAfter.rule.Condition, base, candidate, request)...)
	} else if !oldAfterMatched {
		causes = append(causes, ImpactCause{Kind: ChangeConditionModified, RuleID: afterID, Message: fmt.Sprintf("rule %q becomes true under the candidate condition", afterID)})
	}
	if !newBeforeMatched && reflect.DeepEqual(oldBefore.rule.Condition, newBefore.rule.Condition) {
		causes = append(causes, referencedConditionCauses(beforeGroup, newBefore.rule.Condition, base, candidate, request)...)
	} else if !newBeforeMatched {
		causes = append(causes, ImpactCause{Kind: ChangeConditionModified, RuleID: beforeID, Message: fmt.Sprintf("former winner %q no longer matches under the candidate condition", beforeID)})
	}
	if oldAfterMatched && newBeforeMatched {
		causes = append(causes, orderingCauses(beforeGroup, beforeID, afterGroup, afterID, base, candidate)...)
	}
	if len(causes) == 0 {
		causes = append(causes, ImpactCause{RuleID: afterID, Message: fmt.Sprintf("decision changed from rule %q to rule %q", beforeID, afterID)})
	}
	return causes
}

func orderingCauses(beforeGroup, beforeID, afterGroup, afterID string, base, candidate *RuleSet) []ImpactCause {
	oldBefore, _ := findRule(base, beforeGroup, beforeID)
	newBefore, _ := findRule(candidate, beforeGroup, beforeID)
	oldAfter, _ := findRule(base, afterGroup, afterID)
	newAfter, _ := findRule(candidate, afterGroup, afterID)
	if oldAfter.rule.Priority != newAfter.rule.Priority {
		return []ImpactCause{{Kind: ChangePriorityModified, RuleID: afterID, Message: fmt.Sprintf("rule %q priority changed from %d to %d", afterID, oldAfter.rule.Priority, newAfter.rule.Priority)}}
	}
	if oldBefore.rule.Priority != newBefore.rule.Priority {
		return []ImpactCause{{Kind: ChangePriorityModified, RuleID: beforeID, Message: fmt.Sprintf("rule %q priority changed from %d to %d", beforeID, oldBefore.rule.Priority, newBefore.rule.Priority)}}
	}
	if newBefore.rule.Priority == newAfter.rule.Priority && oldBefore.rule.Priority == oldAfter.rule.Priority &&
		((oldBefore.order < oldAfter.order && newBefore.order > newAfter.order) ||
			(oldBefore.order > oldAfter.order && newBefore.order < newAfter.order)) {
		return []ImpactCause{{Kind: ChangeSamePriorityOrder, RuleID: afterID, Message: fmt.Sprintf("rules %q and %q exchanged public order at priority %d", beforeID, afterID, newAfter.rule.Priority)}}
	}
	return []ImpactCause{{Kind: ChangePriorityModified, RuleID: afterID, Message: fmt.Sprintf("rule ordering makes %q precede %q", afterID, beforeID)}}
}

func referencedConditionCauses(groupID string, condition *Condition, base, candidate *RuleSet, request map[string]any) []ImpactCause {
	var causes []ImpactCause
	for _, ref := range conditionRefs(condition) {
		oldRule, oldOK := findRule(base, groupID, ref)
		newRule, newOK := findRule(candidate, groupID, ref)
		if oldOK && newOK && !reflect.DeepEqual(oldRule.rule.Condition, newRule.rule.Condition) &&
			ruleDefinitelyMatches(ref, base, request) != ruleDefinitelyMatches(ref, candidate, request) {
			causes = append(causes, ImpactCause{Kind: ChangeConditionModified, RuleID: ref, Message: fmt.Sprintf("referenced condition %q changed", ref)})
		}
	}
	return causes
}

func ruleDefinitelyMatches(id string, set *RuleSet, request map[string]any) bool {
	group, rule, ok := findRuleWithGroup(set, "", id)
	if !ok {
		return false
	}
	matched, _, known := evaluateConditionInGroup(rule.rule.Condition, request, group, map[string]bool{id: true})
	return known && matched
}

func findRule(set *RuleSet, groupID, id string) (compiledRule, bool) {
	_, rule, ok := findRuleWithGroup(set, groupID, id)
	return rule, ok
}

func findRuleWithGroup(set *RuleSet, groupID, id string) (compiledGroup, compiledRule, bool) {
	if set == nil {
		return compiledGroup{}, compiledRule{}, false
	}
	if groupID != "" {
		group, exists := set.byGroup[groupID]
		if !exists {
			return compiledGroup{}, compiledRule{}, false
		}
		entry, ok := group.byID[id]
		return group, entry, ok
	}
	for _, group := range set.groups {
		if entry, ok := group.byID[id]; ok {
			return group, entry, true
		}
	}
	return compiledGroup{}, compiledRule{}, false
}

func ruleSetDecision(set *RuleSet, request map[string]any) Decision {
	if set == nil {
		return Decision{Allowed: false, Effect: EffectDeny}
	}
	return set.Evaluate(request)
}

func dedupeCauses(causes []ImpactCause) []ImpactCause {
	seen := map[ImpactCause]bool{}
	result := make([]ImpactCause, 0, len(causes))
	for _, cause := range causes {
		if cause.RuleID == "" || seen[cause] {
			continue
		}
		seen[cause] = true
		result = append(result, cause)
	}
	return result
}
