package policy

import (
	"fmt"
	"sort"
)

// Outcome is the tri-state result of evaluating one rule.
type Outcome string

const (
	OutcomeMatched Outcome = "matched"
	OutcomeFailed  Outcome = "failed"
	OutcomeUnknown Outcome = "unknown"
)

// RuleTrace explains how one rule behaved for a saved request.
type RuleTrace struct {
	Rule        RuleSnapshot
	Outcome     Outcome
	Explanation []string
}

// ReplayDecision is a decision plus enough rule traces to explain rule changes.
type ReplayDecision struct {
	Decision Decision
	Rules    []RuleTrace
}

// ChangeKind identifies why a rule comparison changed.
type ChangeKind string

const (
	ChangeCondition ChangeKind = "condition"
	ChangePriority  ChangeKind = "priority"
	ChangeOrder     ChangeKind = "public_order"
	ChangeEffect    ChangeKind = "effect"
	ChangeAdded     ChangeKind = "added"
	ChangeRemoved   ChangeKind = "removed"
)

// ChangeReason points at the condition reference path, rule metadata, or rule
// lifecycle responsible for a replay difference.
type ChangeReason struct {
	Kind     ChangeKind
	RuleID   string
	Path     string
	OldValue string
	NewValue string
	Message  string
}

// RequestChange compares one saved request against an old and candidate set.
type RequestChange struct {
	RequestID   string
	Description string
	Request     map[string]any
	Old         ReplayDecision
	New         ReplayDecision
	Changed     bool
	Reasons     []ChangeReason
}

// Preview is the impact report for a candidate rule batch.
type Preview struct {
	BaseVersion    int
	Candidate      *RuleSet
	RequestChanges []RequestChange
}

// PreviewRules compiles a candidate without touching the active rule set and
// replays saved requests against both immutable sets.
func (e *Engine) PreviewRules(rules []Rule, requests []map[string]any) (*Preview, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	base := e.ActiveSet()
	if base == nil {
		return nil, fmt.Errorf("active rule set is nil")
	}
	candidate, err := CompileRules(e.nextVersionLocked(), rules)
	if err != nil {
		return nil, err
	}
	return PreviewSets(base, candidate, requests), nil
}

// PreviewSets compares two already compiled, immutable rule sets.
func PreviewSets(base, candidate *RuleSet, requests []map[string]any) *Preview {
	changes := make([]RequestChange, 0, len(requests))
	for _, request := range requests {
		oldTrace := base.Replay(request)
		newTrace := candidate.Replay(request)
		reasons := diffRuleTraces(base, candidate, oldTrace, newTrace)
		changes = append(changes, RequestChange{
			Request: cloneRequest(request),
			Old:     oldTrace,
			New:     newTrace,
			Changed: requestActuallyChanged(oldTrace, newTrace, reasons),
			Reasons: reasons,
		})
	}
	return &Preview{BaseVersion: base.Version(), Candidate: candidate, RequestChanges: changes}
}

// Replay evaluates a request and records matched, explicitly failed, and
// unknown rules. The admission decision still uses only the first matched rule.
func (s *RuleSet) Replay(request map[string]any) ReplayDecision {
	request = cloneRequest(request)
	traces := make([]RuleTrace, 0, len(s.rules))
	decision := Decision{Allowed: false, Effect: EffectDeny, Version: s.version}
	for _, candidate := range s.rules {
		matched, explanation, known := evaluateCondition(candidate.rule.Condition, request, s, map[string]bool{})
		outcome := OutcomeUnknown
		if known {
			if matched {
				outcome = OutcomeMatched
			} else {
				outcome = OutcomeFailed
			}
		}
		trace := RuleTrace{
			Rule: RuleSnapshot{
				ID:          candidate.rule.ID,
				Description: candidate.rule.Description,
				Priority:    candidate.rule.Priority,
				PublicOrder: candidate.order,
				Effect:      candidate.rule.Effect,
			},
			Outcome:     outcome,
			Explanation: cloneStrings(explanation),
		}
		traces = append(traces, trace)
		if outcome == OutcomeMatched && !decision.Matched {
			decision.Effect = candidate.rule.Effect
			decision.Allowed = candidate.rule.Effect == EffectAllow
			decision.Matched = true
			decision.Evidence = &Evidence{Rule: trace.Rule, Explanation: trace.Explanation}
		}
	}
	return ReplayDecision{Decision: decision, Rules: traces}
}

func diffRuleTraces(oldSet, newSet *RuleSet, oldReply, newReply ReplayDecision) []ChangeReason {
	var reasons []ChangeReason
	oldByID := map[string]RuleTrace{}
	newByID := map[string]RuleTrace{}
	for _, trace := range oldReply.Rules {
		oldByID[trace.Rule.ID] = trace
	}
	for _, trace := range newReply.Rules {
		newByID[trace.Rule.ID] = trace
	}

	ids := make([]string, 0, len(oldByID)+len(newByID))
	seen := map[string]bool{}
	for _, trace := range oldReply.Rules {
		ids = append(ids, trace.Rule.ID)
		seen[trace.Rule.ID] = true
	}
	for _, trace := range newReply.Rules {
		if !seen[trace.Rule.ID] {
			ids = append(ids, trace.Rule.ID)
		}
	}
	sort.Strings(ids)

	for _, id := range ids {
		oldTrace, oldExists := oldByID[id]
		newTrace, newExists := newByID[id]
		switch {
		case oldExists && !newExists:
			reasons = append(reasons, ChangeReason{Kind: ChangeRemoved, RuleID: id, Message: "rule removed"})
		case !oldExists && newExists:
			reasons = append(reasons, ChangeReason{Kind: ChangeAdded, RuleID: id, Message: "rule added"})
		default:
			reasons = append(reasons, diffTrace(oldSet, newSet, oldTrace, newTrace)...)
		}
	}

	selectedOld := selectedRuleID(oldReply)
	selectedNew := selectedRuleID(newReply)
	if selectedOld != selectedNew || oldReply.Decision.Allowed != newReply.Decision.Allowed {
		reasons = append(reasons, ChangeReason{
			Kind:     ChangeCondition,
			RuleID:   selectedNew,
			OldValue: selectedOld,
			NewValue: selectedNew,
			Message:  "winning rule changed",
		})
	}
	return dedupeReasons(reasons)
}

func diffTrace(oldSet, newSet *RuleSet, oldTrace, newTrace RuleTrace) []ChangeReason {
	var reasons []ChangeReason
	if oldTrace.Outcome != newTrace.Outcome {
		reasons = append(reasons, ChangeReason{
			Kind:     ChangeCondition,
			RuleID:   newTrace.Rule.ID,
			OldValue: string(oldTrace.Outcome),
			NewValue: string(newTrace.Outcome),
			Message:  "rule condition result changed",
		})
	}
	if oldTrace.Rule.Priority != newTrace.Rule.Priority {
		reasons = append(reasons, ChangeReason{
			Kind:     ChangePriority,
			RuleID:   newTrace.Rule.ID,
			OldValue: fmt.Sprint(oldTrace.Rule.Priority),
			NewValue: fmt.Sprint(newTrace.Rule.Priority),
			Message:  "rule priority changed",
		})
	}
	if oldTrace.Rule.Priority == newTrace.Rule.Priority && oldTrace.Rule.PublicOrder != newTrace.Rule.PublicOrder {
		reasons = append(reasons, ChangeReason{
			Kind:     ChangeOrder,
			RuleID:   newTrace.Rule.ID,
			OldValue: fmt.Sprint(oldTrace.Rule.PublicOrder),
			NewValue: fmt.Sprint(newTrace.Rule.PublicOrder),
			Message:  "same-priority public order changed",
		})
	}
	if oldTrace.Rule.Effect != newTrace.Rule.Effect {
		reasons = append(reasons, ChangeReason{
			Kind:     ChangeEffect,
			RuleID:   newTrace.Rule.ID,
			OldValue: string(oldTrace.Rule.Effect),
			NewValue: string(newTrace.Rule.Effect),
			Message:  "rule effect changed",
		})
	}
	if oldTrace.Outcome != newTrace.Outcome || !sameStrings(oldTrace.Explanation, newTrace.Explanation) {
		reasons = append(reasons, diffRuleCondition(oldSet, newSet, oldTrace.Rule.ID, newTrace.Rule.ID, "$", map[string]bool{})...)
	}
	return reasons
}

func diffRuleCondition(oldSet, newSet *RuleSet, oldRuleID, newRuleID, path string, active map[string]bool) []ChangeReason {
	key := oldRuleID + "\x00" + newRuleID + "\x00" + path
	if active[key] {
		return nil
	}
	active[key] = true
	oldRule, oldExists := oldSet.byID[oldRuleID]
	newRule, newExists := newSet.byID[newRuleID]
	if !oldExists || !newExists {
		return nil
	}
	return diffCondition(oldRule.rule.Condition, newRule.rule.Condition, oldSet, newSet, newRuleID, path, active)
}

func diffCondition(oldCondition, newCondition *Condition, oldSet, newSet *RuleSet, ruleID, path string, active map[string]bool) []ChangeReason {
	if oldCondition == nil || newCondition == nil {
		return conditionChanged(ruleID, path, oldCondition, newCondition)
	}
	if oldCondition.Ref != "" || newCondition.Ref != "" {
		if oldCondition.Ref != newCondition.Ref {
			return conditionChanged(ruleID, path+".ref", oldCondition.Ref, newCondition.Ref)
		}
		return diffRuleCondition(oldSet, newSet, oldCondition.Ref, newCondition.Ref, path+".ref("+newCondition.Ref+")", active)
	}
	if oldCondition.Not != nil || newCondition.Not != nil {
		if oldCondition.Not == nil || newCondition.Not == nil {
			return conditionChanged(ruleID, path+".not", oldCondition.Not, newCondition.Not)
		}
		return diffCondition(oldCondition.Not, newCondition.Not, oldSet, newSet, ruleID, path+".not", active)
	}
	if len(oldCondition.All) != 0 || len(newCondition.All) != 0 {
		if len(oldCondition.All) != len(newCondition.All) {
			return conditionChanged(ruleID, path+".all", len(oldCondition.All), len(newCondition.All))
		}
		var reasons []ChangeReason
		for index := range oldCondition.All {
			reasons = append(reasons, diffCondition(oldCondition.All[index], newCondition.All[index], oldSet, newSet, ruleID, fmt.Sprintf("%s.all[%d]", path, index), active)...)
		}
		return reasons
	}
	if len(oldCondition.Any) != 0 || len(newCondition.Any) != 0 {
		if len(oldCondition.Any) != len(newCondition.Any) {
			return conditionChanged(ruleID, path+".any", len(oldCondition.Any), len(newCondition.Any))
		}
		var reasons []ChangeReason
		for index := range oldCondition.Any {
			reasons = append(reasons, diffCondition(oldCondition.Any[index], newCondition.Any[index], oldSet, newSet, ruleID, fmt.Sprintf("%s.any[%d]", path, index), active)...)
		}
		return reasons
	}
	if oldCondition.Field != newCondition.Field || oldCondition.Op != newCondition.Op || !valuesEqual(oldCondition.Value, newCondition.Value) {
		return []ChangeReason{{Kind: ChangeCondition, RuleID: ruleID, Path: path, OldValue: fmt.Sprintf("%s %s %v", oldCondition.Field, oldCondition.Op, oldCondition.Value), NewValue: fmt.Sprintf("%s %s %v", newCondition.Field, newCondition.Op, newCondition.Value), Message: "atomic condition changed"}}
	}
	return nil
}

func conditionChanged(ruleID, path string, oldValue, newValue any) []ChangeReason {
	return []ChangeReason{{Kind: ChangeCondition, RuleID: ruleID, Path: path, OldValue: fmt.Sprint(oldValue), NewValue: fmt.Sprint(newValue), Message: "condition changed"}}
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// Rules returns defensive copies of the rules in public submission order.
func (s *RuleSet) Rules() []Rule {
	entries := make([]compiledRule, len(s.byID))
	for _, entry := range s.byID {
		entries[entry.order] = entry
	}
	rules := make([]Rule, 0, len(entries))
	for _, entry := range entries {
		rules = append(rules, cloneRule(entry.rule))
	}
	return rules
}

func selectedRuleID(reply ReplayDecision) string {
	if reply.Decision.Evidence == nil {
		return ""
	}
	return reply.Decision.Evidence.Rule.ID
}

func decisionsEquivalent(left, right Decision) bool {
	leftID := ""
	rightID := ""
	if left.Evidence != nil {
		leftID = left.Evidence.Rule.ID
	}
	if right.Evidence != nil {
		rightID = right.Evidence.Rule.ID
	}
	return left.Allowed == right.Allowed && left.Effect == right.Effect && left.Matched == right.Matched && leftID == rightID
}

func requestActuallyChanged(oldReply, newReply ReplayDecision, reasons []ChangeReason) bool {
	if !decisionsEquivalent(oldReply.Decision, newReply.Decision) {
		return true
	}
	oldByID := map[string]RuleTrace{}
	for _, trace := range oldReply.Rules {
		oldByID[trace.Rule.ID] = trace
	}
	for _, newTrace := range newReply.Rules {
		oldTrace, exists := oldByID[newTrace.Rule.ID]
		if !exists || oldTrace.Outcome != newTrace.Outcome {
			return true
		}
		if newTrace.Outcome == OutcomeMatched && !sameStrings(oldTrace.Explanation, newTrace.Explanation) {
			return true
		}
	}
	return false
}

func dedupeReasons(reasons []ChangeReason) []ChangeReason {
	seen := map[ChangeReason]bool{}
	result := make([]ChangeReason, 0, len(reasons))
	for _, reason := range reasons {
		if !seen[reason] {
			seen[reason] = true
			result = append(result, reason)
		}
	}
	return result
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	copied := make([]string, len(values))
	copy(copied, values)
	return copied
}

func cloneRequest(request map[string]any) map[string]any {
	copied := make(map[string]any, len(request))
	for key, value := range request {
		copied[key] = cloneValue(value)
	}
	return copied
}
