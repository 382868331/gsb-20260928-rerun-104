package policy

import (
	"fmt"
	"sort"
	"strings"
)

// DefaultGroup is the group assigned to rules that do not name one. It keeps
// the single-group engine behavior available without extra configuration.
const DefaultGroup = "default"

// GroupOutcome is the independent verdict of one rule group.
type GroupOutcome string

const (
	// GroupNone means the group produced no verdict at all.
	GroupNone GroupOutcome = "none"
	// GroupAllow means a rule in the group definitely matched with allow.
	GroupAllow GroupOutcome = "allow"
	// GroupDeny means a rule in the group definitely matched with deny.
	GroupDeny GroupOutcome = "deny"
	// GroupUnknown means the group could not decide because attributes were missing
	// or otherwise insufficient; this is never silently treated as allow.
	GroupUnknown GroupOutcome = "unknown"
)

// DecisionStatus explains the final adjudication across all groups.
type DecisionStatus string

const (
	StatusDeny          DecisionStatus = "deny"
	StatusAllow         DecisionStatus = "allow"
	StatusIndeterminate DecisionStatus = "indeterminate"
)

// RuleGroup is an ordered, independently judged collection of rules.
// Groups participate in adjudication by GroupPriority (descending); groups at
// the same priority follow their public order in the submitted batch.
type RuleGroup struct {
	ID       string
	Priority int
}

// GroupContribution records what one group contributed to a final decision.
type GroupContribution struct {
	GroupID        string
	GroupPriority  int
	Outcome        GroupOutcome
	MatchedRuleID  string
	UnknownReasons []string
}

// groupDefinition captures a validated group and its public batch order.
type groupDefinition struct {
	group RuleGroup
	order int
}

// groupOutcome evaluates a single independently judged group on a request.
// The first definitely matching rule decides the group, preserving tri-state
// semantics: unknown conditions never match, and unknown reasons are retained.
func (s *RuleSet) groupOutcome(group string, request map[string]any) GroupContribution {
	contribution := GroupContribution{GroupID: group, GroupPriority: s.groupPriority[group], Outcome: GroupNone}
	var unknownReasons []string
	sawUnknown := false
	for _, candidate := range s.rules {
		if candidate.group != group {
			continue
		}
		result := evaluateTri(candidate.rule.Condition, request, s, map[string]bool{})
		if !result.know {
			sawUnknown = true
			unknownReasons = append(unknownReasons, result.reasons...)
			continue
		}
		if !result.value {
			continue
		}
		if candidate.rule.Effect == EffectAllow {
			contribution.Outcome = GroupAllow
		} else {
			contribution.Outcome = GroupDeny
		}
		contribution.MatchedRuleID = candidate.rule.ID
		contribution.UnknownReasons = nil
		return contribution
	}
	if sawUnknown {
		contribution.Outcome = GroupUnknown
		contribution.UnknownReasons = dedupeStrings(unknownReasons)
	}
	return contribution
}

// evaluateGroups runs every group independently and applies the cross-group
// adjudication:
//
//   - an explicit deny from the highest-priority decisive group denies;
//   - an explicit allow wins only when no higher-priority group is unknown;
//   - unknown never becomes allow, and never masks an explicit deny;
//   - without any decisive group the request is denied by default.
func (s *RuleSet) evaluateGroups(request map[string]any) Decision {
	result := Decision{Effect: EffectDeny, Version: s.version, Status: StatusDeny}
	contributions := make([]GroupContribution, 0, len(s.groupOrder))
	for _, group := range s.groupOrder {
		contributions = append(contributions, s.groupOutcome(group, request))
	}
	result.Contributions = contributions

	var bestAllow *GroupContribution
	var bestDeny *GroupContribution
	for index := range contributions {
		contribution := &contributions[index]
		switch contribution.Outcome {
		case GroupDeny:
			if bestDeny == nil {
				bestDeny = contribution
			}
		case GroupAllow:
			if bestAllow == nil {
				bestAllow = contribution
			}
		}
	}

	switch {
	case bestDeny != nil:
		result.Allowed = false
		result.Effect = EffectDeny
		result.Status = StatusDeny
		result.Matched = true
		result.Evidence = s.evidenceFor(bestDeny.MatchedRuleID, request)
	case bestAllow != nil && !hasHigherUnknown(contributions, bestAllow.GroupPriority):
		result.Allowed = true
		result.Effect = EffectAllow
		result.Status = StatusAllow
		result.Matched = true
		result.Evidence = s.evidenceFor(bestAllow.MatchedRuleID, request)
	case bestAllow != nil:
		result.Allowed = false
		result.Effect = EffectDeny
		result.Status = StatusIndeterminate
		result.Matched = false
		result.UnknownReasons = unknownReasonsAbove(contributions, bestAllow.GroupID, s)
	default:
		result.Allowed = false
		result.Effect = EffectDeny
		result.Status = StatusIndeterminate
		result.Matched = false
		result.UnknownReasons = collectUnknownReasons(contributions)
	}
	return result
}

func unknownReasonsAbove(contributions []GroupContribution, allowGroup string, s *RuleSet) []string {
	return unknownReasonsAbovePriority(contributions, s.groupPriority[allowGroup])
}

func hasHigherUnknown(contributions []GroupContribution, priority int) bool {
	for _, contribution := range contributions {
		if contribution.Outcome == GroupUnknown && contribution.GroupPriority > priority {
			return true
		}
	}
	return false
}

func unknownReasonsAbovePriority(contributions []GroupContribution, allowPriority int) []string {
	var reasons []string
	for _, contribution := range contributions {
		if contribution.Outcome == GroupUnknown && contribution.GroupPriority > allowPriority {
			reasons = append(reasons, prefixedReasons(contribution)...)
		}
	}
	return dedupeStrings(reasons)
}

func collectUnknownReasons(contributions []GroupContribution) []string {
	var reasons []string
	for _, contribution := range contributions {
		if contribution.Outcome == GroupUnknown {
			reasons = append(reasons, prefixedReasons(contribution)...)
		}
	}
	return dedupeStrings(reasons)
}

func prefixedReasons(contribution GroupContribution) []string {
	reasons := make([]string, 0, len(contribution.UnknownReasons))
	for _, reason := range contribution.UnknownReasons {
		reasons = append(reasons, fmt.Sprintf("group %q: %s", contribution.GroupID, reason))
	}
	return reasons
}

func (s *RuleSet) evidenceFor(ruleID string, request map[string]any) *Evidence {
	candidate, ok := s.byID[ruleID]
	if !ok {
		return nil
	}
	_, explanation, _ := evaluateCondition(candidate.rule.Condition, request, s, map[string]bool{})
	return &Evidence{
		Rule: RuleSnapshot{
			ID:          candidate.rule.ID,
			Description: candidate.rule.Description,
			Group:       candidate.group,
			Priority:    candidate.rule.Priority,
			PublicOrder: candidate.order,
			Effect:      candidate.rule.Effect,
		},
		Explanation: explanation,
	}
}

func dedupeStrings(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

// CompileRuleGroups validates named independent groups and the rules assigned to
// them. Rules whose Group is empty join the DefaultGroup. Validation of the
// whole batch (including duplicate ids, bad refs and reference cycles across
// group boundaries) must pass before a set is produced.
func CompileRuleGroups(version int, groups []RuleGroup, rules []Rule) (*RuleSet, error) {
	return compile(version, groups, rules)
}

func validateGroups(groups []RuleGroup) (map[string]groupDefinition, []string) {
	definitions := map[string]groupDefinition{}
	var problems []string
	for index, group := range groups {
		id := strings.TrimSpace(group.ID)
		if id == "" {
			problems = append(problems, fmt.Sprintf("group at public order %d: id is empty", index))
			continue
		}
		if _, exists := definitions[id]; exists {
			problems = append(problems, fmt.Sprintf("group %q: duplicate id", id))
			continue
		}
		group.ID = id
		definitions[id] = groupDefinition{group: group, order: index}
	}
	return definitions, problems
}

func orderedGroupIDs(definitions map[string]groupDefinition, extra []string) []string {
	all := make([]groupDefinition, 0, len(definitions)+len(extra))
	for _, definition := range definitions {
		all = append(all, definition)
	}
	for index, id := range extra {
		if _, exists := definitions[id]; !exists {
			all = append(all, groupDefinition{group: RuleGroup{ID: id}, order: len(definitions) + index})
		}
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].group.Priority != all[j].group.Priority {
			return all[i].group.Priority > all[j].group.Priority
		}
		return all[i].order < all[j].order
	})
	ids := make([]string, len(all))
	for index, definition := range all {
		ids[index] = definition.group.ID
	}
	return ids
}
