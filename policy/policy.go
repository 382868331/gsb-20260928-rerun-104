package policy

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Effect is the admission effect of a rule.
type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

// Operator is an atomic condition operator.
type Operator string

const (
	OpEqual    Operator = "eq"
	OpNotEqual Operator = "ne"
	OpGreater  Operator = "gt"
	OpAtLeast  Operator = "gte"
	OpLess     Operator = "lt"
	OpAtMost   Operator = "lte"
	OpIn       Operator = "in"
	OpContains Operator = "contains"
	OpPrefix   Operator = "prefix"
	OpSuffix   Operator = "suffix"
	OpExists   Operator = "exists"
)

// Condition is either an atomic predicate or an all/any/not/ref combination.
// Ref evaluates another rule's condition without using that rule's effect.
type Condition struct {
	Field string
	Op    Operator
	Value any

	All []*Condition
	Any []*Condition
	Not *Condition
	Ref string
}

// Rule is an externally supplied rule definition.
type Rule struct {
	ID          string
	Description string
	Priority    int
	Condition   *Condition
	Effect      Effect
}

// DefaultGroupID identifies the implicit group used by the single-batch API.
const DefaultGroupID = "default"

// RuleGroup is an independently validated collection of rules.
// Groups participate together in one decision; higher Priority groups are
// consulted first. Rules only reference other rules inside the same group.
type RuleGroup struct {
	ID          string
	Description string
	Priority    int
	Rules       []Rule
}

// GroupVerdict is the tri-state outcome of one rule group.
type GroupVerdict string

const (
	GroupAllow   GroupVerdict = "allow"
	GroupDeny    GroupVerdict = "deny"
	GroupUnknown GroupVerdict = "unknown"
)

// GroupContribution records what one independent group contributed.
// Denying groups stay visible even when a higher-priority group allows.
type GroupContribution struct {
	GroupID    string
	Priority   int
	Verdict    GroupVerdict
	Evidence   *Evidence
	UnknownFor []string
}

// RuleSnapshot is an immutable copy exposed in decision evidence.
type RuleSnapshot struct {
	ID          string
	Description string
	Priority    int
	PublicOrder int
	Effect      Effect
}

// Evidence identifies the single rule that actually produced a decision.
type Evidence struct {
	Rule        RuleSnapshot
	Explanation []string
}

// Decision is the result of one admission evaluation against one immutable set.
type Decision struct {
	Allowed        bool
	Effect         Effect
	Version        int
	Matched        bool
	Evidence       *Evidence
	Unknown        bool
	UnknownReasons []string
	Contributions  []GroupContribution
}

type compiledRule struct {
	rule  Rule
	order int
}

type compiledGroup struct {
	id       string
	priority int
	rules    []compiledRule
	byID     map[string]compiledRule
}

// RuleSet is an immutable, validated collection of rules.
type RuleSet struct {
	version int
	groups  []compiledGroup
	byGroup map[string]compiledGroup
}

// Engine is safe for concurrent evaluations and rule-set replacement.
type Engine struct {
	current atomic.Pointer[RuleSet]
	mu      sync.Mutex
	history []ReleaseRecord

	obsMu      sync.Mutex
	candidates map[string]*observedCandidate
	obsSeq     int
}

// NewEngine creates an engine. rules are validated before becoming active.
func NewEngine(rules []Rule) (*Engine, error) {
	e := &Engine{}
	set, err := CompileRules(e.nextVersionLocked(), rules)
	if err != nil {
		return nil, err
	}
	e.recordLocked(ReleaseActionPublish, nil, set, "initial publish")
	return e, nil
}

// NewEngineFromSet embeds an already compiled immutable rule set.
func NewEngineFromSet(set *RuleSet) *Engine {
	engine := &Engine{}
	engine.current.Store(set)
	return engine
}

// Version returns the active rule-set version. An empty engine returns zero.
func (e *Engine) Version() int {
	set := e.current.Load()
	if set == nil {
		return 0
	}
	return set.version
}

// ActiveSet returns the immutable rule set currently used by evaluations.
func (e *Engine) ActiveSet() *RuleSet {
	return e.current.Load()
}

// ReplaceRules validates the complete replacement batch and switches only on success.
// On any validation error the previous active version remains unchanged.
func (e *Engine) ReplaceRules(rules []Rule) error {
	_, err := e.PublishRules(rules)
	return err
}

// LoadSet atomically replaces the active set with a separately compiled set.
func (e *Engine) LoadSet(set *RuleSet) error {
	if set == nil {
		return fmt.Errorf("rule set is nil")
	}
	e.current.Store(set)
	return nil
}

// Evaluate checks a request against one immutable snapshot of the rules.
// When no rule condition is definitely true, the request is denied by default.
func (e *Engine) Evaluate(request map[string]any) Decision {
	set := e.current.Load()
	if set == nil {
		return Decision{Allowed: false, Effect: EffectDeny, Version: 0}
	}
	return set.Evaluate(request)
}

// Evaluate evaluates the immutable rule set. Repeated calls do not see later swaps.
func (s *RuleSet) Evaluate(request map[string]any) Decision {
	result := Decision{Allowed: false, Effect: EffectDeny, Version: s.version}
	for _, group := range s.groups {
		contribution := evaluateGroup(group, request)
		result.Contributions = append(result.Contributions, contribution)
		if len(contribution.UnknownFor) > 0 {
			result.UnknownReasons = append(result.UnknownReasons, unknownGroupReasons(group, contribution.UnknownFor)...)
		}
	}
	result.Unknown = len(result.UnknownReasons) > 0

	// Groups are ordered by decreasing priority. The first definite verdict
	// adjudicates; a group that only stays unknown can never mask a later deny.
	for index := range result.Contributions {
		contribution := &result.Contributions[index]
		if contribution.Verdict == GroupUnknown {
			continue
		}
		result.Matched = true
		result.Evidence = contribution.Evidence
		if contribution.Verdict == GroupAllow {
			result.Allowed = true
			result.Effect = EffectAllow
		} else {
			result.Allowed = false
			result.Effect = EffectDeny
		}
		return result
	}
	// No group produced a definite verdict. Unknown is not allow: deny.
	return result
}

func evaluateGroup(group compiledGroup, request map[string]any) GroupContribution {
	contribution := GroupContribution{GroupID: group.id, Priority: group.priority, Verdict: GroupUnknown}
	for _, candidate := range group.rules {
		matched, explanation, known := evaluateConditionInGroup(candidate.rule.Condition, request, group, map[string]bool{})
		if known && matched {
			contribution.Verdict = verdictForEffect(candidate.rule.Effect)
			contribution.Evidence = &Evidence{
				Rule: RuleSnapshot{
					ID:          candidate.rule.ID,
					Description: candidate.rule.Description,
					Priority:    candidate.rule.Priority,
					PublicOrder: candidate.order,
					Effect:      candidate.rule.Effect,
				},
				Explanation: explanation,
			}
			return contribution
		}
		if !known {
			contribution.UnknownFor = append(contribution.UnknownFor, candidate.rule.ID)
		}
	}
	return contribution
}

func unknownGroupReasons(group compiledGroup, ruleIDs []string) []string {
	reasons := make([]string, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		reasons = append(reasons, fmt.Sprintf("group %q: rule %q stayed unknown because a required attribute was missing or unusable", group.id, id))
	}
	return reasons
}

func verdictForEffect(effect Effect) GroupVerdict {
	if effect == EffectAllow {
		return GroupAllow
	}
	return GroupDeny
}

// Version returns the compiled set's version.
func (s *RuleSet) Version() int { return s.version }

// GroupDecision returns one independent group's own contribution.
func (s *RuleSet) GroupDecision(groupID string, request map[string]any) GroupContribution {
	group, exists := s.byGroup[groupID]
	if !exists {
		return GroupContribution{GroupID: groupID, Verdict: GroupUnknown}
	}
	return evaluateGroup(group, request)
}

// Groups returns the independent group ids in evaluation (priority) order.
func (s *RuleSet) Groups() []string {
	ids := make([]string, 0, len(s.groups))
	for _, group := range s.groups {
		ids = append(ids, group.id)
	}
	return ids
}

// GroupRules returns a defensive copy of one group's published rules.
func (s *RuleSet) GroupRules(groupID string) ([]Rule, bool) {
	group, exists := s.byGroup[groupID]
	if !exists {
		return nil, false
	}
	rules := make([]Rule, len(group.rules))
	for index, entry := range group.rules {
		rules[index] = cloneRule(entry.rule)
	}
	return rules, true
}

// CompileRules validates a complete rule batch and returns an immutable set.
// The batch is exposed as one independent group with the default group id.
func CompileRules(version int, rules []Rule) (*RuleSet, error) {
	return CompileGroups(version, []RuleGroup{{ID: DefaultGroupID, Priority: 0, Rules: rules}})
}

// CompileGroups validates independent rule groups and returns an immutable set.
// Each group is validated on its own; references cannot cross group boundaries.
func CompileGroups(version int, groups []RuleGroup) (*RuleSet, error) {
	if len(groups) == 0 {
		return nil, fmt.Errorf("rule group batch is empty")
	}

	var problems []string
	compiledGroups := make([]compiledGroup, 0, len(groups))
	seenGroups := map[string]bool{}

	for groupIndex, group := range groups {
		group.ID = strings.TrimSpace(group.ID)
		if group.ID == "" {
			problems = append(problems, fmt.Sprintf("group at public order %d: id is empty", groupIndex))
			continue
		}
		if seenGroups[group.ID] {
			problems = append(problems, fmt.Sprintf("group %q: duplicate id", group.ID))
			continue
		}
		seenGroups[group.ID] = true
		compiled, groupProblems := compileGroup(group)
		problems = append(problems, groupProblems...)
		compiledGroups = append(compiledGroups, compiled)
	}

	if len(problems) > 0 {
		return nil, fmt.Errorf("invalid rule batch:\n - %s", strings.Join(problems, "\n - "))
	}

	sort.SliceStable(compiledGroups, func(i, j int) bool {
		return compiledGroups[i].priority > compiledGroups[j].priority
	})

	byGroup := make(map[string]compiledGroup, len(compiledGroups))
	for _, group := range compiledGroups {
		byGroup[group.id] = group
	}
	return &RuleSet{version: version, groups: compiledGroups, byGroup: byGroup}, nil
}

func compileGroup(group RuleGroup) (compiledGroup, []string) {
	var problems []string
	if len(group.Rules) == 0 {
		return compiledGroup{id: group.ID, priority: group.Priority}, []string{fmt.Sprintf("group %q: rule batch is empty", group.ID)}
	}

	compiled := make([]compiledRule, 0, len(group.Rules))
	byID := make(map[string]compiledRule, len(group.Rules))

	for index, rule := range group.Rules {
		rule = cloneRule(rule)
		if strings.TrimSpace(rule.ID) == "" {
			problems = append(problems, fmt.Sprintf("group %q: rule at public order %d: id is empty", group.ID, index))
			continue
		}
		if _, exists := byID[rule.ID]; exists {
			problems = append(problems, fmt.Sprintf("group %q: rule %q: duplicate id", group.ID, rule.ID))
		}
		if rule.Effect != EffectAllow && rule.Effect != EffectDeny {
			problems = append(problems, fmt.Sprintf("group %q: rule %q: effect must be %q or %q", group.ID, rule.ID, EffectAllow, EffectDeny))
		}
		if err := validateCondition(rule.Condition, map[string]bool{}); err != nil {
			problems = append(problems, fmt.Sprintf("group %q: rule %q: %v", group.ID, rule.ID, err))
		}
		entry := compiledRule{rule: rule, order: index}
		compiled = append(compiled, entry)
		if _, exists := byID[rule.ID]; !exists {
			byID[rule.ID] = entry
		}
	}

	for _, rule := range compiled {
		if rule.rule.Condition == nil {
			continue
		}
		seen := map[string]bool{}
		stack := map[string]bool{}
		var cycle []string
		var walk func(string) bool
		walk = func(id string) bool {
			if stack[id] {
				cycle = append(cycle, id)
				return true
			}
			if seen[id] {
				return false
			}
			seen[id] = true
			stack[id] = true
			defer delete(stack, id)
			target, exists := byID[id]
			if !exists {
				return false
			}
			for _, ref := range conditionRefs(target.rule.Condition) {
				if _, refExists := byID[ref]; !refExists {
					problems = append(problems, fmt.Sprintf("group %q: rule %q: reference %q does not exist inside the group", group.ID, rule.rule.ID, ref))
					continue
				}
				if walk(ref) {
					cycle = append(cycle, id)
					return true
				}
			}
			return false
		}
		if walk(rule.rule.ID) {
			problems = append(problems, fmt.Sprintf("group %q: rule %q: reference cycle: %s", group.ID, rule.rule.ID, strings.Join(reverseStrings(cycle), " -> ")))
		}
	}

	sort.SliceStable(compiled, func(i, j int) bool {
		if compiled[i].rule.Priority != compiled[j].rule.Priority {
			return compiled[i].rule.Priority > compiled[j].rule.Priority
		}
		return compiled[i].order < compiled[j].order
	})

	return compiledGroup{id: group.ID, priority: group.Priority, rules: compiled, byID: byID}, problems
}

func reverseStrings(values []string) []string {
	for i, j := 0, len(values)-1; i < j; i, j = i+1, j-1 {
		values[i], values[j] = values[j], values[i]
	}
	return values
}

func cloneRule(rule Rule) Rule {
	rule.Condition = cloneCondition(rule.Condition)
	return rule
}

func cloneCondition(condition *Condition) *Condition {
	if condition == nil {
		return nil
	}
	copyCondition := *condition
	copyCondition.Value = cloneValue(condition.Value)
	if condition.All != nil {
		copyCondition.All = make([]*Condition, len(condition.All))
		for index, child := range condition.All {
			copyCondition.All[index] = cloneCondition(child)
		}
	}
	if condition.Any != nil {
		copyCondition.Any = make([]*Condition, len(condition.Any))
		for index, child := range condition.Any {
			copyCondition.Any[index] = cloneCondition(child)
		}
	}
	copyCondition.Not = cloneCondition(condition.Not)
	return &copyCondition
}

func cloneValue(value any) any {
	switch typed := value.(type) {
	case []any:
		copied := make([]any, len(typed))
		for index, item := range typed {
			copied[index] = cloneValue(item)
		}
		return copied
	case map[string]any:
		copied := make(map[string]any, len(typed))
		for key, item := range typed {
			copied[key] = cloneValue(item)
		}
		return copied
	default:
		return value
	}
}
