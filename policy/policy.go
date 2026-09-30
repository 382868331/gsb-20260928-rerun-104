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
	Allowed  bool
	Effect   Effect
	Version  int
	Matched  bool
	Evidence *Evidence
}

type compiledRule struct {
	rule  Rule
	order int
}

// RuleSet is an immutable, validated collection of rules.
type RuleSet struct {
	version int
	rules   []compiledRule
	byID    map[string]compiledRule
}

// Engine is safe for concurrent evaluations and rule-set replacement.
type Engine struct {
	current atomic.Pointer[RuleSet]
	mu      sync.Mutex
	history []ReleaseRecord
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
	for _, candidate := range s.rules {
		matched, explanation, ok := evaluateCondition(candidate.rule.Condition, request, s, map[string]bool{})
		if ok && matched {
			result.Effect = candidate.rule.Effect
			result.Allowed = candidate.rule.Effect == EffectAllow
			result.Matched = true
			result.Evidence = &Evidence{
				Rule: RuleSnapshot{
					ID:          candidate.rule.ID,
					Description: candidate.rule.Description,
					Priority:    candidate.rule.Priority,
					PublicOrder: candidate.order,
					Effect:      candidate.rule.Effect,
				},
				Explanation: explanation,
			}
			return result
		}
	}
	return result
}

// Version returns the compiled set's version.
func (s *RuleSet) Version() int { return s.version }

// CompileRules validates a complete rule batch and returns an immutable set.
func CompileRules(version int, rules []Rule) (*RuleSet, error) {
	if len(rules) == 0 {
		return nil, fmt.Errorf("rule batch is empty")
	}

	compiled := make([]compiledRule, 0, len(rules))
	byID := make(map[string]compiledRule, len(rules))
	var problems []string

	for index, rule := range rules {
		rule = cloneRule(rule)
		if strings.TrimSpace(rule.ID) == "" {
			problems = append(problems, fmt.Sprintf("rule at public order %d: id is empty", index))
			continue
		}
		if _, exists := byID[rule.ID]; exists {
			problems = append(problems, fmt.Sprintf("rule %q: duplicate id", rule.ID))
		}
		if rule.Effect != EffectAllow && rule.Effect != EffectDeny {
			problems = append(problems, fmt.Sprintf("rule %q: effect must be %q or %q", rule.ID, EffectAllow, EffectDeny))
		}
		if err := validateCondition(rule.Condition, map[string]bool{}); err != nil {
			problems = append(problems, fmt.Sprintf("rule %q: %v", rule.ID, err))
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
					problems = append(problems, fmt.Sprintf("rule %q: reference %q does not exist", rule.rule.ID, ref))
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
			problems = append(problems, fmt.Sprintf("rule %q: reference cycle: %s", rule.rule.ID, strings.Join(reverseStrings(cycle), " -> ")))
		}
	}

	if len(problems) > 0 {
		return nil, fmt.Errorf("invalid rule batch:\n - %s", strings.Join(problems, "\n - "))
	}

	sort.SliceStable(compiled, func(i, j int) bool {
		if compiled[i].rule.Priority != compiled[j].rule.Priority {
			return compiled[i].rule.Priority > compiled[j].rule.Priority
		}
		return compiled[i].order < compiled[j].order
	})

	return &RuleSet{version: version, rules: compiled, byID: byID}, nil
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
