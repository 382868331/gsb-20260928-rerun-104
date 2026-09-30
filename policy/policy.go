package policy

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
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

// ReleaseAction describes a published or withdrawn rule-set change.
type ReleaseAction string

const (
	ReleasePublished ReleaseAction = "published"
	ReleaseWithdrawn ReleaseAction = "withdrawn"
)

// ReleaseRecord is an append-only entry in the engine's release history.
type ReleaseRecord struct {
	Action          ReleaseAction
	Version         int
	PreviousVersion int
	Set             *RuleSet
	Time            time.Time
}

// SavedRequest is a curated request used to preview candidate rule changes.
type SavedRequest struct {
	ID          string
	Description string
	Attributes  map[string]any
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
	mu      sync.RWMutex
	history []ReleaseRecord
	saved   map[string]SavedRequest
}

// NewEngine creates an engine. rules are validated before becoming active.
func NewEngine(rules []Rule) (*Engine, error) {
	set, err := CompileRules(1, rules)
	if err != nil {
		return nil, err
	}
	engine := &Engine{saved: map[string]SavedRequest{}}
	engine.current.Store(set)
	engine.history = []ReleaseRecord{{Action: ReleasePublished, Version: 1, PreviousVersion: 0, Set: set, Time: time.Now()}}
	return engine, nil
}

// NewEngineFromSet embeds an already compiled immutable rule set.
func NewEngineFromSet(set *RuleSet) *Engine {
	engine := &Engine{saved: map[string]SavedRequest{}}
	engine.current.Store(set)
	if set != nil {
		engine.history = []ReleaseRecord{{Action: ReleasePublished, Version: set.Version(), PreviousVersion: 0, Set: set, Time: time.Now()}}
	}
	return engine
}

// SaveRequest stores a defensive copy of a human-selected request for previews.
func (e *Engine) SaveRequest(request SavedRequest) error {
	if strings.TrimSpace(request.ID) == "" {
		return fmt.Errorf("saved request id is empty")
	}
	if request.Attributes == nil {
		request.Attributes = map[string]any{}
	}
	request.Attributes = cloneRequest(request.Attributes)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.saved == nil {
		e.saved = map[string]SavedRequest{}
	}
	e.saved[request.ID] = request
	return nil
}

// SavedRequests returns saved requests ordered by ID.
func (e *Engine) SavedRequests() []SavedRequest {
	e.mu.RLock()
	defer e.mu.RUnlock()
	ids := make([]string, 0, len(e.saved))
	for id := range e.saved {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	requests := make([]SavedRequest, 0, len(ids))
	for _, id := range ids {
		request := e.saved[id]
		request.Attributes = cloneRequest(request.Attributes)
		requests = append(requests, request)
	}
	return requests
}

// PreviewCandidate validates and replays candidate rules against saved requests.
func (e *Engine) PreviewCandidate(rules []Rule) (*Preview, error) {
	saved := e.SavedRequests()
	requests := make([]map[string]any, len(saved))
	for index, request := range saved {
		requests[index] = request.Attributes
	}
	preview, err := e.PreviewRules(rules, requests)
	if err != nil {
		return nil, err
	}
	for index := range preview.RequestChanges {
		if index < len(saved) {
			preview.RequestChanges[index].RequestID = saved[index].ID
			preview.RequestChanges[index].Description = saved[index].Description
		}
	}
	return preview, nil
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
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.replaceRulesLocked(rules, ReleasePublished)
}

func (e *Engine) replaceRulesLocked(rules []Rule, action ReleaseAction) error {
	if e.saved == nil {
		e.saved = map[string]SavedRequest{}
	}
	previous := e.current.Load()
	nextVersion := e.nextVersionLocked()
	set, err := CompileRules(nextVersion, rules)
	if err != nil {
		return err
	}
	previousVersion := 0
	if previous != nil {
		previousVersion = previous.Version()
	}
	e.current.Store(set)
	e.history = append(e.history, ReleaseRecord{Action: action, Version: nextVersion, PreviousVersion: previousVersion, Set: set, Time: time.Now()})
	return nil
}

func (e *Engine) nextVersionLocked() int {
	nextVersion := e.Version()
	for _, record := range e.history {
		if record.Version > nextVersion {
			nextVersion = record.Version
		}
	}
	return nextVersion + 1
}

// LoadSet atomically replaces the active set with a separately compiled set.
func (e *Engine) LoadSet(set *RuleSet) error {
	if set == nil {
		return fmt.Errorf("rule set is nil")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.saved == nil {
		e.saved = map[string]SavedRequest{}
	}
	previous := e.current.Load()
	previousVersion := 0
	if previous != nil {
		previousVersion = previous.Version()
	}
	e.current.Store(set)
	e.history = append(e.history, ReleaseRecord{Action: ReleasePublished, Version: set.Version(), PreviousVersion: previousVersion, Set: set, Time: time.Now()})
	return nil
}

// WithdrawLastPublish restores the set that was active before the latest
// publication and appends a withdrawal record without deleting history.
func (e *Engine) WithdrawLastPublish() (*RuleSet, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.saved == nil {
		e.saved = map[string]SavedRequest{}
	}
	if len(e.history) == 0 {
		return nil, fmt.Errorf("no published rule set to withdraw")
	}
	current := e.current.Load()
	var previous *RuleSet
	lastPublished := -1
	for index := len(e.history) - 1; index >= 0; index-- {
		if e.history[index].Action == ReleasePublished {
			lastPublished = index
			break
		}
	}
	if lastPublished < 0 {
		return nil, fmt.Errorf("no published rule set to withdraw")
	}
	if lastPublished < len(e.history)-1 {
		return nil, fmt.Errorf("latest publication was already withdrawn")
	}
	published := e.history[lastPublished]
	if published.Set != current {
		return nil, fmt.Errorf("latest publication is not active")
	}
	previousVersion := published.PreviousVersion
	if previousVersion == 0 {
		return nil, fmt.Errorf("initial rule set cannot be withdrawn")
	}
	for index := lastPublished - 1; index >= 0; index-- {
		record := e.history[index]
		if record.Action == ReleasePublished && record.Set != nil && record.Version == previousVersion {
			previous = record.Set
			break
		}
	}
	if previous == nil {
		return nil, fmt.Errorf("previous rule set version %d is not available", previousVersion)
	}
	e.current.Store(previous)
	e.history = append(e.history, ReleaseRecord{Action: ReleaseWithdrawn, Version: previous.Version(), PreviousVersion: current.Version(), Set: previous, Time: time.Now()})
	return previous, nil
}

// History returns a copy of append-only publication and withdrawal records.
func (e *Engine) History() []ReleaseRecord {
	e.mu.RLock()
	defer e.mu.RUnlock()
	history := make([]ReleaseRecord, len(e.history))
	copy(history, e.history)
	return history
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
