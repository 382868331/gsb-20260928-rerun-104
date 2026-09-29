package engine

import (
	"fmt"
	"sort"
	"sync/atomic"
	"time"
)

type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
)

type Rule struct {
	ID               string    `json:"id"`
	Priority         int       `json:"priority"`
	PublicationOrder int       `json:"publication_order"`
	Effect           Decision  `json:"effect"`
	Condition        Condition `json:"condition"`
	Description      string    `json:"description,omitempty"`
}

type NamedCondition struct {
	Name      string    `json:"name"`
	Condition Condition `json:"condition"`
}

type RuleSet struct {
	Rules           []Rule           `json:"rules"`
	NamedConditions []NamedCondition `json:"named_conditions,omitempty"`
}

type DecisionEvidence struct {
	Decision         Decision           `json:"decision"`
	VersionID        string             `json:"version_id"`
	Reason           string             `json:"reason"`
	MatchedRuleID    string             `json:"matched_rule_id,omitempty"`
	Effect           Decision           `json:"effect,omitempty"`
	Priority         *int               `json:"priority,omitempty"`
	PublicationOrder *int               `json:"publication_order,omitempty"`
	Condition        *ConditionEvidence `json:"condition,omitempty"`
	Missing          []string           `json:"missing,omitempty"`
}

type compiledRule struct {
	rule Rule
	root *conditionNode
}

type Version struct {
	ID          string
	PublishedAt time.Time
	rules       []compiledRule
	namedRoots  map[string]*conditionNode
	ruleIndex   map[string]int
}

func (v *Version) RuleIDs() []string {
	ids := make([]string, 0, len(v.rules))
	for _, compiled := range v.rules {
		ids = append(ids, compiled.rule.ID)
	}
	return ids
}

func (v *Version) Rule(ruleID string) (Rule, bool) {
	index, exists := v.ruleIndex[ruleID]
	if !exists {
		return Rule{}, false
	}
	return v.rules[index].rule, true
}

type Engine struct {
	current atomic.Pointer[Version]
}

func NewEngine(versionID string, rules RuleSet) (*Engine, error) {
	version, err := Compile(versionID, time.Now().UTC(), rules)
	if err != nil {
		return nil, err
	}
	engine := &Engine{}
	engine.current.Store(version)
	return engine, nil
}

func NewEmptyEngine() *Engine {
	return &Engine{}
}

func (e *Engine) Replace(versionID string, rules RuleSet) error {
	return e.ReplaceAt(versionID, time.Now().UTC(), rules)
}

func (e *Engine) ReplaceAt(versionID string, publishedAt time.Time, rules RuleSet) error {
	candidate, err := Compile(versionID, publishedAt, rules)
	if err != nil {
		return err
	}
	e.current.Store(candidate)
	return nil
}

func (e *Engine) CurrentVersion() *Version {
	return e.current.Load()
}

func (e *Engine) Evaluate(attributes map[string]any) DecisionEvidence {
	version := e.current.Load()
	if version == nil {
		return DecisionEvidence{
			Decision: DecisionDeny,
			Reason:   "no_rule_version_loaded",
			Missing:  nil,
		}
	}
	return version.evaluate(attributes)
}

func (v *Version) evaluate(attributes map[string]any) DecisionEvidence {
	missing := map[string]struct{}{}
	for _, candidate := range v.rules {
		result := candidate.root.evaluate(attributes)
		mergeMissing(missing, result.missing)
		if result.matched {
			priority := candidate.rule.Priority
			order := candidate.rule.PublicationOrder
			conditionEvidence := result.evidence
			return DecisionEvidence{
				Decision:         candidate.rule.Effect,
				VersionID:        v.ID,
				Reason:           "rule_matched",
				MatchedRuleID:    candidate.rule.ID,
				Effect:           candidate.rule.Effect,
				Priority:         &priority,
				PublicationOrder: &order,
				Condition:        &conditionEvidence,
			}
		}
	}
	return DecisionEvidence{
		Decision:  DecisionDeny,
		VersionID: v.ID,
		Reason:    "no_matching_rule",
		Missing:   sortedMissing(missing),
	}
}

func Compile(versionID string, publishedAt time.Time, rules RuleSet) (*Version, error) {
	rules = cloneRuleSet(rules)
	if versionID == "" {
		return nil, ValidationError{Reason: "version_id_required"}
	}
	if publishedAt.IsZero() {
		publishedAt = time.Now().UTC()
	}
	if len(rules.Rules) == 0 {
		return nil, ValidationError{Reason: "rules_required"}
	}

	namedRoots, err := compileNamedConditions(rules.NamedConditions)
	if err != nil {
		return nil, err
	}

	seenRules := map[string]struct{}{}
	compiled := make([]compiledRule, 0, len(rules.Rules))
	for index, rule := range rules.Rules {
		if rule.ID == "" {
			return nil, ValidationError{Reason: "rule_id_required", Index: index}
		}
		if _, exists := seenRules[rule.ID]; exists {
			return nil, ValidationError{Reason: "duplicate_rule_id", RuleID: rule.ID, Index: index}
		}
		seenRules[rule.ID] = struct{}{}
		if rule.Effect != DecisionAllow && rule.Effect != DecisionDeny {
			return nil, ValidationError{Reason: "invalid_effect", RuleID: rule.ID, Index: index}
		}
		if isEmptyCondition(rule.Condition) {
			return nil, ValidationError{Reason: "condition_required", RuleID: rule.ID, Index: index}
		}
		root, err := compileCondition(rule.Condition, func(name string) (*conditionNode, error) {
			target, exists := namedRoots[name]
			if !exists {
				return nil, ValidationError{Reason: "unknown_condition_reference", RuleID: name}
			}
			return target, nil
		}, map[string]string{"rule": rule.ID})
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, compiledRule{rule: rule, root: root})
	}

	sort.SliceStable(compiled, func(i, j int) bool {
		if compiled[i].rule.Priority != compiled[j].rule.Priority {
			return compiled[i].rule.Priority > compiled[j].rule.Priority
		}
		return compiled[i].rule.PublicationOrder > compiled[j].rule.PublicationOrder
	})

	ruleIndex := make(map[string]int, len(compiled))
	for index := range compiled {
		ruleIndex[compiled[index].rule.ID] = index
	}

	version := &Version{
		ID:          versionID,
		PublishedAt: publishedAt.UTC(),
		rules:       compiled,
		namedRoots:  namedRoots,
		ruleIndex:   ruleIndex,
	}
	return version, nil
}

func cloneRuleSet(input RuleSet) RuleSet {
	output := RuleSet{
		Rules:           make([]Rule, len(input.Rules)),
		NamedConditions: make([]NamedCondition, len(input.NamedConditions)),
	}
	for index, rule := range input.Rules {
		rule.Condition = cloneCondition(rule.Condition)
		output.Rules[index] = rule
	}
	for index, definition := range input.NamedConditions {
		definition.Condition = cloneCondition(definition.Condition)
		output.NamedConditions[index] = definition
	}
	return output
}

func cloneCondition(input Condition) Condition {
	output := input
	if input.Not != nil {
		not := cloneCondition(*input.Not)
		output.Not = &not
	}
	if input.All != nil {
		output.All = make([]Condition, len(input.All))
		for index, child := range input.All {
			output.All[index] = cloneCondition(child)
		}
	}
	if input.Any != nil {
		output.Any = make([]Condition, len(input.Any))
		for index, child := range input.Any {
			output.Any[index] = cloneCondition(child)
		}
	}
	output.Value = cloneValue(input.Value)
	return output
}

func compileNamedConditions(definitions []NamedCondition) (map[string]*conditionNode, error) {
	raw := map[string]Condition{}
	for index, definition := range definitions {
		if definition.Name == "" {
			return nil, ValidationError{Reason: "named_condition_name_required", Index: index}
		}
		if _, exists := raw[definition.Name]; exists {
			return nil, ValidationError{Reason: "duplicate_named_condition", RuleID: definition.Name, Index: index}
		}
		raw[definition.Name] = definition.Condition
	}
	compiled := make(map[string]*conditionNode, len(raw))
	visiting := map[string]bool{}
	var compile func(name string) (*conditionNode, error)
	compile = func(name string) (*conditionNode, error) {
		if node, exists := compiled[name]; exists && !visiting[name] {
			return node, nil
		}
		if visiting[name] {
			return nil, ReferenceCycleError{Reference: name, In: "named_condition"}
		}
		condition, exists := raw[name]
		if !exists {
			return nil, ValidationError{Reason: "unknown_condition_reference", RuleID: name}
		}
		visiting[name] = true
		node, err := compileCondition(condition, compile, map[string]string{"named_condition": name})
		if err != nil {
			return nil, err
		}
		delete(visiting, name)
		compiled[name] = node
		return node, nil
	}
	for name := range raw {
		if _, err := compile(name); err != nil {
			return nil, err
		}
	}
	return compiled, nil
}

func compileCondition(c Condition, resolve func(string) (*conditionNode, error), context map[string]string) (*conditionNode, error) {
	branches := 0
	if len(c.All) > 0 {
		branches++
	}
	if len(c.Any) > 0 {
		branches++
	}
	if c.Not != nil {
		branches++
	}
	if c.Ref != "" {
		branches++
	}
	if c.Field != "" || c.Op != "" || c.Value != nil {
		branches++
	}
	if branches == 0 {
		return nil, validationErrorForCondition("empty_condition", c, context)
	}
	if branches > 1 {
		return nil, validationErrorForCondition("multiple_condition_branches", c, context)
	}
	if c.Not != nil && isEmptyCondition(*c.Not) {
		return nil, validationErrorForCondition("empty_condition", c, context)
	}
	if (len(c.All) == 0 && c.All != nil) || (len(c.Any) == 0 && c.Any != nil) {
		return nil, validationErrorForCondition("empty_condition_group", c, context)
	}

	node := &conditionNode{condition: c}
	switch {
	case c.Ref != "":
		target, err := resolve(c.Ref)
		if err != nil {
			return nil, err
		}
		node.ref = target
	case c.Not != nil:
		child, err := compileCondition(*c.Not, resolve, context)
		if err != nil {
			return nil, err
		}
		node.not = child
	case len(c.All) > 0:
		node.all = make([]*conditionNode, 0, len(c.All))
		for _, child := range c.All {
			compiledChild, err := compileCondition(child, resolve, context)
			if err != nil {
				return nil, err
			}
			node.all = append(node.all, compiledChild)
		}
	case len(c.Any) > 0:
		node.any = make([]*conditionNode, 0, len(c.Any))
		for _, child := range c.Any {
			compiledChild, err := compileCondition(child, resolve, context)
			if err != nil {
				return nil, err
			}
			node.any = append(node.any, compiledChild)
		}
	default:
		if c.Field == "" {
			return nil, validationErrorForCondition("field_required", c, context)
		}
		if !validOperator(c.Op) {
			return nil, validationErrorForCondition(fmt.Sprintf("unknown_operator_%s", c.Op), c, context)
		}
		if c.Op == OpIn || c.Op == OpNotIn {
			if _, ok := asSlice(c.Value); !ok {
				return nil, validationErrorForCondition("operator_requires_list", c, context)
			}
		}
	}
	return node, nil
}

func validOperator(op Operator) bool {
	switch op {
	case OpEqual, OpNotEqual, OpLess, OpLessEq, OpGreater, OpGreaterEq, OpIn, OpNotIn, OpContains, OpPrefix, OpSuffix:
		return true
	default:
		return false
	}
}

func isEmptyCondition(c Condition) bool {
	return len(c.All) == 0 && len(c.Any) == 0 && c.Not == nil && c.Ref == "" && c.Field == "" && c.Op == "" && c.Value == nil
}

func validationErrorForCondition(reason string, c Condition, context map[string]string) error {
	e := ValidationError{Reason: reason}
	if ruleID, ok := context["rule"]; ok {
		e.RuleID = ruleID
	}
	if name, ok := context["named_condition"]; ok {
		e.ConditionName = name
	}
	if c.Field != "" {
		e.Field = c.Field
	}
	return e
}
