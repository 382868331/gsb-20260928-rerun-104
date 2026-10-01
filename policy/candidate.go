package policy

import "fmt"

// StagedCandidate is a validated, not-yet-published candidate kept independently
// of the active release. Abandoning it records an "abandon" entry without
// touching the published set or the withdraw/rollback history.
type StagedCandidate struct {
	set    *RuleSet
	groups []RuleGroup
	rules  []Rule
}

// NewEngineWithGroups validates independent rule groups and their rules before
// they become active. Rules without an explicit group join DefaultGroup.
func NewEngineWithGroups(groups []RuleGroup, rules []Rule) (*Engine, error) {
	e := &Engine{}
	set, err := CompileRuleGroups(e.nextVersionLocked(), groups, rules)
	if err != nil {
		return nil, err
	}
	e.recordLocked(ReleaseActionPublish, nil, set, "initial publish")
	return e, nil
}

// PublishRuleGroups validates the complete multi-group batch, publishes it
// atomically, and appends a release record.
func (e *Engine) PublishRuleGroups(groups []RuleGroup, rules []Rule) (*RuleSet, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	current := e.current.Load()
	nextVersion := e.nextVersionLocked()
	set, err := CompileRuleGroups(nextVersion, groups, rules)
	if err != nil {
		return nil, err
	}
	e.current.Store(set)
	e.history = append(e.history, ReleaseRecord{
		Action:   ReleaseActionPublish,
		From:     current,
		To:       set,
		Version:  nextVersion,
		Previous: setVersion(current),
		Reason:   "published multi-group candidate",
	})
	return set, nil
}

// StageRules compiles a candidate without publishing it. The returned candidate
// is independent of later engine activity and can be published or abandoned.
func (e *Engine) StageRules(rules []Rule) (*StagedCandidate, error) {
	return e.StageRuleGroups(nil, rules)
}

// StageRuleGroups compiles a multi-group candidate without publishing it.
func (e *Engine) StageRuleGroups(groups []RuleGroup, rules []Rule) (*StagedCandidate, error) {
	e.mu.Lock()
	nextVersion := e.nextVersionLocked()
	e.mu.Unlock()
	set, err := CompileRuleGroups(nextVersion, groups, rules)
	if err != nil {
		return nil, err
	}
	return &StagedCandidate{set: set, groups: cloneGroups(groups), rules: cloneRules(rules)}, nil
}

// Set returns the candidate's immutable compiled set.
func (c *StagedCandidate) Set() *RuleSet { return c.set }

// PublishStaged atomically publishes a previously staged candidate and records
// the release; the active version used at publish time remains untouched until
// validation-derived publishing completes.
func (e *Engine) PublishStaged(candidate *StagedCandidate) (*RuleSet, error) {
	if candidate == nil || candidate.set == nil {
		return nil, fmt.Errorf("staged candidate is nil")
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	current := e.current.Load()
	set := candidate.set
	e.current.Store(set)
	e.history = append(e.history, ReleaseRecord{
		Action:   ReleaseActionPublish,
		From:     current,
		To:       set,
		Version:  set.version,
		Previous: setVersion(current),
		Reason:   "published staged candidate",
	})
	return set, nil
}

// AbandonStaged records that a candidate was given up without publishing. The
// record is kept separately from withdraw/rollback records and the active set
// is unchanged.
func (e *Engine) AbandonStaged(candidate *StagedCandidate, reason string) error {
	if candidate == nil || candidate.set == nil {
		return fmt.Errorf("staged candidate is nil")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	current := e.current.Load()
	e.history = append(e.history, ReleaseRecord{
		Action:   ReleaseActionAbandon,
		From:     current,
		To:       nil,
		Version:  candidate.set.version,
		Previous: setVersion(current),
		Reason:   reason,
	})
	candidate.set = nil
	return nil
}

func cloneGroups(groups []RuleGroup) []RuleGroup {
	if groups == nil {
		return nil
	}
	copied := make([]RuleGroup, len(groups))
	copy(copied, groups)
	return copied
}

func cloneRules(rules []Rule) []Rule {
	copied := make([]Rule, len(rules))
	for index, rule := range rules {
		copied[index] = cloneRule(rule)
	}
	return copied
}
