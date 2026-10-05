package policy

import "fmt"

// NewEngineGroups creates an engine from independent rule groups.
func NewEngineGroups(groups []RuleGroup) (*Engine, error) {
	e := &Engine{}
	set, err := CompileGroups(e.nextVersionLocked(), groups)
	if err != nil {
		return nil, err
	}
	e.recordLocked(ReleaseActionPublish, nil, set, "initial group publish")
	return e, nil
}

// PublishGroups validates all independent groups together and publishes them
// as one immutable set. Invalid candidates (including reference conflicts or
// cycles inside a group) never replace the formal version.
func (e *Engine) PublishGroups(groups []RuleGroup) (*RuleSet, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	current := e.current.Load()
	nextVersion := e.nextVersionLocked()
	set, err := CompileGroups(nextVersion, groups)
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
		Reason:   "published candidate groups",
	})
	e.markObservationsStaleLocked(set.version, "formal rule set changed")
	return set, nil
}

// ReplaceGroups validates and atomically switches all independent groups.
func (e *Engine) ReplaceGroups(groups []RuleGroup) error {
	_, err := e.PublishGroups(groups)
	return err
}

// PreviewGroup compares the formal set with a candidate that only replaces one
// group. Other groups are reused unchanged from the active set.
func (e *Engine) PreviewGroup(groupID string, rules []Rule, requests []SavedRequest) (*ImpactReport, error) {
	e.mu.Lock()
	base := e.current.Load()
	candidateVersion := e.nextVersionLocked()
	e.mu.Unlock()
	if base == nil {
		return nil, fmt.Errorf("no active rule set")
	}
	candidate, err := candidateWithReplacedGroup(candidateVersion, base, RuleGroup{ID: groupID, Rules: rules})
	if err != nil {
		return nil, err
	}
	return PreviewSets(base, candidate, requests), nil
}

// PublishGroup validates and publishes a candidate that changes only one group.
// Release history stays independent of abandoned previews.
func (e *Engine) PublishGroup(groupID string, rules []Rule) (*RuleSet, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	current := e.current.Load()
	if current == nil {
		return nil, fmt.Errorf("no active rule set")
	}
	candidate, err := candidateWithReplacedGroup(e.nextVersionLocked(), current, RuleGroup{ID: groupID, Rules: rules})
	if err != nil {
		return nil, err
	}
	e.current.Store(candidate)
	e.history = append(e.history, ReleaseRecord{
		Action:   ReleaseActionPublish,
		From:     current,
		To:       candidate,
		Version:  candidate.version,
		Previous: current.version,
		Reason:   fmt.Sprintf("published single group %q", groupID),
	})
	e.markObservationsStaleLocked(candidate.version, "formal rule set changed")
	return candidate, nil
}

func candidateWithReplacedGroup(version int, base *RuleSet, replacement RuleGroup) (*RuleSet, error) {
	if _, exists := base.byGroup[replacement.ID]; !exists {
		return nil, fmt.Errorf("group %q does not exist in the active rule set", replacement.ID)
	}
	groups := make([]RuleGroup, 0, len(base.groups))
	for _, group := range base.groups {
		groups = append(groups, RuleGroup{ID: group.id, Priority: group.priority, Rules: externalRules(group)})
	}
	for index := range groups {
		if groups[index].ID == replacement.ID {
			replacement.Priority = groups[index].Priority
			groups[index] = replacement
		}
	}
	return CompileGroups(version, groups)
}

func externalRules(group compiledGroup) []Rule {
	rules := make([]Rule, len(group.rules))
	for index, entry := range group.rules {
		rules[index] = cloneRule(entry.rule)
	}
	return rules
}
