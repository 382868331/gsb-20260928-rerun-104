package policy

import "fmt"

// ReleaseAction describes the lifecycle transition recorded for a rule set.
type ReleaseAction string

const (
	ReleaseActionPublish  ReleaseAction = "publish"
	ReleaseActionWithdraw ReleaseAction = "withdraw"
)

// ReleaseRecord preserves a publish or withdrawal transition.
type ReleaseRecord struct {
	Action   ReleaseAction
	From     *RuleSet
	To       *RuleSet
	Version  int
	Previous int
	Reason   string
	Basis    *ObservationBasis
}

// PublishRules validates a candidate, publishes it atomically, and records the change.
func (e *Engine) PublishRules(rules []Rule) (*RuleSet, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	current := e.current.Load()
	nextVersion := e.nextVersionLocked()
	set, err := CompileRules(nextVersion, rules)
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
		Reason:   "published candidate",
	})
	e.refreshObservations(changedGroupIDs(current, set))
	return set, nil
}

// WithdrawRules restores the immediately previous published set while retaining history.
func (e *Engine) WithdrawRules() (*RuleSet, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	current := e.current.Load()
	if current == nil {
		return nil, fmt.Errorf("no active rule set to withdraw")
	}
	var previous *RuleSet
	for index := len(e.history) - 1; index >= 0; index-- {
		record := e.history[index]
		if record.Action == ReleaseActionPublish && record.To == current {
			previous = record.From
			break
		}
	}
	if previous == nil {
		return nil, fmt.Errorf("rule set version %d has no predecessor to restore", current.version)
	}
	e.current.Store(previous)
	e.history = append(e.history, ReleaseRecord{
		Action:   ReleaseActionWithdraw,
		From:     current,
		To:       previous,
		Version:  previous.version,
		Previous: current.version,
		Reason:   "withdrew active publication",
	})
	e.refreshObservations(changedGroupIDs(current, previous))
	return previous, nil
}

// History returns a defensive copy of immutable release records.
func (e *Engine) History() []ReleaseRecord {
	e.mu.Lock()
	defer e.mu.Unlock()
	history := make([]ReleaseRecord, len(e.history))
	copy(history, e.history)
	return history
}

func (e *Engine) recordLocked(action ReleaseAction, from, to *RuleSet, reason string) {
	e.current.Store(to)
	e.history = append(e.history, ReleaseRecord{
		Action:   action,
		From:     from,
		To:       to,
		Version:  setVersion(to),
		Previous: setVersion(from),
		Reason:   reason,
	})
}

func setVersion(set *RuleSet) int {
	if set == nil {
		return 0
	}
	return set.version
}

func (e *Engine) nextVersionLocked() int {
	version := 0
	for _, record := range e.history {
		if record.Version > version {
			version = record.Version
		}
	}
	current := e.current.Load()
	if current != nil && current.version > version {
		version = current.version
	}
	return version + 1
}
