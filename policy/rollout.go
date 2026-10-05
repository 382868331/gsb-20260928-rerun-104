package policy

import (
	"fmt"
	"sort"
)

// RolloutStatus describes the lifecycle state of an approved scoped rollout.
type RolloutStatus string

const (
	// RolloutActive means the approved plan still adopts new requests.
	RolloutActive RolloutStatus = "active"
	// RolloutHalted means new candidate adoption stopped because the
	// exposure quota was exhausted or a dependent rule set moved.
	RolloutHalted RolloutStatus = "halted"
	// RolloutWithdrawn means a maintainer emergency-stopped the rollout.
	RolloutWithdrawn RolloutStatus = "withdrawn"
)

// TrialGroup selects a slice of requests, by attributes, that an approved
// candidate may adjudicate. Groups must not overlap: a request that matches
// more than one group (or whose membership cannot be determined) is never
// adopted and keeps the original rules.
type TrialGroup struct {
	ID          string
	Description string
	Condition   *Condition
}

// ProtectedScope selects requests that must keep the original rules even
// when they also match a trial group.
type ProtectedScope struct {
	ID          string
	Description string
	Condition   *Condition
}

// RolloutPlan is the maintainer-approved scope of a candidate rollout.
type RolloutPlan struct {
	TrialGroups     []TrialGroup
	MaxExposure     int
	ProtectedScopes []ProtectedScope
}

// RolloutAssignment records how one request was attributed. Once recorded it
// is immutable: repeating the same request id returns the stored decision
// and never increases the exposure count or changes the attribution.
type RolloutAssignment struct {
	RequestID        string
	GroupID          string
	Adopted          bool
	Reason           string
	Decision         Decision
	BaseVersion      int
	CandidateVersion int
}

// RolloutInfo is a read-only summary of one candidate's rollout.
type RolloutInfo struct {
	CandidateID        string
	Approved           bool
	Status             RolloutStatus
	StopReason         string
	Exposure           int
	MaxExposure        int
	Assignments        int
	AdoptedAssignments int
}

// RolloutImpact summarizes, from valid (non-stale) observation records,
// which recorded requests may be affected by explicit deny changes or by
// unknown (missing) attributes if the candidate adjudicates them.
type RolloutImpact struct {
	CandidateID     string
	ValidRecords    int
	DenyChanges     []string
	UnknownAffected []string
	OtherChanges    []string
}

type rollout struct {
	plan        RolloutPlan
	status      RolloutStatus
	stopReason  string
	exposure    int
	assignments map[string]*RolloutAssignment
	order       []string
}

// ComputeRolloutImpact inspects the candidate's valid (non-stale)
// observation records and reports which requests would see an explicit deny
// change, an unknown-driven difference, or another explicit change. It never
// mutates observation state.
func (e *Engine) ComputeRolloutImpact(candidateID string) (*RolloutImpact, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	observation, ok := e.observations[candidateID]
	if !ok {
		return nil, fmt.Errorf("candidate %q has no observation", candidateID)
	}
	impact := &RolloutImpact{CandidateID: candidateID}
	seen := map[string]bool{}
	for _, record := range observation.records {
		if record.Stale || seen[record.RequestID] {
			continue
		}
		seen[record.RequestID] = true
		impact.ValidRecords++
		switch classifyDifference(record.Current, record.Candidate) {
		case DifferenceExplicitDeny:
			impact.DenyChanges = append(impact.DenyChanges, record.RequestID)
		case DifferenceUnknownDriven:
			impact.UnknownAffected = append(impact.UnknownAffected, record.RequestID)
		case DifferenceExplicitChange:
			impact.OtherChanges = append(impact.OtherChanges, record.RequestID)
		case DifferenceNone:
			// Identical conclusions can still be shaped by missing
			// attributes on either side; surface them as unknown-affected.
			if record.Current.Unknown || record.Candidate.Unknown {
				impact.UnknownAffected = append(impact.UnknownAffected, record.RequestID)
			}
		}
	}
	sort.Strings(impact.DenyChanges)
	sort.Strings(impact.UnknownAffected)
	sort.Strings(impact.OtherChanges)
	return impact, nil
}

// ApproveRollout explicitly approves one grouping plan for an observed
// candidate. The plan is validated and deep-copied; later edits to the
// caller's conditions cannot change the approved scope. Approving replaces
// any previous plan and resets exposure accounting.
func (e *Engine) ApproveRollout(candidateID string, plan RolloutPlan) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	observation, err := e.activeObservationLocked(candidateID)
	if err != nil {
		return err
	}
	approved, err := validateRolloutPlan(plan)
	if err != nil {
		return err
	}
	observation.rollout = &rollout{
		plan:        approved,
		status:      RolloutActive,
		assignments: map[string]*RolloutAssignment{},
	}
	return nil
}

// Adjudicate routes one request. Only requests covered by the approved plan
// (exactly one trial group, no protected scope, determinable membership) are
// adjudicated by the candidate; every other request keeps the original
// rules. Repeating a request id returns the recorded decision unchanged and
// never adds exposure. When the rollout is halted or withdrawn, new requests
// fall back to the original rules while recorded assignments stay in effect.
func (e *Engine) Adjudicate(candidateID, requestID string, attributes map[string]any) (Decision, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	observation, ok := e.observations[candidateID]
	if !ok {
		return Decision{}, fmt.Errorf("candidate %q has no observation", candidateID)
	}
	current := e.current.Load()
	evaluateCurrent := func() Decision {
		if current == nil {
			return Decision{Allowed: false, Effect: EffectDeny, Version: 0}
		}
		return current.Evaluate(attributes)
	}
	active := observation.rollout
	if active == nil {
		return evaluateCurrent(), nil
	}
	if assignment, exists := active.assignments[requestID]; exists {
		return cloneDecision(assignment.Decision), nil
	}
	if active.status != RolloutActive {
		return evaluateCurrent(), nil
	}

	baseVersion := 0
	if current != nil {
		baseVersion = current.version
	}
	record := func(decision Decision, groupID string, adopted bool, reason string) Decision {
		assignment := &RolloutAssignment{
			RequestID:        requestID,
			GroupID:          groupID,
			Adopted:          adopted,
			Reason:           reason,
			Decision:         cloneDecision(decision),
			BaseVersion:      baseVersion,
			CandidateVersion: observation.candidate.version,
		}
		active.assignments[requestID] = assignment
		active.order = append(active.order, requestID)
		return decision
	}

	// Protected scopes keep the original rules. An undeterminable protected
	// membership is treated conservatively as protected.
	for _, scope := range active.plan.ProtectedScopes {
		matched, _, known := evaluateConditionInGroup(scope.Condition, attributes, compiledGroup{}, map[string]bool{})
		if known && matched {
			return record(evaluateCurrent(), "", false, fmt.Sprintf("protected scope %q keeps original rules", scope.ID)), nil
		}
		if !known {
			return record(evaluateCurrent(), "", false, fmt.Sprintf("protected scope %q membership unknown; keeping original rules", scope.ID)), nil
		}
	}

	var matchedGroup string
	matches := 0
	membershipUnknown := false
	for _, group := range active.plan.TrialGroups {
		matched, _, known := evaluateConditionInGroup(group.Condition, attributes, compiledGroup{}, map[string]bool{})
		if !known {
			membershipUnknown = true
			continue
		}
		if matched {
			matches++
			matchedGroup = group.ID
		}
	}
	switch {
	case matches > 1:
		return record(evaluateCurrent(), "", false, "request matches multiple trial groups; keeping original rules"), nil
	case matches == 0 && membershipUnknown:
		return record(evaluateCurrent(), "", false, "trial group membership unknown; keeping original rules"), nil
	case matches == 0:
		return record(evaluateCurrent(), "", false, "request matches no trial group; keeping original rules"), nil
	case membershipUnknown:
		return record(evaluateCurrent(), "", false, "trial group membership ambiguous; keeping original rules"), nil
	}

	if active.exposure >= active.plan.MaxExposure {
		active.status = RolloutHalted
		active.stopReason = fmt.Sprintf("exposure quota %d exhausted", active.plan.MaxExposure)
		return record(evaluateCurrent(), "", false, "exposure quota exhausted; keeping original rules"), nil
	}
	active.exposure++
	return record(observation.candidate.Evaluate(attributes), matchedGroup, true, "adopted by approved trial group"), nil
}

// WithdrawRollout emergency-stops new candidate adoption. Assignments and
// decisions already made are retained and still honored for repeated
// request ids.
func (e *Engine) WithdrawRollout(candidateID, reason string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	observation, ok := e.observations[candidateID]
	if !ok {
		return fmt.Errorf("candidate %q has no observation", candidateID)
	}
	active := observation.rollout
	if active == nil {
		return fmt.Errorf("candidate %q has no approved rollout", candidateID)
	}
	if active.status != RolloutActive {
		return fmt.Errorf("candidate %q rollout is %s, not active", candidateID, active.status)
	}
	active.status = RolloutWithdrawn
	active.stopReason = reason
	return nil
}

// RolloutInfo summarizes one candidate's rollout, if any.
func (e *Engine) RolloutInfo(candidateID string) (RolloutInfo, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	observation, ok := e.observations[candidateID]
	if !ok {
		return RolloutInfo{}, fmt.Errorf("candidate %q has no observation", candidateID)
	}
	info := RolloutInfo{CandidateID: candidateID}
	active := observation.rollout
	if active == nil {
		return info, nil
	}
	info.Approved = true
	info.Status = active.status
	info.StopReason = active.stopReason
	info.Exposure = active.exposure
	info.MaxExposure = active.plan.MaxExposure
	info.Assignments = len(active.assignments)
	for _, assignment := range active.assignments {
		if assignment.Adopted {
			info.AdoptedAssignments++
		}
	}
	return info, nil
}

// RolloutAssignments returns deep copies of the recorded assignments in
// arrival order. Reading them never rewrites the stored attribution.
func (e *Engine) RolloutAssignments(candidateID string) ([]RolloutAssignment, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	observation, ok := e.observations[candidateID]
	if !ok {
		return nil, fmt.Errorf("candidate %q has no observation", candidateID)
	}
	active := observation.rollout
	if active == nil {
		return nil, nil
	}
	assignments := make([]RolloutAssignment, 0, len(active.order))
	for _, requestID := range active.order {
		assignment := active.assignments[requestID]
		copied := *assignment
		copied.Decision = cloneDecision(assignment.Decision)
		assignments = append(assignments, copied)
	}
	return assignments, nil
}

// stopRolloutsLocked halts every active rollout whose dependencies moved
// (formal rule set changed or the candidate itself was replaced). Recorded
// assignments stay in effect; only new adoption stops.
func (e *Engine) stopRolloutsLocked(reason string) {
	for _, observation := range e.observations {
		active := observation.rollout
		if active == nil || active.status != RolloutActive {
			continue
		}
		active.status = RolloutHalted
		active.stopReason = reason
	}
}

func validateRolloutPlan(plan RolloutPlan) (RolloutPlan, error) {
	if plan.MaxExposure < 1 {
		return RolloutPlan{}, fmt.Errorf("rollout plan: max exposure must be at least 1")
	}
	if len(plan.TrialGroups) == 0 {
		return RolloutPlan{}, fmt.Errorf("rollout plan: at least one trial group is required")
	}
	approved := RolloutPlan{MaxExposure: plan.MaxExposure}
	seenGroups := map[string]bool{}
	for index, group := range plan.TrialGroups {
		if group.ID == "" {
			return RolloutPlan{}, fmt.Errorf("rollout plan: trial group at public order %d: id is empty", index)
		}
		if seenGroups[group.ID] {
			return RolloutPlan{}, fmt.Errorf("rollout plan: trial group %q: duplicate id", group.ID)
		}
		seenGroups[group.ID] = true
		if err := validateScopeCondition(group.Condition); err != nil {
			return RolloutPlan{}, fmt.Errorf("rollout plan: trial group %q: %v", group.ID, err)
		}
		approved.TrialGroups = append(approved.TrialGroups, TrialGroup{
			ID:          group.ID,
			Description: group.Description,
			Condition:   cloneCondition(group.Condition),
		})
	}
	seenScopes := map[string]bool{}
	for index, scope := range plan.ProtectedScopes {
		if scope.ID == "" {
			return RolloutPlan{}, fmt.Errorf("rollout plan: protected scope at public order %d: id is empty", index)
		}
		if seenScopes[scope.ID] {
			return RolloutPlan{}, fmt.Errorf("rollout plan: protected scope %q: duplicate id", scope.ID)
		}
		seenScopes[scope.ID] = true
		if err := validateScopeCondition(scope.Condition); err != nil {
			return RolloutPlan{}, fmt.Errorf("rollout plan: protected scope %q: %v", scope.ID, err)
		}
		approved.ProtectedScopes = append(approved.ProtectedScopes, ProtectedScope{
			ID:          scope.ID,
			Description: scope.Description,
			Condition:   cloneCondition(scope.Condition),
		})
	}
	return approved, nil
}

func validateScopeCondition(condition *Condition) error {
	if condition == nil {
		return fmt.Errorf("condition is empty")
	}
	if err := validateCondition(condition, map[string]bool{}); err != nil {
		return err
	}
	if refs := conditionRefs(condition); len(refs) > 0 {
		return fmt.Errorf("scope conditions cannot use ref (%q)", refs[0])
	}
	return nil
}
