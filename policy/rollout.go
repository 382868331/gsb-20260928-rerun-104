package policy

import (
	"fmt"
	"sort"
)

// RolloutStatus describes the lifecycle state of a scoped rollout.
type RolloutStatus string

const (
	// RolloutPlanned means an impact plan was computed but not yet approved;
	// the candidate does not adjudicate any request.
	RolloutPlanned RolloutStatus = "planned"
	// RolloutApproved means the grouping plan was explicitly approved and
	// eligible requests may be adjudicated by the candidate.
	RolloutApproved RolloutStatus = "approved"
	// RolloutHalted means dependency changes or quota exhaustion stopped new
	// candidate adoptions; past adjudications are retained.
	RolloutHalted RolloutStatus = "halted"
	// RolloutWithdrawn means the maintainer urgently withdrew the rollout;
	// past adjudications are retained.
	RolloutWithdrawn RolloutStatus = "withdrawn"
)

// TrialGroup names one non-confusable segment of requests, selected by a
// condition over request attributes. A request matching more than one trial
// group is a conflict and stays on the original rules.
type TrialGroup struct {
	ID        string
	Condition *Condition
}

// ScopedRolloutSpec is the maintainer-defined scope for a candidate rollout:
// mutually exclusive trial groups, reserved scopes that must keep the
// original rules, and the maximum business exposure (distinct requests the
// candidate may adjudicate).
type ScopedRolloutSpec struct {
	CandidateID string
	Groups      []TrialGroup
	Reserved    []TrialGroup
	MaxExposure int
}

// RolloutImpact flags one observed request whose decision may change because
// of a deny change or unknown (missing) attributes under the candidate.
type RolloutImpact struct {
	RequestID string
	GroupID   string
	Kind      DifferenceKind
}

// ScopedRolloutPlan is the computed grouping plan: which observed requests
// are eligible, which are reserved to the original rules, which are
// conflicts (matched multiple trial groups), and which may be impacted.
type ScopedRolloutPlan struct {
	CandidateID string
	Impacts     []RolloutImpact
	Eligible    []string
	Reserved    []string
	Conflicts   []string
}

// RolloutRecord preserves one adjudication made under a scoped rollout,
// including which side decided and the rule versions in force at the time.
type RolloutRecord struct {
	RequestID        string
	GroupID          string
	AdjudicatedBy    string
	Decision         Decision
	BaseVersion      int
	CandidateVersion int
}

const (
	// AdjudicatedByCandidate marks a request decided by the candidate rules.
	AdjudicatedByCandidate = "candidate"
	// AdjudicatedByOriginal marks a request that stayed on the original rules.
	AdjudicatedByOriginal = "original"
)

// RolloutInfo is a read-only summary of one scoped rollout.
type RolloutInfo struct {
	CandidateID string
	Status      RolloutStatus
	Exposure    int
	MaxExposure int
	Records     int
	Reason      string
}

// Rollout is the internal state of one scoped rollout.
type Rollout struct {
	spec        ScopedRolloutSpec
	status      RolloutStatus
	reason      string
	exposure    int
	assignments map[string]RolloutRecord
	order       []string
}

// PlanScopedRollout validates the scope and computes, from the candidate's
// confirmed and non-stale observation records, which requests may be
// affected by deny changes or unknown attributes. The plan is stored as the
// pending plan; nothing adjudicates until ApproveScopedRollout.
func (e *Engine) PlanScopedRollout(spec ScopedRolloutSpec) (*ScopedRolloutPlan, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := validateRolloutSpec(spec); err != nil {
		return nil, err
	}
	observation, ok := e.observations[spec.CandidateID]
	if !ok {
		return nil, fmt.Errorf("candidate %q has no observation", spec.CandidateID)
	}

	plan := &ScopedRolloutPlan{CandidateID: spec.CandidateID}
	seen := map[string]bool{}
	for _, record := range observation.records {
		if !record.Confirmed || record.Stale || seen[record.RequestID] {
			continue
		}
		seen[record.RequestID] = true
		if matchesAnyScope(spec.Reserved, record.Attributes) {
			plan.Reserved = append(plan.Reserved, record.RequestID)
			continue
		}
		groupID, conflict := assignTrialGroup(spec.Groups, record.Attributes)
		if conflict {
			plan.Conflicts = append(plan.Conflicts, record.RequestID)
			continue
		}
		if groupID == "" {
			continue
		}
		plan.Eligible = append(plan.Eligible, record.RequestID)
		kind := classifyDifference(record.Current, record.Candidate)
		if kind == DifferenceExplicitDeny || kind == DifferenceUnknownDriven {
			plan.Impacts = append(plan.Impacts, RolloutImpact{
				RequestID: record.RequestID,
				GroupID:   groupID,
				Kind:      kind,
			})
		}
	}

	if e.rollouts == nil {
		e.rollouts = map[string]*Rollout{}
	}
	e.rollouts[spec.CandidateID] = &Rollout{
		spec:        cloneRolloutSpec(spec),
		status:      RolloutPlanned,
		assignments: map[string]RolloutRecord{},
	}
	copied := *plan
	return &copied, nil
}

// ApproveScopedRollout explicitly approves the previously computed grouping
// plan. Only after approval may the candidate adjudicate eligible requests.
func (e *Engine) ApproveScopedRollout(candidateID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	rollout, ok := e.rollouts[candidateID]
	if !ok {
		return fmt.Errorf("candidate %q has no scoped rollout plan", candidateID)
	}
	if rollout.status != RolloutPlanned {
		return fmt.Errorf("candidate %q rollout is %s, not planned", candidateID, rollout.status)
	}
	rollout.status = RolloutApproved
	return nil
}

// Adjudicate routes one request through the scoped rollout. The candidate
// decides only requests that are approved, still eligible (exactly one trial
// group, no reserved scope), and within the exposure quota; every other
// request keeps the original rules. Repeating the same request ID returns
// the original assignment and decision without increasing exposure.
func (e *Engine) Adjudicate(candidateID, requestID string, attributes map[string]any) (Decision, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	rollout, ok := e.rollouts[candidateID]
	if !ok {
		return Decision{}, fmt.Errorf("candidate %q has no scoped rollout plan", candidateID)
	}
	if record, exists := rollout.assignments[requestID]; exists {
		return cloneDecision(record.Decision), nil
	}

	current := e.current.Load()
	fallback := func() (Decision, error) {
		decision := evaluateWith(current, attributes)
		rollout.recordLocked(RolloutRecord{
			RequestID:     requestID,
			AdjudicatedBy: AdjudicatedByOriginal,
			Decision:      cloneDecision(decision),
			BaseVersion:   setVersion(current),
		})
		return decision, nil
	}

	if rollout.status != RolloutApproved {
		return fallback()
	}
	observation, err := e.activeObservationLocked(candidateID)
	if err != nil {
		return fallback()
	}
	if matchesAnyScope(rollout.spec.Reserved, attributes) {
		return fallback()
	}
	groupID, conflict := assignTrialGroup(rollout.spec.Groups, attributes)
	if conflict || groupID == "" {
		return fallback()
	}
	if rollout.exposure >= rollout.spec.MaxExposure {
		rollout.haltLocked(fmt.Sprintf("exposure quota %d exhausted", rollout.spec.MaxExposure))
		return fallback()
	}

	decision := observation.candidate.Evaluate(attributes)
	rollout.exposure++
	rollout.recordLocked(RolloutRecord{
		RequestID:        requestID,
		GroupID:          groupID,
		AdjudicatedBy:    AdjudicatedByCandidate,
		Decision:         cloneDecision(decision),
		BaseVersion:      setVersion(current),
		CandidateVersion: observation.candidate.version,
	})
	return decision, nil
}

// WithdrawRollout urgently stops new candidate adoptions. Adjudications
// already made, and the rule versions they used, are retained.
func (e *Engine) WithdrawRollout(candidateID, reason string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	rollout, ok := e.rollouts[candidateID]
	if !ok {
		return fmt.Errorf("candidate %q has no scoped rollout plan", candidateID)
	}
	if rollout.status == RolloutWithdrawn {
		return fmt.Errorf("candidate %q rollout is already withdrawn", candidateID)
	}
	rollout.status = RolloutWithdrawn
	rollout.reason = reason
	return nil
}

// RolloutRecords returns deep copies of all adjudications in arrival order.
func (e *Engine) RolloutRecords(candidateID string) ([]RolloutRecord, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	rollout, ok := e.rollouts[candidateID]
	if !ok {
		return nil, fmt.Errorf("candidate %q has no scoped rollout plan", candidateID)
	}
	records := make([]RolloutRecord, 0, len(rollout.order))
	for _, requestID := range rollout.order {
		records = append(records, cloneRolloutRecord(rollout.assignments[requestID]))
	}
	return records, nil
}

// RolloutInfos summarizes all known scoped rollouts.
func (e *Engine) RolloutInfos() []RolloutInfo {
	e.mu.Lock()
	defer e.mu.Unlock()
	infos := make([]RolloutInfo, 0, len(e.rollouts))
	for _, rollout := range e.rollouts {
		infos = append(infos, rollout.info())
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].CandidateID < infos[j].CandidateID })
	return infos
}

func (r *Rollout) info() RolloutInfo {
	return RolloutInfo{
		CandidateID: r.spec.CandidateID,
		Status:      r.status,
		Exposure:    r.exposure,
		MaxExposure: r.spec.MaxExposure,
		Records:     len(r.order),
		Reason:      r.reason,
	}
}

func (r *Rollout) recordLocked(record RolloutRecord) {
	if _, exists := r.assignments[record.RequestID]; exists {
		return
	}
	r.assignments[record.RequestID] = record
	r.order = append(r.order, record.RequestID)
}

func (r *Rollout) haltLocked(reason string) {
	if r.status != RolloutApproved && r.status != RolloutPlanned {
		return
	}
	r.status = RolloutHalted
	r.reason = reason
}

// haltRolloutsLocked stops new candidate adoptions when the rules a rollout
// depends on move. Past adjudications and their versions are retained.
func (e *Engine) haltRolloutsLocked(reason string) {
	for _, rollout := range e.rollouts {
		rollout.haltLocked(reason)
	}
}

func validateRolloutSpec(spec ScopedRolloutSpec) error {
	if spec.CandidateID == "" {
		return fmt.Errorf("candidate id is empty")
	}
	if len(spec.Groups) == 0 {
		return fmt.Errorf("scoped rollout needs at least one trial group")
	}
	if spec.MaxExposure <= 0 {
		return fmt.Errorf("max exposure must be positive")
	}
	if err := validateTrialGroups("trial group", spec.Groups); err != nil {
		return err
	}
	return validateTrialGroups("reserved scope", spec.Reserved)
}

func validateTrialGroups(label string, groups []TrialGroup) error {
	seen := map[string]bool{}
	for _, group := range groups {
		if group.ID == "" {
			return fmt.Errorf("%s id is empty", label)
		}
		if seen[group.ID] {
			return fmt.Errorf("%s %q: duplicate id", label, group.ID)
		}
		seen[group.ID] = true
		if err := validateCondition(group.Condition, map[string]bool{}); err != nil {
			return fmt.Errorf("%s %q: %v", label, group.ID, err)
		}
		if refs := conditionRefs(group.Condition); len(refs) > 0 {
			return fmt.Errorf("%s %q: scope conditions cannot use ref", label, group.ID)
		}
	}
	return nil
}

// assignTrialGroup returns the single trial group matching the attributes.
// A condition that stays unknown (missing attributes) does not match. More
// than one definite match is a conflict: the groups are confusable and the
// request must stay on the original rules.
func assignTrialGroup(groups []TrialGroup, attributes map[string]any) (string, bool) {
	matched := ""
	for _, group := range groups {
		ok, _, known := evaluateConditionInGroup(group.Condition, attributes, compiledGroup{}, map[string]bool{})
		if !known || !ok {
			continue
		}
		if matched != "" {
			return "", true
		}
		matched = group.ID
	}
	return matched, false
}

func matchesAnyScope(groups []TrialGroup, attributes map[string]any) bool {
	for _, group := range groups {
		ok, _, known := evaluateConditionInGroup(group.Condition, attributes, compiledGroup{}, map[string]bool{})
		if known && ok {
			return true
		}
	}
	return false
}

func evaluateWith(set *RuleSet, attributes map[string]any) Decision {
	if set == nil {
		return Decision{Allowed: false, Effect: EffectDeny, Version: 0}
	}
	return set.Evaluate(attributes)
}

func cloneRolloutSpec(spec ScopedRolloutSpec) ScopedRolloutSpec {
	copied := spec
	copied.Groups = cloneTrialGroups(spec.Groups)
	copied.Reserved = cloneTrialGroups(spec.Reserved)
	return copied
}

func cloneTrialGroups(groups []TrialGroup) []TrialGroup {
	if groups == nil {
		return nil
	}
	copied := make([]TrialGroup, len(groups))
	for index, group := range groups {
		copied[index] = TrialGroup{ID: group.ID, Condition: cloneCondition(group.Condition)}
	}
	return copied
}

func cloneRolloutRecord(record RolloutRecord) RolloutRecord {
	record.Decision = cloneDecision(record.Decision)
	return record
}
