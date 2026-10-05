package policy

import (
	"fmt"
	"sort"
)

// ObservationStatus describes the lifecycle state of an observed candidate.
type ObservationStatus string

const (
	ObservationActive    ObservationStatus = "active"
	ObservationAbandoned ObservationStatus = "abandoned"
	ObservationPublished ObservationStatus = "published"
)

// ObservationRecord captures one request evaluated against the current and
// the candidate rule sets at the same time. Only the current decision
// adjudicates business; the candidate side is observational. The record keeps
// a deep copy of the attributes available at request time and is immutable:
// querying or exporting records never rewrites stored history.
type ObservationRecord struct {
	ID               int64
	CandidateID      string
	RequestID        string
	Attributes       map[string]any
	Current          Decision
	Candidate        Decision
	BaseVersion      int
	CandidateVersion int
	Confirmed        bool
	Stale            bool
	StaleReason      string
}

// Observation is the internal state of one observed candidate.
type Observation struct {
	id             string
	status         ObservationStatus
	candidate      *RuleSet
	records        []ObservationRecord
	abandonReason  string
	abandonedCount int
}

// ObservationInfo is a read-only summary of one observed candidate.
type ObservationInfo struct {
	CandidateID      string
	Status           ObservationStatus
	CandidateVersion int
	Records          int
	ConfirmedRecords int
	StaleRecords     int
	AbandonReason    string
}

// DifferenceKind classifies how two candidates diverge on the same request.
type DifferenceKind string

const (
	// DifferenceNone means both candidates reached an equivalent decision.
	DifferenceNone DifferenceKind = "none"
	// DifferenceExplicitDeny means both sides are definite and at least one
	// side is a definite deny: a real adjudication change, not missing data.
	DifferenceExplicitDeny DifferenceKind = "explicit_deny_change"
	// DifferenceExplicitChange means both sides are definite and differ for
	// another reason (effect or winning rule changed).
	DifferenceExplicitChange DifferenceKind = "explicit_change"
	// DifferenceUnknownDriven means at least one side stayed unknown, so the
	// difference comes from missing information rather than a definite flip.
	DifferenceUnknownDriven DifferenceKind = "unknown_difference"
)

// CandidateDifference compares two observed candidates on one shared request.
type CandidateDifference struct {
	RequestID string
	Kind      DifferenceKind
	A         Decision
	B         Decision
}

// CandidateComparison aligns two candidates on the requests both observed.
type CandidateComparison struct {
	CandidateA  string
	CandidateB  string
	Differences []CandidateDifference
	Shared      int
	Divergent   int
}

// StartObservation compiles candidate groups and begins shadow-observing them
// against the current rule set. The candidate never adjudicates business.
func (e *Engine) StartObservation(candidateID string, groups []RuleGroup) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if candidateID == "" {
		return fmt.Errorf("candidate id is empty")
	}
	if e.observations == nil {
		e.observations = map[string]*Observation{}
	}
	if existing, ok := e.observations[candidateID]; ok && existing.status == ObservationActive {
		return fmt.Errorf("candidate %q already has an active observation; resume or abandon it first", candidateID)
	}
	e.candidateSeq++
	candidate, err := CompileGroups(e.candidateSeq, groups)
	if err != nil {
		return err
	}
	e.observations[candidateID] = &Observation{
		id:        candidateID,
		status:    ObservationActive,
		candidate: candidate,
	}
	return nil
}

// Observe evaluates the request with the current rule set (the only business
// adjudication) and records both the current and candidate conclusions with
// their group contributions. Attributes are snapshotted at request time.
func (e *Engine) Observe(candidateID, requestID string, attributes map[string]any) (Decision, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	observation, err := e.activeObservationLocked(candidateID)
	if err != nil {
		return Decision{}, err
	}
	current := e.current.Load()
	var currentDecision Decision
	baseVersion := 0
	if current != nil {
		currentDecision = current.Evaluate(attributes)
		baseVersion = current.version
	} else {
		currentDecision = Decision{Allowed: false, Effect: EffectDeny, Version: 0}
	}
	candidateDecision := observation.candidate.Evaluate(attributes)

	e.obsSeq++
	observation.records = append(observation.records, ObservationRecord{
		ID:               e.obsSeq,
		CandidateID:      candidateID,
		RequestID:        requestID,
		Attributes:       cloneAttributes(attributes),
		Current:          cloneDecision(currentDecision),
		Candidate:        cloneDecision(candidateDecision),
		BaseVersion:      baseVersion,
		CandidateVersion: observation.candidate.version,
	})
	return currentDecision, nil
}

// ObservationRecords returns deep copies of the stored records. Exporting or
// inspecting them cannot mutate the retained history.
func (e *Engine) ObservationRecords(candidateID string) ([]ObservationRecord, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	observation, ok := e.observations[candidateID]
	if !ok {
		return nil, fmt.Errorf("candidate %q has no observation", candidateID)
	}
	records := make([]ObservationRecord, len(observation.records))
	for index, record := range observation.records {
		records[index] = cloneObservationRecord(record)
	}
	return records, nil
}

// ObservationInfos summarizes all known candidates, including abandoned ones.
func (e *Engine) ObservationInfos() []ObservationInfo {
	e.mu.Lock()
	defer e.mu.Unlock()
	infos := make([]ObservationInfo, 0, len(e.observations))
	for _, observation := range e.observations {
		infos = append(infos, observation.info())
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].CandidateID < infos[j].CandidateID })
	return infos
}

func (o *Observation) info() ObservationInfo {
	info := ObservationInfo{
		CandidateID:   o.id,
		Status:        o.status,
		AbandonReason: o.abandonReason,
		Records:       len(o.records),
	}
	if o.candidate != nil {
		info.CandidateVersion = o.candidate.version
	}
	for _, record := range o.records {
		if record.Confirmed {
			info.ConfirmedRecords++
		}
		if record.Stale {
			info.StaleRecords++
		}
	}
	return info
}

// ConfirmObservations marks records as reviewed so they can serve as the
// basis of a later formal publish. Stale records cannot be confirmed.
func (e *Engine) ConfirmObservations(candidateID string, recordIDs ...int64) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	observation, ok := e.observations[candidateID]
	if !ok {
		return fmt.Errorf("candidate %q has no observation", candidateID)
	}
	byID := map[int64]bool{}
	for _, id := range recordIDs {
		byID[id] = true
	}
	confirmed := 0
	for index := range observation.records {
		record := &observation.records[index]
		if len(byID) > 0 && !byID[record.ID] {
			continue
		}
		if record.Stale {
			return fmt.Errorf("record %d is stale (%s) and cannot be confirmed", record.ID, record.StaleReason)
		}
		record.Confirmed = true
		confirmed++
	}
	if confirmed == 0 {
		return fmt.Errorf("no matching observation records to confirm")
	}
	return nil
}

// UpdateObservationCandidate replaces the candidate rules mid-observation.
// All existing records depend on the previous candidate and become stale.
func (e *Engine) UpdateObservationCandidate(candidateID string, groups []RuleGroup) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	observation, err := e.activeObservationLocked(candidateID)
	if err != nil {
		return err
	}
	e.candidateSeq++
	candidate, err := CompileGroups(e.candidateSeq, groups)
	if err != nil {
		return err
	}
	oldVersion := observation.candidate.version
	observation.candidate = candidate
	observation.markStaleLocked(func(record *ObservationRecord) bool {
		return record.CandidateVersion != candidate.version
	}, fmt.Sprintf("candidate rules changed from version %d to %d", oldVersion, candidate.version))
	return nil
}

// AbandonObservation suspends the observation. Records and the abandon
// rationale are retained so a later resume keeps the explanation basis.
func (e *Engine) AbandonObservation(candidateID, reason string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	observation, err := e.activeObservationLocked(candidateID)
	if err != nil {
		return err
	}
	observation.status = ObservationAbandoned
	observation.abandonReason = reason
	observation.abandonedCount++
	return nil
}

// ResumeObservation reactivates an abandoned candidate. Confirmed records and
// the recorded abandon rationale are kept; records already marked stale stay
// stale because the dependencies they were computed against did not come back.
func (e *Engine) ResumeObservation(candidateID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	observation, ok := e.observations[candidateID]
	if !ok {
		return fmt.Errorf("candidate %q has no observation", candidateID)
	}
	if observation.status != ObservationAbandoned {
		return fmt.Errorf("candidate %q is %s, not abandoned", candidateID, observation.status)
	}
	observation.status = ObservationActive
	return nil
}

// CompareObservations aligns two candidates on the requests both observed and
// classifies each divergence as an explicit deny change, another explicit
// change, or a difference driven by unknown (missing) information.
func (e *Engine) CompareObservations(candidateA, candidateB string) (*CandidateComparison, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	first, ok := e.observations[candidateA]
	if !ok {
		return nil, fmt.Errorf("candidate %q has no observation", candidateA)
	}
	second, ok := e.observations[candidateB]
	if !ok {
		return nil, fmt.Errorf("candidate %q has no observation", candidateB)
	}
	byRequest := map[string]ObservationRecord{}
	for _, record := range second.records {
		byRequest[record.RequestID] = record
	}
	comparison := &CandidateComparison{CandidateA: candidateA, CandidateB: candidateB}
	seen := map[string]bool{}
	for _, recordA := range first.records {
		if seen[recordA.RequestID] {
			continue
		}
		recordB, shared := byRequest[recordA.RequestID]
		if !shared {
			continue
		}
		seen[recordA.RequestID] = true
		comparison.Shared++
		difference := CandidateDifference{
			RequestID: recordA.RequestID,
			Kind:      classifyDifference(recordA.Candidate, recordB.Candidate),
			A:         cloneDecision(recordA.Candidate),
			B:         cloneDecision(recordB.Candidate),
		}
		if difference.Kind != DifferenceNone {
			comparison.Divergent++
		}
		comparison.Differences = append(comparison.Differences, difference)
	}
	return comparison, nil
}

func classifyDifference(a, b Decision) DifferenceKind {
	if decisionsEquivalent(a, b) {
		return DifferenceNone
	}
	// A difference is explicit only when both sides reached a definite
	// verdict; otherwise missing information drove the divergence.
	if a.Matched && b.Matched {
		if a.Effect == EffectDeny || b.Effect == EffectDeny {
			return DifferenceExplicitDeny
		}
		return DifferenceExplicitChange
	}
	return DifferenceUnknownDriven
}

// PublishObservation formally publishes the candidate. Publishing requires at
// least one confirmed, non-stale observation: stale conclusions can never be
// the direct basis of a release. The release record states the actual basis
// scope (confirmed records and the base version they were observed against).
func (e *Engine) PublishObservation(candidateID string) (*RuleSet, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	observation, err := e.activeObservationLocked(candidateID)
	if err != nil {
		return nil, err
	}
	var confirmed, staleConfirmed, baseVersion int
	for _, record := range observation.records {
		if !record.Confirmed {
			continue
		}
		if record.Stale {
			staleConfirmed++
			continue
		}
		confirmed++
		baseVersion = record.BaseVersion
	}
	if staleConfirmed > 0 {
		return nil, fmt.Errorf("candidate %q has %d confirmed but stale observations; re-observe before publishing", candidateID, staleConfirmed)
	}
	if confirmed == 0 {
		return nil, fmt.Errorf("candidate %q has no confirmed observations to publish from", candidateID)
	}

	current := e.current.Load()
	candidate := observation.candidate
	candidate.version = e.nextVersionLocked()
	e.current.Store(candidate)
	reason := fmt.Sprintf(
		"published observed candidate %q: basis is %d confirmed observations recorded against base version %d (candidate version %d)",
		candidateID, confirmed, baseVersion, candidate.version)
	e.history = append(e.history, ReleaseRecord{
		Action:   ReleaseActionPublish,
		From:     current,
		To:       candidate,
		Version:  candidate.version,
		Previous: setVersion(current),
		Reason:   reason,
	})
	observation.status = ObservationPublished
	e.markObservationsStaleLocked(candidate.version, "formal rule set changed")
	return candidate, nil
}

func (e *Engine) activeObservationLocked(candidateID string) (*Observation, error) {
	observation, ok := e.observations[candidateID]
	if !ok {
		return nil, fmt.Errorf("candidate %q has no observation", candidateID)
	}
	if observation.status != ObservationActive {
		return nil, fmt.Errorf("candidate %q observation is %s", candidateID, observation.status)
	}
	return observation, nil
}

// markObservationsStaleLocked flags records whose dependencies moved away.
// It runs at mutation time (publish/withdraw/candidate update), never lazily
// at query time, so reading records cannot rewrite history.
func (e *Engine) markObservationsStaleLocked(newBaseVersion int, reason string) {
	for _, observation := range e.observations {
		if observation.status == ObservationPublished {
			continue
		}
		observation.markStaleLocked(func(record *ObservationRecord) bool {
			return record.BaseVersion != newBaseVersion
		}, fmt.Sprintf("%s: base version moved to %d", reason, newBaseVersion))
	}
}

func (o *Observation) markStaleLocked(stale func(*ObservationRecord) bool, reason string) {
	for index := range o.records {
		record := &o.records[index]
		if record.Stale || !stale(record) {
			continue
		}
		record.Stale = true
		record.StaleReason = reason
	}
}

func cloneAttributes(attributes map[string]any) map[string]any {
	if attributes == nil {
		return nil
	}
	copied := make(map[string]any, len(attributes))
	for key, value := range attributes {
		copied[key] = cloneValue(value)
	}
	return copied
}

func cloneDecision(decision Decision) Decision {
	copied := decision
	if decision.UnknownReasons != nil {
		copied.UnknownReasons = append([]string(nil), decision.UnknownReasons...)
	}
	if decision.Evidence != nil {
		evidence := *decision.Evidence
		evidence.Explanation = append([]string(nil), decision.Evidence.Explanation...)
		copied.Evidence = &evidence
	}
	if decision.Contributions != nil {
		copied.Contributions = make([]GroupContribution, len(decision.Contributions))
		for index, contribution := range decision.Contributions {
			cloned := contribution
			cloned.UnknownFor = append([]string(nil), contribution.UnknownFor...)
			if contribution.Evidence != nil {
				evidence := *contribution.Evidence
				evidence.Explanation = append([]string(nil), contribution.Evidence.Explanation...)
				cloned.Evidence = &evidence
			}
			copied.Contributions[index] = cloned
		}
	}
	return copied
}

func cloneObservationRecord(record ObservationRecord) ObservationRecord {
	copied := record
	copied.Attributes = cloneAttributes(record.Attributes)
	copied.Current = cloneDecision(record.Current)
	copied.Candidate = cloneDecision(record.Candidate)
	return copied
}
