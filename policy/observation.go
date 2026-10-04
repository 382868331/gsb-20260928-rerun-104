package policy

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// CandidateStatus describes the lifecycle state of an observing candidate.
type CandidateStatus string

const (
	// CandidateObserving means shadow observations are still being collected.
	CandidateObserving CandidateStatus = "observing"
	// CandidateAbandoned means the candidate was given up; records stay intact.
	CandidateAbandoned CandidateStatus = "abandoned"
)

// DifferenceKind separates explicit verdict changes from unknown-driven ones.
type DifferenceKind string

const (
	// ObservationSame means current and candidate rules reach the same outcome.
	ObservationSame DifferenceKind = "same"
	// ObservationExplicitChange means both sides reach definite, but different verdicts.
	ObservationExplicitChange DifferenceKind = "explicit_change"
	// ObservationUnknownChange means the difference involves information that stayed unknown.
	ObservationUnknownChange DifferenceKind = "unknown_change"
)

// Candidate is an immutable description of one observation session.
type Candidate struct {
	ID               string
	Status           CandidateStatus
	TargetGroup      string
	BaseVersion      int
	ObservationCount int
	Abandonments     []Abandonment
}

// Abandonment records why a candidate was given up. The explanation stays
// available after the candidate is reopened or published.
type Abandonment struct {
	Reason    string
	RecordIDs []string
}

// ObservationRecord is one frozen, exported shadow observation.
// It captures the attributes available at request time and both verdicts.
// Current rules alone perform business adjudication; the candidate verdict
// is explanatory shadow data.
type ObservationRecord struct {
	ID                  string
	RequestID           string
	Description         string
	Attributes          map[string]any
	FormalVersion       int
	CandidateVersion    int
	Formal              Decision
	Candidate           Decision
	Changed             bool
	Kind                DifferenceKind
	ExplicitDenyChanged bool
	// Stale is derived metadata: the formal groups this observation was
	// compared against have since changed. It never rewrites the verdicts.
	Stale               bool
	ChangedDependencies []string
}

// CandidateRequestComparison compares two candidates on one shared request.
type CandidateRequestComparison struct {
	Request             SavedRequest
	A                   Decision
	B                   Decision
	Changed             bool
	Kind                DifferenceKind
	ExplicitDenyChanged bool
	GroupImpacts        []GroupRequestImpact
}

// CandidateComparison is the side-by-side report for two candidates over
// the same batch of historical requests.
type CandidateComparison struct {
	CandidateA      string
	CandidateB      string
	Requests        []CandidateRequestComparison
	ChangedRequests int
}

// ObservationBasis describes the evidence range actually relied on when a
// candidate is published.
type ObservationBasis struct {
	CandidateID         string
	RecordIDs           []string
	RequestIDs          []string
	FormalVersionRange  [2]int
	PreviouslyAbandoned []Abandonment
	Summary             string
}

type candidateSession struct {
	id           string
	targetGroup  string
	baseVersion  int
	groups       []RuleGroup
	candidate    *RuleSet
	status       CandidateStatus
	records      []storedObservation
	abandonments []Abandonment
	sequence     int
}

type storedObservation struct {
	id        string
	request   SavedRequest
	formalSet *RuleSet
	formal    Decision
	candidate Decision
}

// OpenCandidate validates and starts an observation session for a complete
// candidate rule set. The active (formal) set keeps adjudicating requests.
func (e *Engine) OpenCandidate(id string, groups []RuleGroup) (*Candidate, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("candidate id is empty")
	}
	return e.openCandidateLocked(id, "", cloneGroups(groups))
}

// OpenCandidateGroup starts observation for a candidate that only replaces one
// independent group; the other groups are taken from the formal set.
// During observation the remaining groups may still be formally adjusted.
func (e *Engine) OpenCandidateGroup(id, groupID string, rules []Rule) (*Candidate, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("candidate id is empty")
	}
	current := e.current.Load()
	if current == nil {
		return nil, fmt.Errorf("no active rule set")
	}
	if _, exists := current.byGroup[groupID]; !exists {
		return nil, fmt.Errorf("group %q does not exist in the active rule set", groupID)
	}
	groups := buildGroupsWithReplacement(current, RuleGroup{ID: groupID, Rules: cloneRules(rules)})
	return e.openCandidateLocked(id, groupID, groups)
}

func cloneRules(rules []Rule) []Rule {
	copied := make([]Rule, len(rules))
	for index, rule := range rules {
		copied[index] = cloneRule(rule)
	}
	return copied
}

func buildGroupsWithReplacement(base *RuleSet, replacement RuleGroup) []RuleGroup {
	groups := make([]RuleGroup, 0, len(base.groups))
	for _, group := range base.groups {
		entry := RuleGroup{ID: group.id, Priority: group.priority, Rules: externalRules(group)}
		if group.id == replacement.ID {
			replacement.Priority = group.priority
			entry = replacement
		}
		groups = append(groups, entry)
	}
	return groups
}
func (e *Engine) openCandidateLocked(id, targetGroup string, groups []RuleGroup) (*Candidate, error) {
	if e.candidates == nil {
		e.candidates = map[string]*candidateSession{}
	}
	current := e.current.Load()
	if current == nil {
		return nil, fmt.Errorf("no active rule set")
	}
	if existing, exists := e.candidates[id]; exists {
		if !reflect.DeepEqual(existing.groups, groups) {
			return nil, fmt.Errorf("candidate %q already exists with a different definition; reopen it instead of redefining it", id)
		}
		// Reopening a previously abandoned candidate keeps its confirmed
		// observations and abandonment explanation.
		existing.status = CandidateObserving
		return candidateInfo(existing), nil
	}
	candidate, err := CompileGroups(e.nextCandidateLabelLocked(), groups)
	if err != nil {
		return nil, err
	}
	session := &candidateSession{
		id:          id,
		targetGroup: targetGroup,
		baseVersion: current.version,
		groups:      groups,
		candidate:   candidate,
		status:      CandidateObserving,
	}
	e.candidates[id] = session
	return candidateInfo(session), nil
}

// nextCandidateLabelLocked assigns a non-publishing negative label so
// observation records can identify a candidate build; it never becomes a
// formal version number.
func (e *Engine) nextCandidateLabelLocked() int {
	e.candidateLabel--
	return e.candidateLabel
}

func cloneGroups(groups []RuleGroup) []RuleGroup {
	copied := make([]RuleGroup, len(groups))
	for index, group := range groups {
		copied[index] = RuleGroup{
			ID:          group.ID,
			Description: group.Description,
			Priority:    group.Priority,
			Rules:       make([]Rule, len(group.Rules)),
		}
		for ruleIndex, rule := range group.Rules {
			copied[index].Rules[ruleIndex] = cloneRule(rule)
		}
	}
	return copied
}

func candidateInfo(session *candidateSession) *Candidate {
	info := &Candidate{
		ID:               session.id,
		Status:           session.status,
		TargetGroup:      session.targetGroup,
		BaseVersion:      session.baseVersion,
		ObservationCount: len(session.records),
		Abandonments:     append([]Abandonment(nil), session.abandonments...),
	}
	return info
}

// Observe records a shadow run of one candidate against a real request copy.
// The formal rules alone perform the business adjudication; the returned
// Decision is the formal one and is safe for the caller to enforce. The
// candidate verdict is only retained as observation evidence. Attributes are
// deep-copied, so later mutation by the caller cannot rewrite history.
func (e *Engine) Observe(candidateID string, request SavedRequest) (Decision, *ObservationRecord, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	session, exists := e.candidates[candidateID]
	if !exists {
		return Decision{}, nil, fmt.Errorf("candidate %q does not exist", candidateID)
	}
	if session.status == CandidateAbandoned {
		return Decision{}, nil, fmt.Errorf("candidate %q is abandoned; reopen it before collecting more observations", candidateID)
	}
	formalSet := e.current.Load()
	if formalSet == nil {
		return Decision{}, nil, fmt.Errorf("no active rule set")
	}
	request = cloneSavedRequest(request)
	formal := formalSet.Evaluate(request.Attributes)
	candidate := session.candidate.Evaluate(request.Attributes)
	session.sequence++
	requestID := request.ID
	if requestID == "" {
		requestID = fmt.Sprintf("%s-req-%d", session.id, session.sequence)
		request.ID = requestID
	}
	stored := storedObservation{
		id:        fmt.Sprintf("%s-obs-%d", session.id, session.sequence),
		request:   request,
		formalSet: formalSet,
		formal:    formal,
		candidate: candidate,
	}
	session.records = append(session.records, stored)
	record := e.exportObservationLocked(session, stored)
	return formal, &record, nil
}

func cloneSavedRequest(request SavedRequest) SavedRequest {
	clone := SavedRequest{ID: request.ID, Description: request.Description}
	if request.Attributes != nil {
		clone.Attributes = map[string]any{}
		for key, value := range request.Attributes {
			clone.Attributes[key] = cloneValue(value)
		}
	}
	return clone
}

// Candidate returns a candidate descriptor without touching its history.
func (e *Engine) Candidate(candidateID string) (*Candidate, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	session, exists := e.candidates[candidateID]
	if !exists {
		return nil, fmt.Errorf("candidate %q does not exist", candidateID)
	}
	return candidateInfo(session), nil
}

// Candidates lists observation sessions, abandoned or active.
func (e *Engine) Candidates() []Candidate {
	e.mu.Lock()
	defer e.mu.Unlock()
	result := make([]Candidate, 0, len(e.candidates))
	ids := make([]string, 0, len(e.candidates))
	for id := range e.candidates {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		result = append(result, *candidateInfo(e.candidates[id]))
	}
	return result
}

// Observations exports frozen observation records. Querying never mutates them.
// Stale records are reported with their original verdicts plus a stale marker.
func (e *Engine) Observations(candidateID string) ([]ObservationRecord, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	session, exists := e.candidates[candidateID]
	if !exists {
		return nil, fmt.Errorf("candidate %q does not exist", candidateID)
	}
	records := make([]ObservationRecord, 0, len(session.records))
	for _, stored := range session.records {
		records = append(records, e.exportObservationLocked(session, stored))
	}
	return records, nil
}

// Observation returns one frozen observation record by record id.
func (e *Engine) Observation(candidateID, recordID string) (*ObservationRecord, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	session, exists := e.candidates[candidateID]
	if !exists {
		return nil, fmt.Errorf("candidate %q does not exist", candidateID)
	}
	for _, stored := range session.records {
		if stored.id == recordID {
			record := e.exportObservationLocked(session, stored)
			return &record, nil
		}
	}
	return nil, fmt.Errorf("observation record %q does not exist for candidate %q", recordID, candidateID)
}

func (e *Engine) exportObservationLocked(session *candidateSession, stored storedObservation) ObservationRecord {
	current := e.current.Load()
	changedDependencies := dependencyChanges(stored.formalSet, current)
	record := ObservationRecord{
		ID:                  stored.id,
		RequestID:           stored.request.ID,
		Description:         stored.request.Description,
		Attributes:          cloneSavedRequest(stored.request).Attributes,
		FormalVersion:       stored.formal.Version,
		CandidateVersion:    stored.candidate.Version,
		Formal:              stored.formal,
		Candidate:           stored.candidate,
		Stale:               len(changedDependencies) > 0,
		ChangedDependencies: changedDependencies,
	}
	record.Changed, record.Kind, record.ExplicitDenyChanged = compareDecisions(stored.formal, stored.candidate)
	return record
}

// dependencyChanges reports which formal groups changed between the set pinned
// at observation time and the currently formal set. Only groups present in
// both sets can have "changed"; added/removed groups are reported as well so
// the stale explanation identifies every dependency movement.
func dependencyChanges(pinned, current *RuleSet) []string {
	if pinned == current {
		return nil
	}
	changed := map[string]bool{}
	pinnedIDs := map[string]bool{}
	for _, group := range pinned.groups {
		pinnedIDs[group.id] = true
		currentGroup, exists := current.byGroup[group.id]
		if !exists {
			changed[group.id] = true
			continue
		}
		if !sameGroupDefinition(group, currentGroup) {
			changed[group.id] = true
		}
	}
	for _, group := range current.groups {
		if !pinnedIDs[group.id] {
			changed[group.id] = true
		}
	}
	if len(changed) == 0 {
		return nil
	}
	ids := make([]string, 0, len(changed))
	for id := range changed {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func sameGroupDefinition(left, right compiledGroup) bool {
	if left.priority != right.priority || len(left.rules) != len(right.rules) {
		return false
	}
	leftRules := make([]compiledRule, len(left.rules))
	rightRules := make([]compiledRule, len(right.rules))
	for index := range left.rules {
		leftRules[index] = left.rules[index]
		rightRules[index] = right.rules[index]
	}
	return reflect.DeepEqual(leftRules, rightRules)
}

// compareDecisions separates explicit verdict changes from unknown-driven
// differences. A definite-vs-definite disagreement with a deny on one side
// is flagged as an explicit deny change; anything involving unknown stays
// attributed to missing information.
func compareDecisions(formal, candidate Decision) (changed bool, kind DifferenceKind, explicitDenyChanged bool) {
	formalKey, candidateKey := decisionKey(formal), decisionKey(candidate)
	if formalKey == candidateKey {
		return false, ObservationSame, false
	}
	// The final verdict comes from the first definite group. A difference is
	// unknown-driven only when at least one side has no definite winner at all
	// (all groups unknown); an unknown group that does not adjudicate on one
	// side cannot turn an explicit deny on the other side into "missing info".
	if !formal.Matched || !candidate.Matched {
		return true, ObservationUnknownChange, false
	}
	denyParticipates := formalKey == decisionKeyDeny || candidateKey == decisionKeyDeny
	return true, ObservationExplicitChange, denyParticipates
}

const decisionKeyDeny = "deny"

func decisionKey(decision Decision) string {
	if !decision.Matched {
		return "unmatched"
	}
	if decision.Allowed {
		return "allow"
	}
	return decisionKeyDeny
}

// AbandonCandidate gives up a candidate while retaining its records and the
// explanation. Later reopening keeps every confirmed observation and the
// abandoned history.
func (e *Engine) AbandonCandidate(candidateID, reason string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	session, exists := e.candidates[candidateID]
	if !exists {
		return fmt.Errorf("candidate %q does not exist", candidateID)
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return fmt.Errorf("abandonment reason is required so the explanation stays available later")
	}
	recordIDs := make([]string, 0, len(session.records))
	for _, stored := range session.records {
		recordIDs = append(recordIDs, stored.id)
	}
	session.abandonments = append(session.abandonments, Abandonment{Reason: reason, RecordIDs: recordIDs})
	session.status = CandidateAbandoned
	return nil
}

// ReopenCandidate resumes an abandoned candidate. Confirmed observations and
// prior abandonment explanations are preserved, not reset.
func (e *Engine) ReopenCandidate(candidateID string) (*Candidate, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	session, exists := e.candidates[candidateID]
	if !exists {
		return nil, fmt.Errorf("candidate %q does not exist", candidateID)
	}
	if session.status != CandidateAbandoned {
		return nil, fmt.Errorf("candidate %q is not abandoned", candidateID)
	}
	session.status = CandidateObserving
	return candidateInfo(session), nil
}

// PublishCandidate promotes an observing candidate to the formal version.
// Stale observations (their formal dependencies changed afterwards) block the
// release: expired conclusions can never be published directly.
func (e *Engine) PublishCandidate(candidateID string) (*RuleSet, *ObservationBasis, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	session, exists := e.candidates[candidateID]
	if !exists {
		return nil, nil, fmt.Errorf("candidate %q does not exist", candidateID)
	}
	if session.status == CandidateAbandoned {
		return nil, nil, fmt.Errorf("candidate %q was abandoned; reopen it before publishing", candidateID)
	}
	if len(session.records) == 0 {
		return nil, nil, fmt.Errorf("candidate %q has no observations to publish with", candidateID)
	}
	current := e.current.Load()
	if current == nil {
		return nil, nil, fmt.Errorf("no active rule set")
	}
	var staleIDs []string
	for _, stored := range session.records {
		if changed := dependencyChanges(stored.formalSet, current); len(changed) > 0 {
			staleIDs = append(staleIDs, fmt.Sprintf("%s (changed groups: %s)", stored.id, strings.Join(changed, ",")))
		}
	}
	if len(staleIDs) > 0 {
		return nil, nil, fmt.Errorf("candidate %q cannot be published from expired observations: %s", candidateID, strings.Join(staleIDs, "; "))
	}

	var set *RuleSet
	var err error
	if session.targetGroup != "" {
		set, err = candidateWithReplacedGroup(e.nextVersionLocked(), current, RuleGroup{ID: session.targetGroup, Rules: candidateGroupRules(session, session.targetGroup)})
	} else {
		set, err = CompileGroups(e.nextVersionLocked(), session.groups)
	}
	if err != nil {
		return nil, nil, err
	}
	basis := buildBasis(session)
	e.current.Store(set)
	e.history = append(e.history, ReleaseRecord{
		Action:   ReleaseActionPublish,
		From:     current,
		To:       set,
		Version:  set.version,
		Previous: current.version,
		Reason:   basis.Summary,
		Basis:    &basis,
	})
	// Publishing adopts the candidate; the session stays read-only history.
	session.status = CandidateObserving
	return set, &basis, nil
}

func candidateGroupRules(session *candidateSession, groupID string) []Rule {
	for _, group := range session.groups {
		if group.ID == groupID {
			return cloneRules(group.Rules)
		}
	}
	return nil
}

func buildBasis(session *candidateSession) ObservationBasis {
	basis := ObservationBasis{
		CandidateID: session.id,
		RecordIDs:   make([]string, 0, len(session.records)),
		RequestIDs:  make([]string, 0, len(session.records)),
	}
	minVersion, maxVersion := 0, 0
	for _, stored := range session.records {
		basis.RecordIDs = append(basis.RecordIDs, stored.id)
		basis.RequestIDs = append(basis.RequestIDs, stored.request.ID)
		version := stored.formal.Version
		if minVersion == 0 || version < minVersion {
			minVersion = version
		}
		if version > maxVersion {
			maxVersion = version
		}
	}
	basis.FormalVersionRange = [2]int{minVersion, maxVersion}
	basis.PreviouslyAbandoned = append([]Abandonment(nil), session.abandonments...)
	basis.Summary = fmt.Sprintf(
		"published candidate %q on the basis of %d fresh observation(s) over formal versions %d..%d; %d prior abandonment(s) retained",
		session.id, len(session.records), minVersion, maxVersion, len(session.abandonments),
	)
	return basis
}

// CompareCandidates runs two candidates over the same batch of historical
// requests. With an empty request batch it uses the requests observed by both
// candidates. Explicit verdict changes and unknown-driven differences are
// reported separately.
func (e *Engine) CompareCandidates(candidateA, candidateB string, requests []SavedRequest) (*CandidateComparison, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	sessionA, exists := e.candidates[candidateA]
	if !exists {
		return nil, fmt.Errorf("candidate %q does not exist", candidateA)
	}
	sessionB, exists := e.candidates[candidateB]
	if !exists {
		return nil, fmt.Errorf("candidate %q does not exist", candidateB)
	}
	if len(requests) == 0 {
		requests = sharedObservedRequests(sessionA, sessionB)
	}
	comparison := &CandidateComparison{CandidateA: candidateA, CandidateB: candidateB}
	for _, request := range requests {
		request = cloneSavedRequest(request)
		decisionA := sessionA.candidate.Evaluate(request.Attributes)
		decisionB := sessionB.candidate.Evaluate(request.Attributes)
		changed, kind, explicitDeny := compareDecisions(decisionA, decisionB)
		entry := CandidateRequestComparison{
			Request:             request,
			A:                   decisionA,
			B:                   decisionB,
			Changed:             changed,
			Kind:                kind,
			ExplicitDenyChanged: explicitDeny,
			GroupImpacts:        compareGroupImpacts(request, sessionA.candidate, sessionB.candidate),
		}
		if changed {
			comparison.ChangedRequests++
		}
		comparison.Requests = append(comparison.Requests, entry)
	}
	return comparison, nil
}

func sharedObservedRequests(sessionA, sessionB *candidateSession) []SavedRequest {
	byB := map[string]SavedRequest{}
	for _, stored := range sessionB.records {
		byB[stored.request.ID] = stored.request
	}
	seen := map[string]bool{}
	var requests []SavedRequest
	for _, stored := range sessionA.records {
		if request, exists := byB[stored.request.ID]; exists && !seen[request.ID] {
			seen[request.ID] = true
			requests = append(requests, request)
		}
	}
	return requests
}

func compareGroupImpacts(request SavedRequest, setA, setB *RuleSet) []GroupRequestImpact {
	impacts, _ := groupImpacts(request, setA, setB)
	return impacts
}
