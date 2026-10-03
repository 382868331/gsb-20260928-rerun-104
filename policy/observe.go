package policy

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// DifferenceKind classifies why the shadow candidate disagreed with the
// authoritative decision for one observed request.
type DifferenceKind string

const (
	// DifferenceNone means both sides reached an equivalent decision.
	DifferenceNone DifferenceKind = "none"
	// DifferenceVerdict means a definite allow/deny flip with known attributes.
	DifferenceVerdict DifferenceKind = "verdict_change"
	// DifferenceUnknown means the divergence stems from unknown information
	// (missing or unusable attributes), not from a definite verdict flip.
	DifferenceUnknown DifferenceKind = "unknown_change"
)

// ObservationRecord keeps one shadow evaluation of a real request copy.
// The candidate side never adjudicates; only Current drives business effects.
type ObservationRecord struct {
	Sequence      int
	ActiveVersion int
	CandidateID   string
	Attributes    map[string]any
	Current       Decision
	Candidate     Decision
	Changed       bool
	Difference    DifferenceKind
	Causes        []ImpactCause
	Stale         bool
	StaleReason   string
}

// ObservationBasis records the full range of observations a candidate
// publication relied on, excluding stale records.
type ObservationBasis struct {
	CandidateID    string
	FromSequence   int
	ToSequence     int
	RecordCount    int
	StaleExcluded  int
	ActiveVersions []int
}

// ObservationSnapshot exports an observation session so it can be resumed
// after a restart without losing the recorded differences.
type ObservationSnapshot struct {
	CandidateID string
	Groups      []RuleGroup
	Records     []ObservationRecord
}

// ComparedRequest replays one historical request against two candidates.
type ComparedRequest struct {
	SourceCandidate string
	SourceSequence  int
	Attributes      map[string]any
	First           Decision
	Second          Decision
	Changed         bool
	Difference      DifferenceKind
}

// CandidateComparison contrasts two candidates on the same historical requests.
type CandidateComparison struct {
	FirstID         string
	SecondID        string
	Requests        []ComparedRequest
	ChangedRequests int
}

type observedCandidate struct {
	id          string
	groups      []RuleGroup
	set         *RuleSet
	baseVersion int
	dependsOn   []string
	abandoned   bool
	records     []ObservationRecord
}

// StartObservation registers a shadow candidate. The candidate's own groups
// replace same-id groups; every other active group is reused and recorded as
// a dependency. Nothing about the authoritative decision changes.
func (e *Engine) StartObservation(id string, groups []RuleGroup) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("candidate id is empty")
	}
	e.obsMu.Lock()
	defer e.obsMu.Unlock()
	if e.candidates == nil {
		e.candidates = map[string]*observedCandidate{}
	}
	if existing, ok := e.candidates[id]; ok && !existing.abandoned {
		return fmt.Errorf("candidate %q is already under observation", id)
	}
	set, depends, err := buildShadowSet(e.current.Load(), groups)
	if err != nil {
		return err
	}
	e.candidates[id] = &observedCandidate{
		id:          id,
		groups:      cloneGroups(groups),
		set:         set,
		baseVersion: e.Version(),
		dependsOn:   depends,
	}
	return nil
}

// Observe evaluates one real request against the active set (authoritative)
// and every active candidate (shadow). Only the authoritative Decision is
// returned; candidate allows never trigger business effects. Each candidate
// records the request attributes available at observation time together with
// both sides' per-group contributions.
func (e *Engine) Observe(request map[string]any) Decision {
	set := e.current.Load()
	var decision Decision
	if set == nil {
		decision = Decision{Allowed: false, Effect: EffectDeny}
	} else {
		decision = set.Evaluate(request)
	}

	e.obsMu.Lock()
	defer e.obsMu.Unlock()
	for _, id := range e.sortedCandidateIDsLocked() {
		cand := e.candidates[id]
		if cand.abandoned {
			continue
		}
		shadow := cand.set.Evaluate(request)
		e.obsSeq++
		record := ObservationRecord{
			Sequence:      e.obsSeq,
			ActiveVersion: decision.Version,
			CandidateID:   id,
			Attributes:    cloneAttributes(request),
			Current:       decision,
			Candidate:     shadow,
		}
		record.Changed = !decisionsEquivalent(decision, shadow)
		record.Difference = classifyDifference(decision, shadow, record.Changed)
		if record.Changed {
			saved := SavedRequest{ID: fmt.Sprintf("obs-%d", record.Sequence), Attributes: request}
			_, changedGroups := groupImpacts(saved, set, cand.set)
			record.Causes = attributeImpact(request, set, cand.set, RequestImpact{
				Before:        decision,
				After:         shadow,
				Changed:       true,
				ChangedGroups: changedGroups,
			})
		}
		cand.records = append(cand.records, record)
	}
	return decision
}

// ExplainCandidate returns the recorded observations of a candidate, including
// after it has been abandoned, so past differences remain explainable.
func (e *Engine) ExplainCandidate(id string) ([]ObservationRecord, error) {
	e.obsMu.Lock()
	defer e.obsMu.Unlock()
	cand, ok := e.candidates[id]
	if !ok {
		return nil, fmt.Errorf("candidate %q is not registered", id)
	}
	records := make([]ObservationRecord, len(cand.records))
	copy(records, cand.records)
	return records, nil
}

// AbandonCandidate stops shadow evaluation for a candidate while retaining
// its records for later explanation.
func (e *Engine) AbandonCandidate(id string) error {
	e.obsMu.Lock()
	defer e.obsMu.Unlock()
	cand, ok := e.candidates[id]
	if !ok {
		return fmt.Errorf("candidate %q is not registered", id)
	}
	cand.abandoned = true
	return nil
}

// CompareCandidates replays the historical requests recorded by either
// candidate against both candidate rule sets and reports where they diverge.
func (e *Engine) CompareCandidates(firstID, secondID string) (*CandidateComparison, error) {
	e.obsMu.Lock()
	defer e.obsMu.Unlock()
	first, ok := e.candidates[firstID]
	if !ok {
		return nil, fmt.Errorf("candidate %q is not registered", firstID)
	}
	second, ok := e.candidates[secondID]
	if !ok {
		return nil, fmt.Errorf("candidate %q is not registered", secondID)
	}
	report := &CandidateComparison{FirstID: firstID, SecondID: secondID}
	sources := []struct {
		id      string
		records []ObservationRecord
	}{{firstID, first.records}, {secondID, second.records}}
	for _, source := range sources {
		for _, record := range source.records {
			entry := ComparedRequest{
				SourceCandidate: source.id,
				SourceSequence:  record.Sequence,
				Attributes:      cloneAttributes(record.Attributes),
				First:           first.set.Evaluate(record.Attributes),
				Second:          second.set.Evaluate(record.Attributes),
			}
			entry.Changed = !decisionsEquivalent(entry.First, entry.Second)
			entry.Difference = classifyDifference(entry.First, entry.Second, entry.Changed)
			if entry.Changed {
				report.ChangedRequests++
			}
			report.Requests = append(report.Requests, entry)
		}
	}
	return report, nil
}

// PublishCandidate publishes a candidate that has been under observation.
// The release record carries the full observation basis (sequence range and
// active versions covered). Records marked stale because a depended-on group
// changed are excluded; a candidate whose observations are all stale cannot
// be published directly from those old conclusions.
func (e *Engine) PublishCandidate(id string) (*RuleSet, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.obsMu.Lock()
	cand, ok := e.candidates[id]
	if !ok {
		e.obsMu.Unlock()
		return nil, fmt.Errorf("candidate %q is not registered", id)
	}
	if cand.abandoned {
		e.obsMu.Unlock()
		return nil, fmt.Errorf("candidate %q has been abandoned", id)
	}
	basis, err := observationBasis(cand)
	if err != nil {
		e.obsMu.Unlock()
		return nil, err
	}
	ownGroups := cloneGroups(cand.groups)
	e.obsMu.Unlock()

	current := e.current.Load()
	set, _, err := buildShadowSet(current, ownGroups)
	if err != nil {
		return nil, err
	}
	compiled, err := CompileGroups(e.nextVersionLocked(), externalGroups(set))
	if err != nil {
		return nil, err
	}
	e.current.Store(compiled)
	e.history = append(e.history, ReleaseRecord{
		Action:   ReleaseActionPublish,
		From:     current,
		To:       compiled,
		Version:  compiled.version,
		Previous: setVersion(current),
		Reason:   fmt.Sprintf("published observed candidate %q", id),
		Basis:    basis,
	})

	e.obsMu.Lock()
	delete(e.candidates, id)
	e.obsMu.Unlock()
	e.refreshObservations(changedGroupIDs(current, compiled))
	return compiled, nil
}

// ExportObservation snapshots a candidate session for later resumption.
func (e *Engine) ExportObservation(id string) (ObservationSnapshot, error) {
	e.obsMu.Lock()
	defer e.obsMu.Unlock()
	cand, ok := e.candidates[id]
	if !ok {
		return ObservationSnapshot{}, fmt.Errorf("candidate %q is not registered", id)
	}
	snapshot := ObservationSnapshot{
		CandidateID: id,
		Groups:      cloneGroups(cand.groups),
		Records:     make([]ObservationRecord, len(cand.records)),
	}
	copy(snapshot.Records, cand.records)
	return snapshot, nil
}

// ResumeObservation restores an exported session after a restart. The
// candidate is recompiled against the current active set, recorded
// differences (including stale markers) are kept, and sequence numbering
// continues so a later publication still covers the full basis range.
func (e *Engine) ResumeObservation(snapshot ObservationSnapshot) error {
	id := strings.TrimSpace(snapshot.CandidateID)
	if id == "" {
		return fmt.Errorf("candidate id is empty")
	}
	e.obsMu.Lock()
	defer e.obsMu.Unlock()
	if e.candidates == nil {
		e.candidates = map[string]*observedCandidate{}
	}
	if existing, ok := e.candidates[id]; ok && !existing.abandoned {
		return fmt.Errorf("candidate %q is already under observation", id)
	}
	set, depends, err := buildShadowSet(e.current.Load(), snapshot.Groups)
	if err != nil {
		return err
	}
	records := make([]ObservationRecord, len(snapshot.Records))
	copy(records, snapshot.Records)
	for _, record := range records {
		if record.Sequence > e.obsSeq {
			e.obsSeq = record.Sequence
		}
	}
	e.candidates[id] = &observedCandidate{
		id:          id,
		groups:      cloneGroups(snapshot.Groups),
		set:         set,
		baseVersion: e.Version(),
		dependsOn:   depends,
		records:     records,
	}
	return nil
}

// refreshObservations marks records stale when a publish or withdraw changed
// groups a candidate depends on, then recompiles the shadow set against the
// new active set so observation continues. Callers hold e.mu.
func (e *Engine) refreshObservations(changed []string) {
	if len(changed) == 0 {
		return
	}
	e.obsMu.Lock()
	defer e.obsMu.Unlock()
	base := e.current.Load()
	for _, cand := range e.candidates {
		if cand.abandoned {
			continue
		}
		staleGroups := intersectStrings(cand.dependsOn, changed)
		if len(staleGroups) == 0 {
			continue
		}
		reason := fmt.Sprintf("depended groups changed by a publish: %s", strings.Join(staleGroups, ", "))
		for index := range cand.records {
			if !cand.records[index].Stale {
				cand.records[index].Stale = true
				cand.records[index].StaleReason = reason
			}
		}
		if set, depends, err := buildShadowSet(base, cand.groups); err == nil {
			cand.set = set
			cand.dependsOn = depends
			cand.baseVersion = setVersion(base)
		}
	}
}

func observationBasis(cand *observedCandidate) (*ObservationBasis, error) {
	basis := &ObservationBasis{CandidateID: cand.id}
	versions := map[int]bool{}
	for _, record := range cand.records {
		if record.Stale {
			basis.StaleExcluded++
			continue
		}
		if basis.RecordCount == 0 || record.Sequence < basis.FromSequence {
			basis.FromSequence = record.Sequence
		}
		if record.Sequence > basis.ToSequence {
			basis.ToSequence = record.Sequence
		}
		basis.RecordCount++
		if !versions[record.ActiveVersion] {
			versions[record.ActiveVersion] = true
			basis.ActiveVersions = append(basis.ActiveVersions, record.ActiveVersion)
		}
	}
	if len(cand.records) > 0 && basis.RecordCount == 0 {
		return nil, fmt.Errorf("candidate %q has only stale observations; republish requires fresh observation", cand.id)
	}
	sort.Ints(basis.ActiveVersions)
	return basis, nil
}

func buildShadowSet(base *RuleSet, own []RuleGroup) (*RuleSet, []string, error) {
	groups := make([]RuleGroup, 0, len(own))
	ownIDs := map[string]bool{}
	for _, group := range own {
		ownIDs[group.ID] = true
		groups = append(groups, group)
	}
	var depends []string
	if base != nil {
		for _, group := range base.groups {
			if ownIDs[group.id] {
				continue
			}
			groups = append(groups, RuleGroup{ID: group.id, Priority: group.priority, Rules: externalRules(group)})
			depends = append(depends, group.id)
		}
	}
	if len(groups) == 0 {
		return nil, nil, fmt.Errorf("candidate has no groups and there is no active rule set")
	}
	set, err := CompileGroups(0, groups)
	if err != nil {
		return nil, nil, err
	}
	return set, depends, nil
}

func classifyDifference(current, shadow Decision, changed bool) DifferenceKind {
	if !changed {
		return DifferenceNone
	}
	if current.Unknown != shadow.Unknown {
		return DifferenceUnknown
	}
	if current.Unknown && shadow.Unknown && !equalStrings(current.UnknownReasons, shadow.UnknownReasons) {
		return DifferenceUnknown
	}
	return DifferenceVerdict
}

func changedGroupIDs(oldSet, newSet *RuleSet) []string {
	if newSet == nil {
		return nil
	}
	if oldSet == nil {
		changed := make([]string, 0, len(newSet.groups))
		for _, group := range newSet.groups {
			changed = append(changed, group.id)
		}
		return changed
	}
	seen := map[string]bool{}
	var changed []string
	for _, group := range newSet.groups {
		seen[group.id] = true
		old, ok := oldSet.byGroup[group.id]
		if !ok || old.priority != group.priority || !reflect.DeepEqual(externalRules(old), externalRules(group)) {
			changed = append(changed, group.id)
		}
	}
	for _, group := range oldSet.groups {
		if !seen[group.id] {
			changed = append(changed, group.id)
		}
	}
	sort.Strings(changed)
	return changed
}

func cloneGroups(groups []RuleGroup) []RuleGroup {
	cloned := make([]RuleGroup, len(groups))
	for index, group := range groups {
		rules := make([]Rule, len(group.Rules))
		for ruleIndex, rule := range group.Rules {
			rules[ruleIndex] = cloneRule(rule)
		}
		cloned[index] = RuleGroup{ID: group.ID, Description: group.Description, Priority: group.Priority, Rules: rules}
	}
	return cloned
}

func externalGroups(set *RuleSet) []RuleGroup {
	groups := make([]RuleGroup, 0, len(set.groups))
	for _, group := range set.groups {
		groups = append(groups, RuleGroup{ID: group.id, Priority: group.priority, Rules: externalRules(group)})
	}
	return groups
}

func cloneAttributes(attributes map[string]any) map[string]any {
	cloned := make(map[string]any, len(attributes))
	for key, value := range attributes {
		cloned[key] = cloneValue(value)
	}
	return cloned
}

func intersectStrings(left, right []string) []string {
	set := map[string]bool{}
	for _, value := range right {
		set[value] = true
	}
	var result []string
	for _, value := range left {
		if set[value] {
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func (e *Engine) sortedCandidateIDsLocked() []string {
	ids := make([]string, 0, len(e.candidates))
	for id := range e.candidates {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
