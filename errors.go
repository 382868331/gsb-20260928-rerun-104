package engine

import "fmt"

type ValidationError struct {
	Reason        string `json:"reason"`
	RuleID        string `json:"rule_id,omitempty"`
	ConditionName string `json:"condition_name,omitempty"`
	Field         string `json:"field,omitempty"`
	Index         int    `json:"index,omitempty"`
}

func (e ValidationError) Error() string {
	if e.RuleID != "" {
		return fmt.Sprintf("request policy validation error: %s in rule %q", e.Reason, e.RuleID)
	}
	if e.ConditionName != "" {
		return fmt.Sprintf("request policy validation error: %s in named condition %q", e.Reason, e.ConditionName)
	}
	return "request policy validation error: " + e.Reason
}

type ReferenceCycleError struct {
	Reference string `json:"reference"`
	In        string `json:"in,omitempty"`
}

func (e ReferenceCycleError) Error() string {
	if e.In != "" {
		return fmt.Sprintf("request policy reference cycle at %q in %s", e.Reference, e.In)
	}
	return "request policy reference cycle at " + e.Reference
}
