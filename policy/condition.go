package policy

import (
	"fmt"
	"reflect"
	"strings"
)

type tribool struct {
	value        bool
	know         bool
	explanations []string
}

func unknownTri() tribool { return tribool{} }

func knownTri(value bool, explanations ...string) tribool {
	return tribool{value: value, know: true, explanations: explanations}
}

func evaluateConditionInGroup(condition *Condition, request map[string]any, group compiledGroup, active map[string]bool) (bool, []string, bool) {
	result := evaluateTriInGroup(condition, request, group, active)
	return result.value, result.explanations, result.know
}

func evaluateTriInGroup(condition *Condition, request map[string]any, group compiledGroup, active map[string]bool) tribool {
	if condition == nil {
		return unknownTri()
	}

	if condition.Ref != "" {
		if active[condition.Ref] {
			return unknownTri()
		}
		referenced, exists := group.byID[condition.Ref]
		if !exists {
			return unknownTri()
		}
		active[condition.Ref] = true
		defer delete(active, condition.Ref)
		return evaluateTriInGroup(referenced.rule.Condition, request, group, active)
	}

	if condition.Not != nil {
		result := evaluateTriInGroup(condition.Not, request, group, active)
		if !result.know {
			return unknownTri()
		}
		return knownTri(!result.value, append([]string{"not ("}, result.explanations...)...)
	}

	if len(condition.All) > 0 {
		sawUnknown := false
		var explanations []string
		for _, child := range condition.All {
			result := evaluateTriInGroup(child, request, group, active)
			if !result.know {
				sawUnknown = true
				continue
			}
			if !result.value {
				return knownTri(false)
			}
			explanations = append(explanations, result.explanations...)
		}
		if sawUnknown {
			return unknownTri()
		}
		return knownTri(true, explanations...)
	}

	if len(condition.Any) > 0 {
		sawUnknown := false
		for _, child := range condition.Any {
			result := evaluateTriInGroup(child, request, group, active)
			if !result.know {
				sawUnknown = true
				continue
			}
			if result.value {
				return knownTri(true, result.explanations...)
			}
		}
		if sawUnknown {
			return unknownTri()
		}
		return knownTri(false)
	}

	return evaluateAtomic(condition, request)
}

func evaluateAtomic(condition *Condition, request map[string]any) tribool {
	value, exists := request[condition.Field]
	if condition.Op == OpExists {
		return knownTri(exists, fmt.Sprintf("field %q exists = %t", condition.Field, exists))
	}
	if !exists {
		return unknownTri()
	}

	switch condition.Op {
	case OpEqual:
		return boolTri(valuesEqual(value, condition.Value), condition, value)
	case OpNotEqual:
		return boolTri(!valuesEqual(value, condition.Value), condition, value)
	case OpIn:
		members, ok := condition.Value.([]any)
		if !ok {
			return unknownTri()
		}
		for _, member := range members {
			if valuesEqual(value, member) {
				return knownTri(true, fmt.Sprintf("field %q value %v is in %v", condition.Field, value, members))
			}
		}
		return knownTri(false)
	case OpContains, OpPrefix, OpSuffix:
		left, leftOK := value.(string)
		right, rightOK := condition.Value.(string)
		if !leftOK || !rightOK {
			return unknownTri()
		}
		matched := false
		switch condition.Op {
		case OpContains:
			matched = strings.Contains(left, right)
		case OpPrefix:
			matched = strings.HasPrefix(left, right)
		case OpSuffix:
			matched = strings.HasSuffix(left, right)
		}
		return boolTri(matched, condition, value)
	}

	comparison, ok := compareValues(value, condition.Value)
	if !ok {
		return unknownTri()
	}
	matched := false
	switch condition.Op {
	case OpGreater:
		matched = comparison > 0
	case OpAtLeast:
		matched = comparison >= 0
	case OpLess:
		matched = comparison < 0
	case OpAtMost:
		matched = comparison <= 0
	default:
		return unknownTri()
	}
	return boolTri(matched, condition, value)
}

func boolTri(matched bool, condition *Condition, actual any) tribool {
	return knownTri(matched, fmt.Sprintf("field %q %v %v; actual %v", condition.Field, condition.Op, condition.Value, actual))
}

func valuesEqual(left, right any) bool {
	if leftNumber, leftOK := numberFloat(left); leftOK {
		if rightNumber, rightOK := numberFloat(right); rightOK {
			return leftNumber == rightNumber
		}
	}
	return reflect.DeepEqual(left, right)
}

func compareValues(left, right any) (int, bool) {
	leftNumber, leftOK := numberFloat(left)
	rightNumber, rightOK := numberFloat(right)
	if leftOK && rightOK {
		switch {
		case leftNumber > rightNumber:
			return 1, true
		case leftNumber < rightNumber:
			return -1, true
		default:
			return 0, true
		}
	}
	leftString, leftOK := left.(string)
	rightString, rightOK := right.(string)
	if leftOK && rightOK {
		return strings.Compare(leftString, rightString), true
	}
	return 0, false
}

func numberFloat(value any) (float64, bool) {
	switch typed := value.(type) {
	case int:
		return float64(typed), true
	case int8:
		return float64(typed), true
	case int16:
		return float64(typed), true
	case int32:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case uint:
		return float64(typed), true
	case uint8:
		return float64(typed), true
	case uint16:
		return float64(typed), true
	case uint32:
		return float64(typed), true
	case uint64:
		return float64(typed), true
	case float32:
		return float64(typed), true
	case float64:
		return typed, true
	default:
		return 0, false
	}
}

func validateCondition(condition *Condition, active map[string]bool) error {
	if condition == nil {
		return fmt.Errorf("condition is empty")
	}
	kinds := 0
	if condition.Field != "" || condition.Op != "" {
		kinds++
	}
	if len(condition.All) > 0 {
		kinds++
	}
	if len(condition.Any) > 0 {
		kinds++
	}
	if condition.Not != nil {
		kinds++
	}
	if condition.Ref != "" {
		kinds++
	}
	if kinds != 1 {
		return fmt.Errorf("condition must contain exactly one of atomic, all, any, not, or ref")
	}

	if condition.Ref != "" {
		if strings.TrimSpace(condition.Ref) == "" {
			return fmt.Errorf("ref is empty")
		}
		return nil
	}
	if condition.Not != nil {
		return validateCondition(condition.Not, active)
	}
	if len(condition.All) > 0 {
		for _, child := range condition.All {
			if err := validateCondition(child, active); err != nil {
				return err
			}
		}
		return nil
	}
	if len(condition.Any) > 0 {
		for _, child := range condition.Any {
			if err := validateCondition(child, active); err != nil {
				return err
			}
		}
		return nil
	}

	if strings.TrimSpace(condition.Field) == "" {
		return fmt.Errorf("field is empty")
	}
	switch condition.Op {
	case OpEqual, OpNotEqual, OpGreater, OpAtLeast, OpLess, OpAtMost, OpContains, OpPrefix, OpSuffix:
		if condition.Value == nil {
			return fmt.Errorf("operator %s requires a value", condition.Op)
		}
	case OpIn:
		if _, ok := condition.Value.([]any); !ok {
			return fmt.Errorf("operator %s requires []any", condition.Op)
		}
	case OpExists:
	default:
		return fmt.Errorf("unsupported operator %q", condition.Op)
	}
	return nil
}

func conditionRefs(condition *Condition) []string {
	if condition == nil {
		return nil
	}
	if condition.Ref != "" {
		return []string{condition.Ref}
	}
	var refs []string
	if condition.Not != nil {
		refs = append(refs, conditionRefs(condition.Not)...)
	}
	for _, child := range condition.All {
		refs = append(refs, conditionRefs(child)...)
	}
	for _, child := range condition.Any {
		refs = append(refs, conditionRefs(child)...)
	}
	return refs
}
