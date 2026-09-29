package engine

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

type Operator string

const (
	OpEqual     Operator = "eq"
	OpNotEqual  Operator = "ne"
	OpLess      Operator = "lt"
	OpLessEq    Operator = "le"
	OpGreater   Operator = "gt"
	OpGreaterEq Operator = "ge"
	OpIn        Operator = "in"
	OpNotIn     Operator = "not_in"
	OpContains  Operator = "contains"
	OpPrefix    Operator = "starts_with"
	OpSuffix    Operator = "ends_with"
)

// Condition is a small, JSON-friendly predicate tree. Exactly one of All,
// Any, Not, Ref, or a Field/Op predicate must be set.
type Condition struct {
	All   []Condition `json:"all,omitempty"`
	Any   []Condition `json:"any,omitempty"`
	Not   *Condition  `json:"not,omitempty"`
	Ref   string      `json:"ref,omitempty"`
	Field string      `json:"field,omitempty"`
	Op    Operator    `json:"op,omitempty"`
	Value any         `json:"value,omitempty"`
}

type ConditionEvidence struct {
	Kind     string              `json:"kind"`
	Field    string              `json:"field,omitempty"`
	Op       Operator            `json:"op,omitempty"`
	Value    any                 `json:"value,omitempty"`
	Ref      string              `json:"ref,omitempty"`
	Matched  bool                `json:"matched"`
	Missing  []string            `json:"missing,omitempty"`
	Children []ConditionEvidence `json:"children,omitempty"`
}

type conditionNode struct {
	condition Condition
	all       []*conditionNode
	any       []*conditionNode
	not       *conditionNode
	ref       *conditionNode
}

type ternaryResult struct {
	matched  bool
	unknown  bool
	missing  map[string]struct{}
	evidence ConditionEvidence
}

func (n *conditionNode) evaluate(attributes map[string]any) ternaryResult {
	switch {
	case n.ref != nil:
		child := n.ref.evaluate(attributes)
		child.evidence = ConditionEvidence{
			Kind:     "ref",
			Ref:      n.condition.Ref,
			Matched:  child.matched,
			Missing:  sortedMissing(child.missing),
			Children: []ConditionEvidence{child.evidence},
		}
		return child
	case n.not != nil:
		child := n.not.evaluate(attributes)
		result := ternaryResult{missing: child.missing}
		if !child.unknown {
			result.matched = !child.matched
		}
		if child.unknown {
			result.unknown = true
		}
		result.evidence = ConditionEvidence{
			Kind:     "not",
			Matched:  result.matched,
			Missing:  sortedMissing(result.missing),
			Children: []ConditionEvidence{child.evidence},
		}
		return result
	case len(n.all) > 0:
		result := ternaryResult{matched: true, missing: map[string]struct{}{}}
		children := make([]ConditionEvidence, 0, len(n.all))
		known := true
		for _, childNode := range n.all {
			child := childNode.evaluate(attributes)
			children = append(children, child.evidence)
			if known {
				if child.unknown {
					result.unknown = true
					result.matched = false
					mergeMissing(result.missing, child.missing)
				} else if !child.matched {
					known = false
					result.matched = false
					result.unknown = false
					result.missing = map[string]struct{}{}
				}
			}
		}
		result.evidence = ConditionEvidence{Kind: "all", Matched: result.matched, Missing: sortedMissing(result.missing), Children: children}
		return result
	case len(n.any) > 0:
		result := ternaryResult{missing: map[string]struct{}{}}
		children := make([]ConditionEvidence, 0, len(n.any))
		hasKnownChild := false
		for _, childNode := range n.any {
			child := childNode.evaluate(attributes)
			children = append(children, child.evidence)
			hasKnownChild = true
			if child.matched {
				result.matched = true
				result.unknown = false
				result.missing = map[string]struct{}{}
			} else if child.unknown && !result.matched {
				result.unknown = true
				mergeMissing(result.missing, child.missing)
			}
		}
		if !hasKnownChild {
			result.matched = false
		}
		result.evidence = ConditionEvidence{Kind: "any", Matched: result.matched, Missing: sortedMissing(result.missing), Children: children}
		return result
	default:
		return n.evaluatePredicate(attributes)
	}
}

func (n *conditionNode) evaluatePredicate(attributes map[string]any) ternaryResult {
	c := n.condition
	value, exists := getAttribute(attributes, c.Field)
	evidence := ConditionEvidence{Kind: "predicate", Field: c.Field, Op: c.Op, Value: c.Value}
	if !exists {
		return ternaryResult{
			unknown:  true,
			missing:  map[string]struct{}{c.Field: {}},
			evidence: withMissing(evidence, []string{c.Field}),
		}
	}

	matched, err := compare(value, c.Op, c.Value)
	if err != nil {
		evidence.Matched = false
		return ternaryResult{matched: false, evidence: evidence}
	}
	evidence.Matched = matched
	return ternaryResult{matched: matched, evidence: evidence}
}

func getAttribute(attributes map[string]any, path string) (any, bool) {
	if attributes == nil {
		return nil, false
	}
	if value, ok := attributes[path]; ok {
		return value, true
	}
	parts := strings.Split(path, ".")
	if len(parts) == 1 {
		return nil, false
	}
	var current any = attributes
	for _, part := range parts {
		m, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = m[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func compare(actual any, op Operator, expected any) (bool, error) {
	switch op {
	case OpEqual:
		return valuesEqual(actual, expected), nil
	case OpNotEqual:
		return !valuesEqual(actual, expected), nil
	case OpIn, OpNotIn:
		items, ok := asSlice(expected)
		if !ok {
			return false, fmt.Errorf("operator %s requires a list value", op)
		}
		found := false
		for _, item := range items {
			if valuesEqual(actual, item) {
				found = true
				break
			}
		}
		if op == OpIn {
			return found, nil
		}
		return !found, nil
	case OpContains:
		if actualText, ok := actual.(string); ok {
			if expectedText, ok := expected.(string); ok {
				return strings.Contains(actualText, expectedText), nil
			}
		}
		items, ok := asSlice(actual)
		if !ok {
			return false, fmt.Errorf("operator %s requires a string or list attribute", op)
		}
		for _, item := range items {
			if valuesEqual(item, expected) {
				return true, nil
			}
		}
		return false, nil
	case OpPrefix, OpSuffix:
		actualText, ok := actual.(string)
		if !ok {
			return false, fmt.Errorf("operator %s requires a string attribute", op)
		}
		expectedText, ok := expected.(string)
		if !ok {
			return false, fmt.Errorf("operator %s requires a string value", op)
		}
		if op == OpPrefix {
			return strings.HasPrefix(actualText, expectedText), nil
		}
		return strings.HasSuffix(actualText, expectedText), nil
	case OpLess, OpLessEq, OpGreater, OpGreaterEq:
		actualNumber, actualIsNumber := toFloat64(actual)
		expectedNumber, expectedIsNumber := toFloat64(expected)
		if actualIsNumber && expectedIsNumber {
			switch op {
			case OpLess:
				return actualNumber < expectedNumber, nil
			case OpLessEq:
				return actualNumber <= expectedNumber, nil
			case OpGreater:
				return actualNumber > expectedNumber, nil
			default:
				return actualNumber >= expectedNumber, nil
			}
		}
		actualText, actualTextOK := actual.(string)
		expectedText, expectedTextOK := expected.(string)
		if actualTextOK && expectedTextOK {
			switch op {
			case OpLess:
				return actualText < expectedText, nil
			case OpLessEq:
				return actualText <= expectedText, nil
			case OpGreater:
				return actualText > expectedText, nil
			default:
				return actualText >= expectedText, nil
			}
		}
		return false, fmt.Errorf("operator %s requires comparable number or string operands", op)
	default:
		return false, fmt.Errorf("unknown operator %q", op)
	}
}

func valuesEqual(left, right any) bool {
	leftNumber, leftIsNumber := toFloat64(left)
	rightNumber, rightIsNumber := toFloat64(right)
	if leftIsNumber && rightIsNumber {
		return leftNumber == rightNumber
	}
	if reflect.DeepEqual(left, right) {
		return true
	}
	return false
}

func toFloat64(value any) (float64, bool) {
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
	case json.Number:
		parsed, err := typed.Float64()
		return parsed, err == nil
	default:
		return 0, false
	}
}

func asSlice(value any) ([]any, bool) {
	if value == nil {
		return nil, false
	}
	reflected := reflect.ValueOf(value)
	if reflected.Kind() != reflect.Slice && reflected.Kind() != reflect.Array {
		return nil, false
	}
	result := make([]any, reflected.Len())
	for index := 0; index < reflected.Len(); index++ {
		result[index] = reflected.Index(index).Interface()
	}
	return result, true
}

func cloneValue(value any) any {
	if value == nil {
		return nil
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Slice, reflect.Array:
		elementType := reflected.Type().Elem()
		clone := reflect.MakeSlice(reflect.SliceOf(elementType), reflected.Len(), reflected.Len())
		for index := 0; index < reflected.Len(); index++ {
			clone.Index(index).Set(reflect.ValueOf(cloneValue(reflected.Index(index).Interface())))
		}
		return clone.Interface()
	case reflect.Map:
		clone := reflect.MakeMapWithSize(reflected.Type(), reflected.Len())
		iterator := reflected.MapRange()
		for iterator.Next() {
			clone.SetMapIndex(iterator.Key(), reflect.ValueOf(cloneValue(iterator.Value().Interface())))
		}
		return clone.Interface()
	case reflect.Pointer:
		if reflected.IsNil() {
			return nil
		}
		return cloneValue(reflected.Elem().Interface())
	default:
		return value
	}
}

func mergeMissing(target map[string]struct{}, source map[string]struct{}) {
	for key := range source {
		target[key] = struct{}{}
	}
}

func sortedMissing(values map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	for index := 1; index < len(result); index++ {
		for previous := index; previous > 0 && result[previous-1] > result[previous]; previous-- {
			result[previous-1], result[previous] = result[previous], result[previous-1]
		}
	}
	return result
}

func withMissing(evidence ConditionEvidence, missing []string) ConditionEvidence {
	evidence.Matched = false
	evidence.Missing = missing
	return evidence
}
