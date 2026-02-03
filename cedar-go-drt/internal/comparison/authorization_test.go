// Copyright Cedar Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package comparison

import (
	"testing"
)

func TestCompareAuthorization_MatchingResults(t *testing.T) {
	goResult := &AuthorizationResult{
		Decision:            "allow",
		DeterminingPolicies: []string{"policy0", "policy1"},
		ErroringPolicies:    []string{},
	}

	leanResult := &AuthorizationResult{
		Decision:            "allow",
		DeterminingPolicies: []string{"policy1", "policy0"}, // Different order
		ErroringPolicies:    []string{},
	}

	config := DefaultConfig()
	diffs := CompareAuthorization(goResult, leanResult, config)

	if len(diffs) != 0 {
		t.Errorf("Expected no differences, got %d: %v", len(diffs), diffs)
	}
}

func TestCompareAuthorization_DecisionMismatch(t *testing.T) {
	goResult := &AuthorizationResult{
		Decision:            "allow",
		DeterminingPolicies: []string{"policy0"},
		ErroringPolicies:    []string{},
	}

	leanResult := &AuthorizationResult{
		Decision:            "deny",
		DeterminingPolicies: []string{},
		ErroringPolicies:    []string{},
	}

	config := DefaultConfig()
	diffs := CompareAuthorization(goResult, leanResult, config)

	if len(diffs) == 0 {
		t.Error("Expected differences for decision mismatch")
	}

	found := false
	for _, d := range diffs {
		if d.Field == "decision" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected decision difference to be reported")
	}
}

func TestCompareAuthorization_DeterminingPoliciesMismatch(t *testing.T) {
	goResult := &AuthorizationResult{
		Decision:            "allow",
		DeterminingPolicies: []string{"policy0"},
		ErroringPolicies:    []string{},
	}

	leanResult := &AuthorizationResult{
		Decision:            "allow",
		DeterminingPolicies: []string{"policy0", "policy1"},
		ErroringPolicies:    []string{},
	}

	config := DefaultConfig()
	diffs := CompareAuthorization(goResult, leanResult, config)

	if len(diffs) == 0 {
		t.Error("Expected differences for determining policies mismatch")
	}

	found := false
	for _, d := range diffs {
		if d.Field == "determiningPolicies" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected determiningPolicies difference to be reported")
	}
}

func TestCompareAuthorization_ErroringPoliciesIgnored(t *testing.T) {
	goResult := &AuthorizationResult{
		Decision:            "deny",
		DeterminingPolicies: []string{},
		ErroringPolicies:    []string{"policy0"},
	}

	leanResult := &AuthorizationResult{
		Decision:            "deny",
		DeterminingPolicies: []string{},
		ErroringPolicies:    []string{"policy1"},
	}

	config := LenientConfig() // Ignores errors
	diffs := CompareAuthorization(goResult, leanResult, config)

	if len(diffs) != 0 {
		t.Errorf("Expected no differences with lenient config, got %d: %v", len(diffs), diffs)
	}
}

func TestCompareAuthorization_ErroringPoliciesCompared(t *testing.T) {
	goResult := &AuthorizationResult{
		Decision:            "deny",
		DeterminingPolicies: []string{},
		ErroringPolicies:    []string{"policy0"},
	}

	leanResult := &AuthorizationResult{
		Decision:            "deny",
		DeterminingPolicies: []string{},
		ErroringPolicies:    []string{"policy1"},
	}

	config := DefaultConfig() // Compares policy IDs
	diffs := CompareAuthorization(goResult, leanResult, config)

	if len(diffs) == 0 {
		t.Error("Expected differences for erroring policies mismatch")
	}
}

func TestCompareStringSlices(t *testing.T) {
	tests := []struct {
		name     string
		a        []string
		b        []string
		expected bool
	}{
		{"both empty", []string{}, []string{}, true},
		{"same elements same order", []string{"a", "b"}, []string{"a", "b"}, true},
		{"same elements different order", []string{"b", "a"}, []string{"a", "b"}, true},
		{"different lengths", []string{"a"}, []string{"a", "b"}, false},
		{"different elements", []string{"a", "b"}, []string{"a", "c"}, false},
		{"nil vs empty", nil, []string{}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := compareStringSlices(tc.a, tc.b)
			if result != tc.expected {
				t.Errorf("compareStringSlices(%v, %v) = %v, want %v", tc.a, tc.b, result, tc.expected)
			}
		})
	}
}

func TestFormatDifferences(t *testing.T) {
	diffs := []AuthorizationDifference{
		{Field: "decision", Description: "decision mismatch: go=allow lean=deny"},
	}

	result := FormatDifferences(diffs)
	if result == "no differences" {
		t.Error("Expected formatted differences, got 'no differences'")
	}

	result = FormatDifferences(nil)
	if result != "no differences" {
		t.Errorf("Expected 'no differences' for nil, got %q", result)
	}
}
