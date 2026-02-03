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

package fuzz

import (
	"runtime"
	"testing"

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/comparison"
)

// FuzzValidationStrict is a strict validation fuzz target that requires
// cedar-go and Lean to agree on ALL validation outcomes - both accepts AND rejects.
//
// This is stricter than FuzzValidation which only checks type soundness
// (if cedar-go accepts, Lean must accept).
//
// FuzzValidationStrict catches cases where:
// - cedar-go is overly strict (rejects valid policies that Lean accepts)
// - cedar-go is overly permissive (accepts invalid policies that Lean rejects)
//
// Use this target to find places where cedar-go validation differs from
// the formal specification, even when cedar-go is being conservative.
func FuzzValidationStrict(f *testing.F) {
	addValidationStrictSeeds(f)

	config := comparison.StrictConfig()

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		s, policies, err := parseValidationInput(data)
		if err != nil {
			return // Invalid input, skip
		}

		// Run cedar-go validation
		goResult := runCedarGoValidation(s, policies)

		// Run Lean validation
		leanResp := runLeanValidation(t, s, policies)
		if leanResp == nil {
			return // Lean error, skip
		}

		leanResult := &comparison.ValidationResult{
			Valid:  leanResp.Valid,
			Errors: []string{leanResp.Errors},
		}

		// Use strict comparison - both must agree on valid AND invalid
		diffs := comparison.CompareValidation(goResult, leanResult, config)
		if len(diffs) > 0 {
			// Log whether this is cedar-go being strict or permissive
			if goResult.Valid && !leanResult.Valid {
				t.Errorf("cedar-go OVERLY PERMISSIVE: accepted policy that Lean rejected\n%s\nInput: %s",
					comparison.FormatValidationDifferences(diffs), string(data))
			} else if !goResult.Valid && leanResult.Valid {
				t.Errorf("cedar-go OVERLY STRICT: rejected policy that Lean accepted\n%s\nGo errors: %v\nInput: %s",
					comparison.FormatValidationDifferences(diffs), goResult.Errors, string(data))
			} else {
				t.Errorf("Validation divergence:\n%s\nInput: %s",
					comparison.FormatValidationDifferences(diffs), string(data))
			}
		}
	})
}

func addValidationStrictSeeds(f *testing.F) {
	// Basic valid policy
	f.Add([]byte(`{
		"schema": "{\"entityTypes\":{\"User\":{},\"Document\":{}},\"actions\":{\"view\":{\"appliesTo\":{\"principalTypes\":[\"User\"],\"resourceTypes\":[\"Document\"]}}}}",
		"policies": ["permit(principal, action, resource);"]
	}`))

	// Policy with condition
	f.Add([]byte(`{
		"schema": "{\"\":{\"entityTypes\":{\"User\":{\"shape\":{\"type\":\"Record\",\"attributes\":{\"active\":{\"type\":\"Boolean\",\"required\":true}}}},\"Document\":{}},\"actions\":{\"view\":{\"appliesTo\":{\"principalTypes\":[\"User\"],\"resourceTypes\":[\"Document\"]}}}}}",
		"policies": ["permit(principal, action, resource) when { principal.active };"]
	}`))

	// Policy with attribute that might not exist
	f.Add([]byte(`{
		"schema": "{\"\":{\"entityTypes\":{\"User\":{\"shape\":{\"type\":\"Record\",\"attributes\":{\"name\":{\"type\":\"String\",\"required\":false}}}},\"Document\":{}},\"actions\":{\"view\":{\"appliesTo\":{\"principalTypes\":[\"User\"],\"resourceTypes\":[\"Document\"]}}}}}",
		"policies": ["permit(principal, action, resource) when { principal.name == \"alice\" };"]
	}`))

	// Policy with wrong type in condition
	f.Add([]byte(`{
		"schema": "{\"\":{\"entityTypes\":{\"User\":{\"shape\":{\"type\":\"Record\",\"attributes\":{\"age\":{\"type\":\"Long\",\"required\":true}}}},\"Document\":{}},\"actions\":{\"view\":{\"appliesTo\":{\"principalTypes\":[\"User\"],\"resourceTypes\":[\"Document\"]}}}}}",
		"policies": ["permit(principal, action, resource) when { principal.age == \"not a number\" };"]
	}`))

	// Policy with unknown action
	f.Add([]byte(`{
		"schema": "{\"entityTypes\":{\"User\":{},\"Document\":{}},\"actions\":{\"view\":{\"appliesTo\":{\"principalTypes\":[\"User\"],\"resourceTypes\":[\"Document\"]}}}}",
		"policies": ["permit(principal, action == Action::\"delete\", resource);"]
	}`))

	// Policy with scope type mismatch
	f.Add([]byte(`{
		"schema": "{\"\":{\"entityTypes\":{\"User\":{},\"Admin\":{},\"Document\":{}},\"actions\":{\"view\":{\"appliesTo\":{\"principalTypes\":[\"User\"],\"resourceTypes\":[\"Document\"]}}}}}",
		"policies": ["permit(principal == Admin::\"bob\", action == Action::\"view\", resource);"]
	}`))

	// Forbid policy
	f.Add([]byte(`{
		"schema": "{\"entityTypes\":{\"User\":{},\"Document\":{}},\"actions\":{\"view\":{\"appliesTo\":{\"principalTypes\":[\"User\"],\"resourceTypes\":[\"Document\"]}}}}",
		"policies": ["forbid(principal, action, resource);"]
	}`))

	// Multiple policies
	f.Add([]byte(`{
		"schema": "{\"entityTypes\":{\"User\":{},\"Document\":{}},\"actions\":{\"view\":{\"appliesTo\":{\"principalTypes\":[\"User\"],\"resourceTypes\":[\"Document\"]}}}}",
		"policies": ["permit(principal, action, resource);", "forbid(principal == User::\"blocked\", action, resource);"]
	}`))
}
