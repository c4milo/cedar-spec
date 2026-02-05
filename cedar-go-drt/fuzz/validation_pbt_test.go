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
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
	"github.com/cedar-policy/cedar-go/x/exp/validator"

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/typegen"
)

// FuzzValidationPBT is a property-based test for validation.
// It tests properties that should hold for ANY valid schema and policy combination,
// without comparing to Lean (pure property-based testing).
func FuzzValidationPBT(f *testing.F) {
	f.Add([]byte("validation-pbt-seed-1"))
	f.Add([]byte("validation-pbt-seed-2"))
	f.Add(make([]byte, 128))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		testValidationPBT(t, data, inputGen)
	})
}

func testValidationPBT(t *testing.T, data []byte, inputGen *typegen.InputGenerator) {
	input, s, ok := prepareValidationPBTInput(data, inputGen)
	if !ok {
		return
	}

	result := validator.ValidatePolicies(s, input.Policies)
	checkValidationResultConsistency(t, result.Valid, len(result.Errors))
	checkErrorPolicyIDsExist(t, result, input.Policies)
}

func prepareValidationPBTInput(data []byte, inputGen *typegen.InputGenerator) (*typegen.TypeDirectedInput, *schema.Schema, bool) {
	if len(data) < 32 {
		return nil, nil, false
	}

	input, err := inputGen.Generate(data)
	if err != nil || input.Policies == nil {
		return nil, nil, false
	}

	s, parseErr := schema.NewFromJSON(input.SchemaJSON)
	if parseErr != nil {
		return nil, nil, false
	}

	return input, s, true
}

func checkValidationResultConsistency(t *testing.T, valid bool, errorCount int) {
	if valid && errorCount > 0 {
		t.Errorf("Inconsistent validation: Valid=true but has %d errors", errorCount)
	}

	if !valid && errorCount == 0 {
		t.Errorf("Inconsistent validation: Valid=false but no errors reported")
	}
}

func checkErrorPolicyIDsExist(t *testing.T, result validator.PolicyValidationResult, policies *cedar.PolicySet) {
	policyIDs := collectPolicyIDs(policies)

	for _, verr := range result.Errors {
		if verr.PolicyID != "" && !policyIDs[verr.PolicyID] {
			t.Errorf("Error references unknown policy ID: %s", verr.PolicyID)
		}
	}
}

func collectPolicyIDs(policies *cedar.PolicySet) map[cedar.PolicyID]bool {
	policyIDs := make(map[cedar.PolicyID]bool)
	for id := range policies.All() {
		policyIDs[id] = true
	}
	return policyIDs
}

// FuzzValidationPBTTypeDirected is a type-directed property-based test for validation.
// Since we generate policies that should conform to the schema, validation should usually pass.
func FuzzValidationPBTTypeDirected(f *testing.F) {
	f.Add([]byte("validation-pbt-td-seed-1"))
	f.Add([]byte("validation-pbt-td-seed-2"))
	f.Add(make([]byte, 128))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 32 {
			return
		}

		// Generate type-directed input
		input, err := inputGen.Generate(data)
		if err != nil {
			return
		}

		if input.Policies == nil {
			return
		}

		// Parse the schema
		s, parseErr := schema.NewFromJSON(input.SchemaJSON)
		if parseErr != nil {
			return
		}

		// Run validation
		result := validator.ValidatePolicies(s, input.Policies)

		// For type-directed generation, we expect most policies to validate
		// This is a soft property - we just track statistics
		_ = result

		// Property: Consistency checks still apply
		if result.Valid && len(result.Errors) > 0 {
			t.Errorf("Inconsistent validation: Valid=true but has %d errors", len(result.Errors))
		}

		if !result.Valid && len(result.Errors) == 0 {
			t.Errorf("Inconsistent validation: Valid=false but no errors reported")
		}
	})
}

// TestValidationProperties tests specific validation properties.
func TestValidationProperties(t *testing.T) {
	schemaJSON := []byte(`{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"name": {"type": "String", "required": true}
						}
					}
				},
				"Doc": {}
			},
			"actions": {
				"view": {
					"appliesTo": {
						"principalTypes": ["User"],
						"resourceTypes": ["Doc"]
					}
				}
			}
		}
	}`)

	s, parseErr := schema.NewFromJSON(schemaJSON)
	if parseErr != nil {
		t.Fatalf("Failed to parse schema: %v", parseErr)
	}

	tests := []struct {
		name        string
		policy      string
		expectValid bool
	}{
		{
			name:        "valid simple permit",
			policy:      `permit(principal, action, resource);`,
			expectValid: true,
		},
		{
			name:        "valid with principal type constraint",
			policy:      `permit(principal is User, action, resource);`,
			expectValid: true,
		},
		{
			name:        "valid with action constraint",
			policy:      `permit(principal, action == Action::"view", resource);`,
			expectValid: true,
		},
		{
			name:        "valid attribute access",
			policy:      `permit(principal, action, resource) when { principal.name == "alice" };`,
			expectValid: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ps := cedar.NewPolicySet()
			var policy cedar.Policy
			if err := policy.UnmarshalCedar([]byte(tc.policy)); err != nil {
				t.Fatalf("Failed to parse policy: %v", err)
			}
			ps.Add("test", &policy)

			result := validator.ValidatePolicies(s, ps)

			if result.Valid != tc.expectValid {
				t.Errorf("Expected Valid=%v, got Valid=%v (errors: %v)",
					tc.expectValid, result.Valid, result.Errors)
			}
		})
	}
}

// TestValidationConsistency tests that validation is deterministic.
func TestValidationConsistency(t *testing.T) {
	schemaJSON := []byte(`{"": {"entityTypes": {"User": {}}, "actions": {"view": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["User"]}}}}}`)

	s, parseErr := schema.NewFromJSON(schemaJSON)
	if parseErr != nil {
		t.Fatalf("Failed to parse schema: %v", parseErr)
	}

	ps := cedar.NewPolicySet()
	var policy cedar.Policy
	_ = policy.UnmarshalCedar([]byte(`permit(principal, action, resource);`))
	ps.Add("p1", &policy)

	// Run validation multiple times
	var firstValid bool
	var firstErrorCount int
	firstRun := true
	for i := range 10 {
		result := validator.ValidatePolicies(s, ps)
		if firstRun {
			firstValid = result.Valid
			firstErrorCount = len(result.Errors)
			firstRun = false
		} else {
			if result.Valid != firstValid {
				t.Errorf("Validation not deterministic: run %d got Valid=%v, expected %v",
					i, result.Valid, firstValid)
			}
			if len(result.Errors) != firstErrorCount {
				t.Errorf("Validation not deterministic: run %d got %d errors, expected %d",
					i, len(result.Errors), firstErrorCount)
			}
		}
	}
}
