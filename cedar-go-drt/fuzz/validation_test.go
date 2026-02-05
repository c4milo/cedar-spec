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
	"encoding/json"
	"fmt"
	"runtime"
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
	"github.com/cedar-policy/cedar-go/x/exp/validator"

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/comparison"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/lean"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/proto"
)

// ValidationFuzzInput represents the structure of validation fuzz input data
type ValidationFuzzInput struct {
	Schema   string   `json:"schema"`
	Policies []string `json:"policies"`
}

// parseValidationInput parses the validation fuzz input.
func parseValidationInput(data []byte) (*schema.Schema, *cedar.PolicySet, error) {
	var input ValidationFuzzInput
	if err := json.Unmarshal(data, &input); err != nil {
		return nil, nil, err
	}

	s, err := schema.NewFromJSON([]byte(input.Schema))
	if err != nil {
		return nil, nil, err
	}

	policies := cedar.NewPolicySet()
	for i, policyStr := range input.Policies {
		var policy cedar.Policy
		if err := policy.UnmarshalCedar([]byte(policyStr)); err != nil {
			return nil, nil, err
		}
		policies.Add(cedar.PolicyID(fmt.Sprintf("policy%d", i)), &policy)
	}

	return s, policies, nil
}

// runLeanValidation runs Lean validation and returns the result.
func runLeanValidation(t *testing.T, s *schema.Schema, policies *cedar.PolicySet) *lean.ValidationResponse {
	t.Helper()

	valReq := proto.ValidationFromCedar(policies, s)
	protoBytes, err := valReq.ToProtobuf()
	if err != nil {
		t.Logf("Failed to convert to protobuf: %v", err)
		return nil
	}

	if err := lean.Initialize(); err != nil {
		t.Fatalf("Failed to initialize Lean: %v", err)
	}

	lt, err := lean.NewLeanThread()
	if err != nil {
		t.Fatalf("Failed to create Lean thread: %v", err)
	}
	defer lt.Close()

	leanResp, err := lean.Validate(protoBytes)
	if err != nil {
		t.Logf("Lean FFI error: %v", err)
		return nil
	}

	return leanResp
}

// runCedarGoValidation runs cedar-go policy validation and returns the result.
// Uses WithAllowUnknownEntityTypes to match Lean's behavior where unknown entity types
// in principalTypes/resourceTypes are accepted at schema validation time and handled
// at policy validation time via impossiblePolicy checks.
func runCedarGoValidation(s *schema.Schema, policies *cedar.PolicySet) *comparison.ValidationResult {
	result := validator.ValidatePolicies(s, policies, validator.WithAllowUnknownEntityTypes())

	var errors []string
	for _, err := range result.Errors {
		errors = append(errors, fmt.Sprintf("policy %s: %s", err.PolicyID, err.Message))
	}

	return &comparison.ValidationResult{
		Valid:  result.Valid,
		Errors: errors,
	}
}

// FuzzValidation is the main fuzz target for validation testing.
// It compares cedar-go validation results against the Lean formalization.
func FuzzValidation(f *testing.F) {
	addValidationSeeds(f)

	config := comparison.DefaultConfig()

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

		checkValidationResults(t, goResult, leanResult, config, data)
	})
}

func addValidationSeeds(f *testing.F) {
	f.Add([]byte(`{
		"schema": "{\"entityTypes\":{\"User\":{},\"Document\":{}},\"actions\":{\"view\":{\"appliesTo\":{\"principalTypes\":[\"User\"],\"resourceTypes\":[\"Document\"]}}}}",
		"policies": ["permit(principal, action, resource);"]
	}`))
}

func checkValidationResults(t *testing.T, goResult, leanResult *comparison.ValidationResult, config comparison.ComparisonConfig, data []byte) {
	t.Helper()

	diffs := comparison.CompareValidation(goResult, leanResult, config)
	if len(diffs) > 0 {
		t.Errorf("Validation divergence detected:\n%s\nInput: %s",
			comparison.FormatValidationDifferences(diffs), string(data))
	}

	if err := comparison.CheckTypeSoundness(goResult, leanResult); err != nil {
		t.Errorf("Type soundness violation: %v\nInput: %s", err, string(data))
	}
}

// TestValidationBasic tests basic validation scenarios
func TestValidationBasic(t *testing.T) {
	tests := []struct {
		name        string
		schema      string
		policy      string
		expectParse bool
	}{
		{
			name:        "valid simple schema and policy",
			schema:      `{"entityTypes":{"User":{},"Document":{}},"actions":{"view":{"appliesTo":{"principalTypes":["User"],"resourceTypes":["Document"]}}}}`,
			policy:      "permit(principal, action, resource);",
			expectParse: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := schema.NewFromJSON([]byte(tc.schema))
			if (err == nil) != tc.expectParse {
				t.Errorf("Schema parse: expected success=%v, got error=%v", tc.expectParse, err)
			}

			var policy cedar.Policy
			err = policy.UnmarshalCedar([]byte(tc.policy))
			if (err == nil) != tc.expectParse {
				t.Errorf("Policy parse: expected success=%v, got error=%v", tc.expectParse, err)
			}
		})
	}
}
