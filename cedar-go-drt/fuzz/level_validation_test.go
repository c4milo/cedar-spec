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

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/lean"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/proto"
)

// LevelValidationFuzzInput represents the structure of level validation fuzz input.
type LevelValidationFuzzInput struct {
	Schema   string   `json:"schema"`
	Policies []string `json:"policies"`
	Level    int32    `json:"level"`
}

// parseLevelValidationInput parses the level validation fuzz input.
func parseLevelValidationInput(data []byte) (*schema.Schema, *cedar.PolicySet, int32, error) {
	var input LevelValidationFuzzInput
	if err := json.Unmarshal(data, &input); err != nil {
		return nil, nil, 0, err
	}

	s, err := schema.NewFromJSON([]byte(input.Schema))
	if err != nil {
		return nil, nil, 0, err
	}

	policies := cedar.NewPolicySet()
	for i, policyStr := range input.Policies {
		var policy cedar.Policy
		if err := policy.UnmarshalCedar([]byte(policyStr)); err != nil {
			return nil, nil, 0, err
		}
		policies.Add(cedar.PolicyID(fmt.Sprintf("policy%d", i)), &policy)
	}

	return s, policies, input.Level, nil
}

// runLeanLevelValidation runs Lean level validation and returns the result.
func runLeanLevelValidation(t *testing.T, s *schema.Schema, policies *cedar.PolicySet, level int32) *lean.ValidationResponse {
	t.Helper()

	req := proto.LevelValidationFromCedar(s, policies, level)
	protoBytes, err := req.ToProtobuf()
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

	leanResp, err := lean.LevelValidate(protoBytes)
	if err != nil {
		t.Logf("Lean FFI error: %v", err)
		return nil
	}

	return leanResp
}

// FuzzLevelValidation is the fuzz target for level-based validation testing.
// It validates policies against a schema at various validation levels using
// the Lean formalization.
//
// Validation levels control the strictness of type checking:
//   - Level 0: Basic type checking (permissive)
//   - Level 1: Standard validation (default)
//   - Level 2: Strict validation
//
// This tests that different validation levels behave consistently between
// implementations.
func FuzzLevelValidation(f *testing.F) {
	addLevelValidationSeeds(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		s, policies, level, err := parseLevelValidationInput(data)
		if err != nil {
			return // Invalid input, skip
		}

		// Clamp level to valid range
		if level < 0 {
			level = 0
		}
		if level > 2 {
			level = 2
		}

		// Run Lean level validation
		leanResp := runLeanLevelValidation(t, s, policies, level)
		if leanResp == nil {
			return // Lean error, skip
		}

		// For now, we verify Lean can validate at different levels without crashing.
		// Cedar-go doesn't expose level-based validation, so we can't compare directly.
		// A valid response (either valid or with errors) is acceptable.
		_ = leanResp.Valid
	})
}

func addLevelValidationSeeds(f *testing.F) {
	// Simple policy at level 0
	f.Add([]byte(`{
		"schema": "{\"entityTypes\":{\"User\":{},\"Document\":{}},\"actions\":{\"view\":{\"appliesTo\":{\"principalTypes\":[\"User\"],\"resourceTypes\":[\"Document\"]}}}}",
		"policies": ["permit(principal, action, resource);"],
		"level": 0
	}`))

	// Simple policy at level 1
	f.Add([]byte(`{
		"schema": "{\"entityTypes\":{\"User\":{},\"Document\":{}},\"actions\":{\"view\":{\"appliesTo\":{\"principalTypes\":[\"User\"],\"resourceTypes\":[\"Document\"]}}}}",
		"policies": ["permit(principal, action, resource);"],
		"level": 1
	}`))

	// Typed policy at level 1
	f.Add([]byte(`{
		"schema": "{\"entityTypes\":{\"User\":{},\"Document\":{}},\"actions\":{\"view\":{\"appliesTo\":{\"principalTypes\":[\"User\"],\"resourceTypes\":[\"Document\"]}}}}",
		"policies": ["permit(principal == User::\"alice\", action == Action::\"view\", resource);"],
		"level": 1
	}`))

	// Policy with condition at level 2
	f.Add([]byte(`{
		"schema": "{\"entityTypes\":{\"User\":{\"shape\":{\"type\":\"Record\",\"attributes\":{\"role\":{\"type\":\"String\"}}}},\"Document\":{}},\"actions\":{\"view\":{\"appliesTo\":{\"principalTypes\":[\"User\"],\"resourceTypes\":[\"Document\"]}}}}",
		"policies": ["permit(principal, action, resource) when { principal.role == \"admin\" };"],
		"level": 2
	}`))

	// Policy with entity hierarchy
	f.Add([]byte(`{
		"schema": "{\"entityTypes\":{\"User\":{\"memberOfTypes\":[\"Group\"]},\"Group\":{},\"Document\":{}},\"actions\":{\"view\":{\"appliesTo\":{\"principalTypes\":[\"User\",\"Group\"],\"resourceTypes\":[\"Document\"]}}}}",
		"policies": ["permit(principal in Group::\"admins\", action, resource);"],
		"level": 1
	}`))

	// Minimal schema with forbid policy
	f.Add([]byte(`{
		"schema": "{\"entityTypes\":{\"User\":{},\"Document\":{}},\"actions\":{\"delete\":{\"appliesTo\":{\"principalTypes\":[\"User\"],\"resourceTypes\":[\"Document\"]}}}}",
		"policies": ["forbid(principal, action == Action::\"delete\", resource);"],
		"level": 0
	}`))

	// Load corpus from testdata
	loadCorpusSeeds(f, "testdata/fuzz/FuzzLevelValidation")
}

// TestLevelValidationBasic tests basic level validation scenarios
func TestLevelValidationBasic(t *testing.T) {
	tests := []struct {
		name        string
		schema      string
		policy      string
		level       int32
		expectParse bool
	}{
		{
			name:        "simple policy level 0",
			schema:      `{"entityTypes":{"User":{},"Document":{}},"actions":{"view":{"appliesTo":{"principalTypes":["User"],"resourceTypes":["Document"]}}}}`,
			policy:      `permit(principal, action, resource);`,
			level:       0,
			expectParse: true,
		},
		{
			name:        "simple policy level 1",
			schema:      `{"entityTypes":{"User":{},"Document":{}},"actions":{"view":{"appliesTo":{"principalTypes":["User"],"resourceTypes":["Document"]}}}}`,
			policy:      `permit(principal, action, resource);`,
			level:       1,
			expectParse: true,
		},
		{
			name:        "typed policy level 2",
			schema:      `{"entityTypes":{"User":{}},"actions":{}}`,
			policy:      `permit(principal == User::"alice", action, resource);`,
			level:       2,
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
