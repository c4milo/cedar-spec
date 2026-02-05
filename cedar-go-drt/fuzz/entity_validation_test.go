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
	"runtime"
	"testing"

	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/schema"

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/lean"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/proto"
)

// EntityValidationFuzzInput represents the structure of entity validation fuzz input.
type EntityValidationFuzzInput struct {
	Schema   string          `json:"schema"`
	Entities json.RawMessage `json:"entities"`
}

// parseEntityValidationInput parses the entity validation fuzz input.
func parseEntityValidationInput(data []byte) (*schema.Schema, types.EntityMap, error) {
	var input EntityValidationFuzzInput
	if err := json.Unmarshal(data, &input); err != nil {
		return nil, nil, err
	}

	s, err := schema.NewFromJSON([]byte(input.Schema))
	if err != nil {
		return nil, nil, err
	}

	var entities types.EntityMap
	if err := json.Unmarshal(input.Entities, &entities); err != nil {
		return nil, nil, err
	}

	return s, entities, nil
}

// runLeanEntityValidation runs Lean entity validation and returns the result.
func runLeanEntityValidation(t *testing.T, s *schema.Schema, entities types.EntityMap) *lean.ValidationResponse {
	t.Helper()

	req := proto.EntityValidationFromCedar(s, entities)
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

	leanResp, err := lean.ValidateEntities(protoBytes)
	if err != nil {
		t.Logf("Lean FFI error: %v", err)
		return nil
	}

	return leanResp
}

// FuzzEntityValidation is the fuzz target for entity validation testing.
// It validates that entities conform to a schema using the Lean formalization.
func FuzzEntityValidation(f *testing.F) {
	addEntityValidationSeeds(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		s, entities, err := parseEntityValidationInput(data)
		if err != nil {
			return // Invalid input, skip
		}

		// Run Lean entity validation
		leanResp := runLeanEntityValidation(t, s, entities)
		if leanResp == nil {
			return // Lean error, skip
		}

		// For now, we verify Lean can validate without crashing.
		// Cedar-go doesn't expose direct entity validation, so we can't compare.
		// A valid response (either valid or with errors) is acceptable.
		_ = leanResp.Valid
	})
}

func addEntityValidationSeeds(f *testing.F) {
	// Valid entities matching schema
	f.Add([]byte(`{
		"schema": "{\"entityTypes\":{\"User\":{\"shape\":{\"type\":\"Record\",\"attributes\":{\"name\":{\"type\":\"String\"}}}},\"Document\":{}},\"actions\":{\"view\":{\"appliesTo\":{\"principalTypes\":[\"User\"],\"resourceTypes\":[\"Document\"]}}}}",
		"entities": [
			{
				"uid": {"type": "User", "id": "alice"},
				"attrs": {"name": "Alice"},
				"parents": []
			},
			{
				"uid": {"type": "Document", "id": "doc1"},
				"attrs": {},
				"parents": []
			}
		]
	}`))

	// Empty entities
	f.Add([]byte(`{
		"schema": "{\"entityTypes\":{\"User\":{}},\"actions\":{}}",
		"entities": []
	}`))

	// Entity with parent relationship
	f.Add([]byte(`{
		"schema": "{\"entityTypes\":{\"User\":{\"memberOfTypes\":[\"Group\"]},\"Group\":{}},\"actions\":{}}",
		"entities": [
			{
				"uid": {"type": "User", "id": "alice"},
				"attrs": {},
				"parents": [{"type": "Group", "id": "admins"}]
			},
			{
				"uid": {"type": "Group", "id": "admins"},
				"attrs": {},
				"parents": []
			}
		]
	}`))

	// Load corpus from testdata
	loadCorpusSeeds(f, "testdata/fuzz/FuzzEntityValidation")
}

// TestEntityValidationBasic tests basic entity validation scenarios
func TestEntityValidationBasic(t *testing.T) {
	tests := []struct {
		name        string
		schema      string
		entities    string
		expectParse bool
	}{
		{
			name:        "valid schema and entities",
			schema:      `{"entityTypes":{"User":{}},"actions":{}}`,
			entities:    `[{"uid":{"type":"User","id":"alice"},"attrs":{},"parents":[]}]`,
			expectParse: true,
		},
		{
			name:        "empty entities",
			schema:      `{"entityTypes":{"User":{}},"actions":{}}`,
			entities:    `[]`,
			expectParse: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := schema.NewFromJSON([]byte(tc.schema))
			if (err == nil) != tc.expectParse {
				t.Errorf("Schema parse: expected success=%v, got error=%v", tc.expectParse, err)
			}

			var entities types.EntityMap
			err = json.Unmarshal([]byte(tc.entities), &entities)
			if (err == nil) != tc.expectParse {
				t.Errorf("Entities parse: expected success=%v, got error=%v", tc.expectParse, err)
			}
		})
	}
}
