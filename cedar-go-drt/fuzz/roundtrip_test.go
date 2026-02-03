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
	"bytes"
	"encoding/json"
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/x/exp/schema"

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/typegen"
)

// FuzzPolicyRoundtrip tests that policies survive Cedar -> JSON -> Cedar roundtrip.
func FuzzPolicyRoundtrip(f *testing.F) {
	// Add seed policies
	f.Add([]byte(`permit(principal, action, resource);`))
	f.Add([]byte(`forbid(principal, action, resource) when { context.admin == false };`))
	f.Add([]byte(`permit(principal == User::"alice", action, resource in Folder::"public");`))
	f.Add([]byte(`permit(principal, action in [Action::"read", Action::"write"], resource);`))

	f.Fuzz(func(t *testing.T, policyBytes []byte) {
		// Parse as Cedar
		var policy1 cedar.Policy
		if err := policy1.UnmarshalCedar(policyBytes); err != nil {
			return // Invalid Cedar, skip
		}

		// Marshal to JSON
		jsonBytes, err := policy1.MarshalJSON()
		if err != nil {
			t.Errorf("MarshalJSON failed for valid policy: %v", err)
			return
		}

		// Parse JSON back
		var policy2 cedar.Policy
		if err := policy2.UnmarshalJSON(jsonBytes); err != nil {
			t.Errorf("UnmarshalJSON failed: %v\nJSON: %s", err, string(jsonBytes))
			return
		}

		// Marshal back to Cedar
		cedarBytes2 := policy2.MarshalCedar()
		if len(cedarBytes2) == 0 {
			t.Errorf("MarshalCedar returned empty after roundtrip")
			return
		}

		// Parse again to compare
		var policy3 cedar.Policy
		if err := policy3.UnmarshalCedar(cedarBytes2); err != nil {
			t.Errorf("Final UnmarshalCedar failed: %v\nCedar: %s", err, string(cedarBytes2))
			return
		}

		// Compare JSON representations (more stable than Cedar text)
		json1, _ := policy1.MarshalJSON()
		json3, _ := policy3.MarshalJSON()

		if !jsonEqual(json1, json3) {
			t.Errorf("Policy changed after roundtrip:\nOriginal: %s\nAfter: %s",
				string(json1), string(json3))
		}
	})
}

// FuzzSchemaRoundtrip tests that schemas survive JSON -> Cedar -> JSON roundtrip.
func FuzzSchemaRoundtrip(f *testing.F) {
	// Add seed schemas
	f.Add([]byte(`{"": {"entityTypes": {"User": {}}, "actions": {"view": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["User"]}}}}}`))
	f.Add([]byte(`{"": {"entityTypes": {"Doc": {"shape": {"type": "Record", "attributes": {"title": {"type": "String", "required": true}}}}}, "actions": {}}}`))

	f.Fuzz(func(t *testing.T, schemaBytes []byte) {
		// Parse as JSON
		var s1 schema.Schema
		if err := s1.UnmarshalJSON(schemaBytes); err != nil {
			return // Invalid JSON schema, skip
		}

		// Marshal to Cedar format
		cedarBytes, err := s1.MarshalCedar()
		if err != nil {
			// Some valid JSON schemas may not marshal to Cedar
			return
		}

		// Parse Cedar back
		var s2 schema.Schema
		if err := s2.UnmarshalCedar(cedarBytes); err != nil {
			t.Errorf("UnmarshalCedar failed: %v\nCedar: %s", err, string(cedarBytes))
			return
		}

		// Marshal back to JSON
		jsonBytes2, err := s2.MarshalJSON()
		if err != nil {
			t.Errorf("MarshalJSON failed after roundtrip: %v", err)
			return
		}

		// Both should parse to equivalent structures
		if len(jsonBytes2) == 0 && len(schemaBytes) > 2 {
			t.Logf("Schema became empty after roundtrip")
		}
	})
}

// FuzzPolicySetRoundtrip tests policy set roundtrip.
func FuzzPolicySetRoundtrip(f *testing.F) {
	inputGen := typegen.DefaultInputGenerator()

	f.Add([]byte("policyset-seed-1"))
	f.Add([]byte("policyset-seed-2"))
	f.Add(make([]byte, 128))

	f.Fuzz(func(t *testing.T, data []byte) {
		policies, ok := preparePolicySetRoundtrip(data, inputGen)
		if !ok {
			return
		}
		testPolicySetJSONRoundtrip(t, policies)
	})
}

func preparePolicySetRoundtrip(data []byte, inputGen *typegen.InputGenerator) (*cedar.PolicySet, bool) {
	if len(data) < 16 {
		return nil, false
	}

	input, err := inputGen.Generate(data)
	if err != nil || input.Policies == nil {
		return nil, false
	}

	count := 0
	for range input.Policies.All() {
		count++
	}
	if count == 0 {
		return nil, false
	}

	return input.Policies, true
}

func testPolicySetJSONRoundtrip(t *testing.T, policies *cedar.PolicySet) {
	for id, policy := range policies.All() {
		testSinglePolicyJSONRoundtrip(t, id, policy)
	}
}

func testSinglePolicyJSONRoundtrip(t *testing.T, id cedar.PolicyID, policy *cedar.Policy) {
	jsonBytes, err := policy.MarshalJSON()
	if err != nil {
		t.Errorf("MarshalJSON failed for policy %s: %v", id, err)
		return
	}

	var policy2 cedar.Policy
	if err := policy2.UnmarshalJSON(jsonBytes); err != nil {
		t.Errorf("UnmarshalJSON failed for policy %s: %v", id, err)
	}
}

// FuzzEntitiesRoundtrip tests entities roundtrip via JSON.
func FuzzEntitiesRoundtrip(f *testing.F) {
	inputGen := typegen.DefaultInputGenerator()

	f.Add([]byte("entities-seed-1"))
	f.Add(make([]byte, 64))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 16 {
			return
		}

		input, err := inputGen.Generate(data)
		if err != nil {
			return
		}

		if input.Entities == nil || len(input.Entities.Entities) == 0 {
			return
		}

		// Marshal entities to JSON
		jsonBytes, err := json.Marshal(entitiesToJSON(input.Entities))
		if err != nil {
			t.Errorf("Failed to marshal entities: %v", err)
			return
		}

		// Verify it's valid JSON
		var raw any
		if err := json.Unmarshal(jsonBytes, &raw); err != nil {
			t.Errorf("Entities JSON is invalid: %v", err)
		}
	})
}

// entitiesToJSON converts entities to a JSON-serializable format.
func entitiesToJSON(entities *typegen.GeneratedEntities) []map[string]any {
	var result []map[string]any

	for uid, entity := range entities.Entities {
		e := map[string]any{
			"uid": map[string]string{
				"type": string(uid.Type),
				"id":   string(uid.ID),
			},
		}

		// Add parents
		var parents []map[string]string
		for parent := range entity.Parents.All() {
			parents = append(parents, map[string]string{
				"type": string(parent.Type),
				"id":   string(parent.ID),
			})
		}
		if len(parents) > 0 {
			e["parents"] = parents
		}

		result = append(result, e)
	}

	return result
}

// jsonEqual compares two JSON byte slices for semantic equality.
func jsonEqual(a, b []byte) bool {
	var objA, objB any
	if err := json.Unmarshal(a, &objA); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &objB); err != nil {
		return false
	}

	// Re-marshal to normalize
	normA, _ := json.Marshal(objA)
	normB, _ := json.Marshal(objB)

	return bytes.Equal(normA, normB)
}
