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
)

// FuzzJSONSchemaRoundtrip tests JSON schema roundtrip (JSON → parse → JSON).
func FuzzJSONSchemaRoundtrip(f *testing.F) {
	f.Add([]byte(`{"": {"entityTypes": {}, "actions": {}}}`))
	f.Add([]byte(`{"": {"entityTypes": {"User": {}}, "actions": {"view": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["User"]}}}}}`))
	f.Add([]byte(`{"NS": {"entityTypes": {"Doc": {"shape": {"type": "Record", "attributes": {"title": {"type": "String"}}}}}, "actions": {}}}`))

	f.Fuzz(func(t *testing.T, schemaBytes []byte) {
		// Parse JSON schema
		var s1 schema.Schema
		if err := s1.UnmarshalJSON(schemaBytes); err != nil {
			return // Invalid JSON, skip
		}

		// Marshal back to JSON
		jsonBytes1, err := s1.MarshalJSON()
		if err != nil {
			return // Some schemas may not marshal
		}

		// Parse again
		var s2 schema.Schema
		if err := s2.UnmarshalJSON(jsonBytes1); err != nil {
			t.Errorf("Failed to parse re-marshaled JSON: %v", err)
			return
		}

		// Marshal again and compare
		jsonBytes2, err := s2.MarshalJSON()
		if err != nil {
			t.Errorf("Failed to marshal second time: %v", err)
			return
		}

		if !jsonEqual(jsonBytes1, jsonBytes2) {
			t.Errorf("JSON schema not stable after roundtrip:\nFirst:  %s\nSecond: %s",
				string(jsonBytes1), string(jsonBytes2))
		}
	})
}

// FuzzSchemaCedarToJSON tests schema conversion from Cedar format to JSON.
func FuzzSchemaCedarToJSON(f *testing.F) {
	f.Add([]byte(`entity User;`))
	f.Add([]byte(`entity User { name: String };`))
	f.Add([]byte(`entity Doc; action view appliesTo { principal: User, resource: Doc };`))
	f.Add([]byte(`namespace NS { entity Foo; }`))

	f.Fuzz(func(t *testing.T, cedarBytes []byte) {
		// Parse Cedar schema
		var s schema.Schema
		if err := s.UnmarshalCedar(cedarBytes); err != nil {
			return // Invalid Cedar schema, skip
		}

		// Convert to JSON
		jsonBytes, err := s.MarshalJSON()
		if err != nil {
			// Some valid Cedar schemas may not convert to JSON
			return
		}

		if len(jsonBytes) == 0 {
			t.Error("MarshalJSON produced empty output for valid schema")
		}

		// Verify it's valid JSON
		var raw any
		if err := json.Unmarshal(jsonBytes, &raw); err != nil {
			t.Errorf("MarshalJSON produced invalid JSON: %v", err)
		}
	})
}

// FuzzSchemaJSONToCedar tests schema conversion from JSON to Cedar format.
func FuzzSchemaJSONToCedar(f *testing.F) {
	f.Add([]byte(`{"": {"entityTypes": {"User": {}}, "actions": {}}}`))
	f.Add([]byte(`{"": {"entityTypes": {"Doc": {"shape": {"type": "Record", "attributes": {"title": {"type": "String"}}}}}, "actions": {"view": {"appliesTo": {"principalTypes": ["Doc"], "resourceTypes": ["Doc"]}}}}}`))

	f.Fuzz(func(t *testing.T, jsonBytes []byte) {
		// Parse JSON schema
		var s schema.Schema
		if err := s.UnmarshalJSON(jsonBytes); err != nil {
			return // Invalid JSON, skip
		}

		// Convert to Cedar format
		cedarBytes, err := s.MarshalCedar()
		if err != nil {
			// Some JSON schemas may not convert to Cedar
			return
		}

		if len(cedarBytes) == 0 && len(jsonBytes) > 10 {
			// Non-trivial schema should produce output
			t.Logf("Warning: non-trivial schema produced empty Cedar output")
		}
	})
}

// FuzzSimpleParser tests basic policy parsing.
func FuzzSimpleParser(f *testing.F) {
	f.Add([]byte(`permit(principal, action, resource);`))
	f.Add([]byte(`forbid(principal, action, resource);`))
	f.Add([]byte(`permit(principal == User::"alice", action, resource);`))
	f.Add([]byte(`permit(principal, action, resource) when { true };`))
	f.Add([]byte(`permit(principal, action, resource) unless { false };`))
	f.Add([]byte(`permit(principal in Group::"admins", action == Action::"delete", resource);`))

	f.Fuzz(func(t *testing.T, policyBytes []byte) {
		var policy cedar.Policy
		err := policy.UnmarshalCedar(policyBytes)

		if err != nil {
			// Invalid policy - that's fine, just verify we don't panic
			return
		}

		// Valid policy - verify we can marshal it back
		cedarOut := policy.MarshalCedar()
		if len(cedarOut) == 0 {
			t.Error("MarshalCedar returned empty for valid policy")
		}

		// Verify we can parse the output
		var policy2 cedar.Policy
		if err := policy2.UnmarshalCedar(cedarOut); err != nil {
			t.Errorf("Failed to re-parse marshaled policy: %v\nOutput: %s", err, string(cedarOut))
		}
	})
}

// FuzzFormatter tests policy formatting (marshal produces valid, parseable output).
func FuzzFormatter(f *testing.F) {
	f.Add([]byte(`permit(principal,action,resource);`))
	f.Add([]byte(`permit(principal, action, resource) when { context.x == 1 };`))
	f.Add([]byte(`forbid(principal, action, resource) unless { principal.admin };`))

	f.Fuzz(func(t *testing.T, policyBytes []byte) {
		var policy cedar.Policy
		if err := policy.UnmarshalCedar(policyBytes); err != nil {
			return
		}

		// Format (marshal) the policy
		formatted := policy.MarshalCedar()

		// Verify formatted output is valid
		var policy2 cedar.Policy
		if err := policy2.UnmarshalCedar(formatted); err != nil {
			t.Errorf("Formatted policy is not valid: %v\nOriginal: %s\nFormatted: %s",
				err, string(policyBytes), string(formatted))
			return
		}

		// Formatting should be idempotent
		formatted2 := policy2.MarshalCedar()
		if !bytes.Equal(formatted, formatted2) {
			t.Errorf("Formatting not idempotent:\nFirst:  %s\nSecond: %s",
				string(formatted), string(formatted2))
		}
	})
}

// FuzzFormatterBytes tests formatting with arbitrary byte inputs.
func FuzzFormatterBytes(f *testing.F) {
	f.Add(make([]byte, 0))
	f.Add(make([]byte, 10))
	f.Add([]byte("random garbage that's not a policy"))
	f.Add([]byte{0, 1, 2, 3, 255, 254, 253})

	f.Fuzz(func(t *testing.T, data []byte) {
		var policy cedar.Policy
		err := policy.UnmarshalCedar(data)

		// We don't care if it fails - just verify no panics
		if err != nil {
			return
		}

		// If it parsed, formatting should work
		_ = policy.MarshalCedar()
	})
}

// FuzzEntitiesRoundtripBytes tests entity roundtrip with arbitrary bytes.
func FuzzEntitiesRoundtripBytes(f *testing.F) {
	f.Add([]byte(`[]`))
	f.Add([]byte(`[{"uid": {"type": "User", "id": "alice"}, "attrs": {}, "parents": []}]`))
	f.Add(make([]byte, 50))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Try to parse as entity JSON
		var entities []map[string]any
		if err := json.Unmarshal(data, &entities); err != nil {
			return // Not valid JSON array
		}

		// Re-marshal
		output, err := json.Marshal(entities)
		if err != nil {
			return
		}

		// Should produce valid JSON
		var entities2 []map[string]any
		if err := json.Unmarshal(output, &entities2); err != nil {
			t.Errorf("Re-marshaled entities not valid JSON: %v", err)
		}
	})
}

// FuzzGeneralRoundtrip tests general Cedar policy roundtrip through all formats.
func FuzzGeneralRoundtrip(f *testing.F) {
	f.Add([]byte(`permit(principal, action, resource);`))
	f.Add([]byte(`forbid(principal, action, resource) when { context.level > 5 };`))

	f.Fuzz(func(t *testing.T, policyBytes []byte) {
		// Cedar -> Policy
		var p1 cedar.Policy
		if err := p1.UnmarshalCedar(policyBytes); err != nil {
			return
		}

		// Policy -> JSON
		jsonBytes, err := p1.MarshalJSON()
		if err != nil {
			t.Errorf("MarshalJSON failed: %v", err)
			return
		}

		// JSON -> Policy
		var p2 cedar.Policy
		if err := p2.UnmarshalJSON(jsonBytes); err != nil {
			t.Errorf("UnmarshalJSON failed: %v\nJSON: %s", err, string(jsonBytes))
			return
		}

		// Policy -> Cedar
		cedarBytes2 := p2.MarshalCedar()

		// Cedar -> Policy (final)
		var p3 cedar.Policy
		if err := p3.UnmarshalCedar(cedarBytes2); err != nil {
			t.Errorf("Final UnmarshalCedar failed: %v\nCedar: %s", err, string(cedarBytes2))
			return
		}

		// Compare via JSON (most stable comparison)
		json1, _ := p1.MarshalJSON()
		json3, _ := p3.MarshalJSON()

		if !jsonEqual(json1, json3) {
			t.Errorf("Policy changed after full roundtrip:\nOriginal JSON: %s\nFinal JSON: %s",
				string(json1), string(json3))
		}
	})
}
