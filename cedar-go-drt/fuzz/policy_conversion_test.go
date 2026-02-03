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

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/typegen"
)

// FuzzPolicyCedarToJSON tests that Cedar text -> AST -> JSON -> AST roundtrips correctly.
// This verifies that parsing Cedar syntax and converting to JSON produces equivalent policies.
func FuzzPolicyCedarToJSON(f *testing.F) {
	// Add seeds
	f.Add([]byte("permit(principal, action, resource);"))
	f.Add([]byte(`forbid(principal, action, resource) when { context.x > 5 };`))
	f.Add([]byte(`permit(principal == User::"alice", action, resource);`))
	f.Add(make([]byte, 32))
	f.Add(make([]byte, 64))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Try to parse as Cedar text
		var policy cedar.Policy
		if err := policy.UnmarshalCedar(data); err != nil {
			return // Invalid Cedar, skip
		}

		// Cedar -> JSON
		jsonBytes, err := policy.MarshalJSON()
		if err != nil {
			t.Fatalf("Failed to marshal valid policy to JSON: %v", err)
		}

		// JSON -> Policy
		var roundtrippedPolicy cedar.Policy
		if err := roundtrippedPolicy.UnmarshalJSON(jsonBytes); err != nil {
			t.Fatalf("Failed to unmarshal JSON back to policy: %v\nJSON: %s", err, string(jsonBytes))
		}

		// Compare by re-serializing to Cedar text
		originalCedar := policy.MarshalCedar()
		roundtrippedCedar := roundtrippedPolicy.MarshalCedar()

		if !bytes.Equal(originalCedar, roundtrippedCedar) {
			t.Errorf("Policy roundtrip mismatch!\nOriginal: %s\nRoundtripped: %s\nJSON: %s",
				string(originalCedar), string(roundtrippedCedar), string(jsonBytes))
		}
	})
}

// FuzzPolicyJSONToCedar tests that JSON -> AST -> Cedar text -> AST roundtrips correctly.
// This verifies that parsing JSON policies and converting to Cedar syntax works.
func FuzzPolicyJSONToCedar(f *testing.F) {
	// Add JSON seeds
	f.Add([]byte(`{"effect":"permit","principal":{"op":"All"},"action":{"op":"All"},"resource":{"op":"All"},"conditions":[]}`))
	f.Add([]byte(`{"effect":"forbid","principal":{"op":"All"},"action":{"op":"All"},"resource":{"op":"All"},"conditions":[{"kind":"when","body":{"Value":false}}]}`))
	f.Add(make([]byte, 64))

	f.Fuzz(func(t *testing.T, data []byte) {
		// First check if it's valid JSON
		if !json.Valid(data) {
			return
		}

		// Try to parse as JSON policy
		var policy cedar.Policy
		if err := policy.UnmarshalJSON(data); err != nil {
			return // Invalid policy JSON, skip
		}

		// JSON -> Cedar text
		cedarBytes := policy.MarshalCedar()

		// Cedar text -> Policy
		var roundtrippedPolicy cedar.Policy
		if err := roundtrippedPolicy.UnmarshalCedar(cedarBytes); err != nil {
			t.Fatalf("Failed to parse Cedar text back to policy: %v\nCedar: %s", err, string(cedarBytes))
		}

		// Compare by re-serializing to JSON
		originalJSON, _ := policy.MarshalJSON()
		roundtrippedJSON, _ := roundtrippedPolicy.MarshalJSON()

		// Parse both JSON to compare structurally (ignore whitespace differences)
		var originalMap, roundtrippedMap map[string]any
		_ = json.Unmarshal(originalJSON, &originalMap)
		_ = json.Unmarshal(roundtrippedJSON, &roundtrippedMap)

		originalNorm, _ := json.Marshal(originalMap)
		roundtrippedNorm, _ := json.Marshal(roundtrippedMap)

		if !bytes.Equal(originalNorm, roundtrippedNorm) {
			t.Errorf("Policy JSON->Cedar->JSON mismatch!\nOriginal JSON: %s\nCedar: %s\nRoundtripped JSON: %s",
				string(originalJSON), string(cedarBytes), string(roundtrippedJSON))
		}
	})
}

// FuzzPolicySetCedarToJSON tests PolicySet Cedar -> JSON -> Cedar roundtripping.
func FuzzPolicySetCedarToJSON(f *testing.F) {
	f.Add([]byte("permit(principal, action, resource);"))
	f.Add([]byte("permit(principal, action, resource);\nforbid(principal, action, resource) when { false };"))
	f.Add(make([]byte, 64))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 16 {
			return
		}

		// Generate valid policies
		input, err := inputGen.GenerateForAuthorization(data)
		if err != nil {
			return
		}

		// For each policy, test roundtrip
		for _, policy := range input.Policies.All() {
			// Cedar -> JSON
			jsonBytes, err := policy.MarshalJSON()
			if err != nil {
				continue // Skip policies that can't marshal
			}

			// JSON -> Policy
			var roundtripped cedar.Policy
			if err := roundtripped.UnmarshalJSON(jsonBytes); err != nil {
				t.Errorf("Failed to unmarshal JSON: %v\nJSON: %s", err, string(jsonBytes))
				continue
			}

			// Compare effects
			if policy.Effect() != roundtripped.Effect() {
				t.Errorf("Effect mismatch: original=%v, roundtripped=%v",
					policy.Effect(), roundtripped.Effect())
			}
		}
	})
}

// TestPolicyCedarToJSONBasic tests basic Cedar -> JSON conversion scenarios.
func TestPolicyCedarToJSONBasic(t *testing.T) {
	tests := []struct {
		name   string
		cedar  string
		effect cedar.Effect
	}{
		{
			name:   "simple permit",
			cedar:  "permit(principal, action, resource);",
			effect: cedar.Permit,
		},
		{
			name:   "simple forbid",
			cedar:  "forbid(principal, action, resource);",
			effect: cedar.Forbid,
		},
		{
			name:   "permit with when condition",
			cedar:  "permit(principal, action, resource) when { true };",
			effect: cedar.Permit,
		},
		{
			name:   "permit with unless condition",
			cedar:  "permit(principal, action, resource) unless { false };",
			effect: cedar.Permit,
		},
		{
			name:   "principal constraint",
			cedar:  `permit(principal == User::"alice", action, resource);`,
			effect: cedar.Permit,
		},
		{
			name:   "action constraint",
			cedar:  `permit(principal, action == Action::"view", resource);`,
			effect: cedar.Permit,
		},
		{
			name:   "resource constraint",
			cedar:  `permit(principal, action, resource == Doc::"readme");`,
			effect: cedar.Permit,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runCedarToJSONTestCase(t, tc.cedar, tc.effect)
		})
	}
}

func runCedarToJSONTestCase(t *testing.T, cedarStr string, expectedEffect cedar.Effect) {
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(cedarStr)); err != nil {
		t.Fatalf("Failed to parse Cedar: %v", err)
	}

	jsonBytes, err := policy.MarshalJSON()
	if err != nil {
		t.Fatalf("Failed to marshal to JSON: %v", err)
	}

	var roundtripped cedar.Policy
	if err := roundtripped.UnmarshalJSON(jsonBytes); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if roundtripped.Effect() != expectedEffect {
		t.Errorf("Effect mismatch: expected %v, got %v", expectedEffect, roundtripped.Effect())
	}

	verifyCedarTextRoundtrip(t, policy, roundtripped)
}

func verifyCedarTextRoundtrip(t *testing.T, original, roundtripped cedar.Policy) {
	originalCedar := original.MarshalCedar()
	roundtrippedCedar := roundtripped.MarshalCedar()

	if !bytes.Equal(originalCedar, roundtrippedCedar) {
		t.Errorf("Cedar text mismatch!\nOriginal: %s\nRoundtripped: %s",
			string(originalCedar), string(roundtrippedCedar))
	}
}

// TestPolicyJSONToCedarBasic tests basic JSON -> Cedar conversion scenarios.
func TestPolicyJSONToCedarBasic(t *testing.T) {
	tests := []struct {
		name   string
		json   string
		effect cedar.Effect
	}{
		{
			name:   "permit all",
			json:   `{"effect":"permit","principal":{"op":"All"},"action":{"op":"All"},"resource":{"op":"All"},"conditions":[]}`,
			effect: cedar.Permit,
		},
		{
			name:   "forbid all",
			json:   `{"effect":"forbid","principal":{"op":"All"},"action":{"op":"All"},"resource":{"op":"All"},"conditions":[]}`,
			effect: cedar.Forbid,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var policy cedar.Policy
			if err := policy.UnmarshalJSON([]byte(tc.json)); err != nil {
				t.Fatalf("Failed to parse JSON: %v", err)
			}

			// Verify effect
			if policy.Effect() != tc.effect {
				t.Errorf("Effect mismatch: expected %v, got %v", tc.effect, policy.Effect())
			}

			// JSON -> Cedar -> JSON roundtrip
			cedarBytes := policy.MarshalCedar()

			var roundtripped cedar.Policy
			if err := roundtripped.UnmarshalCedar(cedarBytes); err != nil {
				t.Fatalf("Failed to parse Cedar: %v\nCedar: %s", err, string(cedarBytes))
			}

			if roundtripped.Effect() != tc.effect {
				t.Errorf("Roundtripped effect mismatch: expected %v, got %v", tc.effect, roundtripped.Effect())
			}
		})
	}
}
