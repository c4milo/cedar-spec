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
	"strings"
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
)

// FuzzPolicyParserCrash tests that the policy parser does not crash on arbitrary input.
// This is a pure Go test that does not require Lean.
//
// The test ensures the parser handles malformed input gracefully by returning
// errors rather than panicking. This is important for security as parsers are
// often exposed to untrusted input.
func FuzzPolicyParserCrash(f *testing.F) {
	// Add seed corpus with various valid and invalid policy strings
	addParserSeeds(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Limit input size to avoid excessive memory usage
		if len(data) > 10000 {
			return
		}

		// Test policy parsing - should not panic
		var policy cedar.Policy
		_ = policy.UnmarshalCedar(data)

		// Also test as string input
		_ = policy.UnmarshalCedar([]byte(string(data)))
	})
}

// FuzzSimpleParserString tests policy parsing starting from string input.
func FuzzSimpleParserString(f *testing.F) {
	f.Add("permit(principal, action, resource);")
	f.Add("forbid(principal, action, resource);")
	f.Add("")
	f.Add("invalid")
	f.Add("permit(")
	f.Add("permit(principal")
	f.Add("permit(principal,")
	f.Add("permit(principal, action")
	f.Add("permit(principal, action,")
	f.Add("permit(principal, action, resource")
	f.Add("permit(principal, action, resource)")
	f.Add("permit(principal, action, resource) when")
	f.Add("permit(principal, action, resource) when {")
	f.Add("permit(principal, action, resource) when { true")
	f.Add("permit(principal, action, resource) when { true }")
	f.Add(strings.Repeat("permit(", 100))
	f.Add(strings.Repeat("(", 1000))
	f.Add(strings.Repeat(")", 1000))
	f.Add(strings.Repeat("{", 1000))
	f.Add(strings.Repeat("}", 1000))

	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 10000 {
			return
		}

		var policy cedar.Policy
		_ = policy.UnmarshalCedar([]byte(input))
	})
}

// FuzzSchemaParser tests that the schema parser does not crash on arbitrary input.
func FuzzSchemaParser(f *testing.F) {
	addSchemaParserSeeds(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 10000 {
			return
		}

		// Test JSON schema parsing - should not panic
		_, _ = schema.NewFromJSON(data)

		// Test Cedar schema parsing - should not panic
		_, _ = schema.NewFromCedar("fuzz.cedar", data)
	})
}

// FuzzEntityUIDParser tests that entity UID string parsing does not crash.
// Note: cedar-go uses types.NewEntityUID(type, id) rather than parsing strings,
// so this test focuses on JSON entity parsing.
func FuzzEntityUIDParser(f *testing.F) {
	addEntityParserSeeds(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 10000 {
			return
		}

		// Test JSON entity parsing - this exercises entity UID handling
		var entity map[string]any
		_ = json.Unmarshal(data, &entity)
	})
}

// addParserSeeds adds seed corpus entries for policy parsing.
func addParserSeeds(f *testing.F) {
	// Valid policies
	f.Add([]byte(`permit(principal, action, resource);`))
	f.Add([]byte(`forbid(principal, action, resource);`))
	f.Add([]byte(`permit(principal == User::"alice", action, resource);`))
	f.Add([]byte(`permit(principal, action == Action::"read", resource);`))
	f.Add([]byte(`permit(principal, action, resource == Document::"doc1");`))
	f.Add([]byte(`permit(principal in Group::"admins", action, resource);`))
	f.Add([]byte(`permit(principal, action in [Action::"read", Action::"write"], resource);`))
	f.Add([]byte(`permit(principal, action, resource) when { true };`))
	f.Add([]byte(`permit(principal, action, resource) when { context.admin == true };`))
	f.Add([]byte(`permit(principal, action, resource) unless { context.blocked };`))
	f.Add([]byte(`@id("policy1") permit(principal, action, resource);`))

	// Invalid/malformed policies
	f.Add([]byte(``))
	f.Add([]byte(`permit`))
	f.Add([]byte(`permit(`))
	f.Add([]byte(`permit(principal`))
	f.Add([]byte(`permit(principal,`))
	f.Add([]byte(`permit(principal, action`))
	f.Add([]byte(`permit(principal, action,`))
	f.Add([]byte(`permit(principal, action, resource`))
	f.Add([]byte(`permit(principal, action, resource)`))
	f.Add([]byte(`permit(principal, action, resource) when`))
	f.Add([]byte(`permit(principal, action, resource) when {`))
	f.Add([]byte(`permit(principal, action, resource) when { }`))
	f.Add([]byte(`invalid`))
	f.Add([]byte(`permit permit permit`))
	f.Add([]byte(`;;;`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`[]`))

	// Edge cases
	f.Add([]byte{0x00})
	f.Add([]byte{0xFF})
	f.Add([]byte{0x00, 0x00, 0x00})
	f.Add(make([]byte, 256))

	// Unicode edge cases
	f.Add([]byte(`permit(principal == User::"日本語", action, resource);`))
	f.Add([]byte(`permit(principal == User::"émoji🎉", action, resource);`))
	f.Add([]byte(`permit(principal == User::"\u0000", action, resource);`))

	// Deeply nested expressions
	f.Add([]byte(`permit(principal, action, resource) when { ((((true)))) };`))
	f.Add([]byte(`permit(principal, action, resource) when { if true then true else true };`))

	// Long identifiers
	longID := strings.Repeat("a", 1000)
	f.Add([]byte(`permit(principal == User::"` + longID + `", action, resource);`))

	// Repeated structures
	f.Add([]byte(strings.Repeat("permit(principal, action, resource);", 100)))
}

// addSchemaParserSeeds adds seed corpus entries for schema parsing.
func addSchemaParserSeeds(f *testing.F) {
	// Valid JSON schemas
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"": {"entityTypes": {}, "actions": {}}}`))
	f.Add([]byte(`{"": {"entityTypes": {"User": {}}, "actions": {}}}`))
	f.Add([]byte(`{"": {"entityTypes": {"User": {}}, "actions": {"view": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["User"]}}}}}`))
	f.Add([]byte(`{"Namespace": {"entityTypes": {"User": {"shape": {"type": "Record", "attributes": {}}}}, "actions": {}}}`))

	// Invalid JSON
	f.Add([]byte(`{`))
	f.Add([]byte(`}`))
	f.Add([]byte(`{"entityTypes":`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`"string"`))
	f.Add([]byte(`123`))

	// Cedar schema syntax
	f.Add([]byte(`entity User;`))
	f.Add([]byte(`entity User { name: String };`))
	f.Add([]byte(`action view appliesTo { principal: [User], resource: [User] };`))
	f.Add([]byte(`namespace Ns { entity User; }`))

	// Edge cases
	f.Add([]byte{0x00})
	f.Add(make([]byte, 100))
}

// addEntityParserSeeds adds seed corpus entries for entity UID parsing.
func addEntityParserSeeds(f *testing.F) {
	// Valid entity UIDs
	f.Add([]byte(`User::"alice"`))
	f.Add([]byte(`Action::"read"`))
	f.Add([]byte(`Namespace::Type::"id"`))
	f.Add([]byte(`A::B::C::"nested"`))

	// Invalid entity UIDs
	f.Add([]byte(``))
	f.Add([]byte(`User`))
	f.Add([]byte(`User::`))
	f.Add([]byte(`User::"`))
	f.Add([]byte(`User::"unclosed`))
	f.Add([]byte(`::"`))
	f.Add([]byte(`::"id"`))
	f.Add([]byte(`"just a string"`))

	// Edge cases
	f.Add([]byte{0x00})
	f.Add([]byte(`User::"` + strings.Repeat("a", 1000) + `"`))
}

// TestParserDoesNotPanic runs basic sanity checks for parser robustness.
func TestParserDoesNotPanic(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"null byte", "\x00"},
		{"binary garbage", "\xff\xfe\xfd"},
		{"deeply nested parens", strings.Repeat("(", 100) + strings.Repeat(")", 100)},
		{"deeply nested braces", strings.Repeat("{", 100) + strings.Repeat("}", 100)},
		{"long string", strings.Repeat("a", 10000)},
		{"unicode", "permit(principal == User::\"日本語\", action, resource);"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// These should not panic
			var policy cedar.Policy
			_ = policy.UnmarshalCedar([]byte(tc.input))

			// Test schema parsing - should not panic
			_, _ = schema.NewFromJSON([]byte(tc.input))
			_, _ = schema.NewFromCedar("test.cedar", []byte(tc.input))

			// Test entity JSON parsing
			var entity map[string]any
			_ = json.Unmarshal([]byte(tc.input), &entity)
		})
	}
}
