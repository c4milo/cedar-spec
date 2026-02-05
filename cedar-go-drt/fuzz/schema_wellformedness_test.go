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
	"strings"
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
	"github.com/cedar-policy/cedar-go/x/exp/validator"

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/comparison"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/lean"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/proto"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/typegen"
)

// SchemaWellFormednessInput represents test input for schema well-formedness testing.
type SchemaWellFormednessInput struct {
	Schema string `json:"schema"`
}

// FuzzSchemaWellFormedness tests schema well-formedness validation against Lean.
//
// This test generates schemas (both valid and potentially malformed) and validates
// a trivial policy against them. Since schema well-formedness is checked during
// policy validation in both implementations, this indirectly tests that:
//
//  1. Entity types referenced in policies exist in the schema
//  2. Action definitions have valid appliesTo configurations
//  3. Attribute types are well-formed
//  4. Entity hierarchies are valid (no undefined parent types)
//
// The test compares cedar-go's validation result against Lean's validation result
// to ensure both implementations agree on what constitutes a well-formed schema.
func FuzzSchemaWellFormedness(f *testing.F) {
	addSchemaWellFormednessSeeds(f)

	config := comparison.DefaultConfig()
	// Use strict comparison - both should agree on schema validity
	config.ValidationMode = comparison.ValidationComparisonModeAgreeOnAll

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		var input SchemaWellFormednessInput
		if err := json.Unmarshal(data, &input); err != nil {
			return // Invalid JSON, skip
		}

		// Skip schemas with malformed field casing - Go's JSON decoder is case-insensitive
		// while Lean's is case-sensitive, causing divergence on malformed input
		if hasMalformedFieldCasing(input.Schema) {
			return
		}

		s, err := schema.NewFromJSON([]byte(input.Schema))
		if err != nil {
			return // Invalid schema JSON, skip
		}

		// Create a trivial policy that should validate if schema is well-formed
		trivialPolicy := "permit(principal, action, resource);"
		policies := cedar.NewPolicySet()
		var policy cedar.Policy
		if err := policy.UnmarshalCedar([]byte(trivialPolicy)); err != nil {
			t.Fatalf("Failed to parse trivial policy: %v", err)
		}
		policies.Add("policy0", &policy)

		// Run cedar-go validation
		goResult := runSchemaValidation(t, s, policies)

		// Run Lean validation
		leanResult := runLeanSchemaValidation(t, s, policies)
		if leanResult == nil {
			return // Lean error, skip
		}

		// Compare results
		diffs := comparison.CompareValidation(goResult, leanResult, config)
		if len(diffs) > 0 {
			t.Errorf("Schema well-formedness divergence:\n%s\nSchema: %s",
				comparison.FormatValidationDifferences(diffs), input.Schema)
		}
	})
}

// FuzzSchemaWellFormednessTypeDirected uses type-directed generation for better coverage.
func FuzzSchemaWellFormednessTypeDirected(f *testing.F) {
	inputGen := typegen.DefaultInputGenerator()

	f.Add([]byte("schema-wellformedness-seed-1"))
	f.Add([]byte("schema-wellformedness-seed-2"))
	f.Add(make([]byte, 64))

	config := comparison.DefaultConfig()
	config.ValidationMode = comparison.ValidationComparisonModeAgreeOnAll

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		if len(data) < 16 {
			return
		}

		input, err := inputGen.Generate(data)
		if err != nil || input.Schema == nil || input.SchemaJSON == nil {
			return
		}

		// Parse the generated schema JSON into schema.Schema
		s, parseErr := schema.NewFromJSON(input.SchemaJSON)
		if parseErr != nil {
			return // Schema didn't parse, skip
		}

		// Create trivial policy
		trivialPolicy := "permit(principal, action, resource);"
		policies := cedar.NewPolicySet()
		var policy cedar.Policy
		if err := policy.UnmarshalCedar([]byte(trivialPolicy)); err != nil {
			return
		}
		policies.Add("policy0", &policy)

		// Run cedar-go validation
		goResult := runSchemaValidation(t, s, policies)

		// Run Lean validation
		leanResult := runLeanSchemaValidation(t, s, policies)
		if leanResult == nil {
			return
		}

		// Compare results
		diffs := comparison.CompareValidation(goResult, leanResult, config)
		if len(diffs) > 0 {
			t.Errorf("Schema well-formedness divergence (type-directed):\n%s\nSchema: %s",
				comparison.FormatValidationDifferences(diffs), string(input.SchemaJSON))
		}
	})
}

// runSchemaValidation runs cedar-go validation and returns the result.
// Uses WithAllowUnknownEntityTypes() to match Lean's behavior where unknown
// entity types in principalTypes/resourceTypes are accepted at schema level.
func runSchemaValidation(t *testing.T, s *schema.Schema, policies *cedar.PolicySet) *comparison.ValidationResult {
	t.Helper()

	// Use WithAllowUnknownEntityTypes to match Lean's behavior
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

// runLeanSchemaValidation runs Lean validation and returns the result.
func runLeanSchemaValidation(t *testing.T, s *schema.Schema, policies *cedar.PolicySet) *comparison.ValidationResult {
	t.Helper()

	valReq := proto.ValidationFromCedar(policies, s)
	protoBytes, err := valReq.ToProtobuf()
	if err != nil {
		t.Logf("Failed to convert to protobuf: %v", err)
		return nil
	}

	var result *comparison.ValidationResult
	err = lean.WithLeanThread(func() error {
		leanResp, leanErr := lean.Validate(protoBytes)
		if leanErr != nil {
			return leanErr
		}
		result = &comparison.ValidationResult{
			Valid:  leanResp.Valid,
			Errors: []string{leanResp.Errors},
		}
		return nil
	})

	if err != nil {
		t.Logf("Lean FFI error: %v", err)
		return nil
	}

	return result
}

// addSchemaWellFormednessSeeds adds seed corpus for schema well-formedness testing.
func addSchemaWellFormednessSeeds(f *testing.F) {
	// Valid well-formed schemas
	validSchemas := []string{
		// Minimal valid schema
		`{"": {"entityTypes": {"User": {}}, "actions": {"view": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["User"]}}}}}`,

		// Schema with entity hierarchy
		`{"": {"entityTypes": {"User": {}, "Admin": {"memberOfTypes": ["User"]}}, "actions": {"manage": {"appliesTo": {"principalTypes": ["Admin"], "resourceTypes": ["User"]}}}}}`,

		// Schema with attributes
		`{"": {"entityTypes": {"User": {"shape": {"type": "Record", "attributes": {"name": {"type": "String", "required": true}, "age": {"type": "Long", "required": false}}}}}, "actions": {"view": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["User"]}}}}}`,

		// Schema with nested record attributes
		`{"": {"entityTypes": {"User": {"shape": {"type": "Record", "attributes": {"profile": {"type": "Record", "attributes": {"email": {"type": "String"}}}}}}}, "actions": {"view": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["User"]}}}}}`,

		// Schema with set attributes
		`{"": {"entityTypes": {"User": {"shape": {"type": "Record", "attributes": {"roles": {"type": "Set", "element": {"type": "String"}}}}}}, "actions": {"view": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["User"]}}}}}`,

		// Schema with multiple namespaces
		`{"NS1": {"entityTypes": {"User": {}}, "actions": {}}, "NS2": {"entityTypes": {"Document": {}}, "actions": {"view": {"appliesTo": {"principalTypes": ["NS1::User"], "resourceTypes": ["Document"]}}}}}`,

		// Schema with entity references in attributes
		`{"": {"entityTypes": {"User": {}, "Document": {"shape": {"type": "Record", "attributes": {"owner": {"type": "Entity", "name": "User"}}}}}, "actions": {"view": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["Document"]}}}}}`,

		// Schema with action context
		`{"": {"entityTypes": {"User": {}, "Resource": {}}, "actions": {"view": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["Resource"], "context": {"type": "Record", "attributes": {"ip": {"type": "Extension", "name": "ipaddr"}}}}}}}}`,

		// Empty entity types (valid but edge case)
		`{"": {"entityTypes": {}, "actions": {}}}`,

		// Schema with common types
		`{"": {"commonTypes": {"Address": {"type": "Record", "attributes": {"street": {"type": "String"}}}}, "entityTypes": {"User": {"shape": {"type": "Record", "attributes": {"address": {"type": "Address"}}}}}, "actions": {"view": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["User"]}}}}}`,
	}

	// Potentially malformed schemas (may or may not be accepted)
	edgeCaseSchemas := []string{
		// Self-referential entity type (might be valid)
		`{"": {"entityTypes": {"User": {"memberOfTypes": ["User"]}}, "actions": {}}}`,

		// Action without appliesTo
		`{"": {"entityTypes": {"User": {}}, "actions": {"view": {}}}}`,

		// Reference to undefined entity type
		`{"": {"entityTypes": {"User": {}}, "actions": {"view": {"appliesTo": {"principalTypes": ["NonExistent"], "resourceTypes": ["User"]}}}}}`,

		// Empty principal/resource types
		`{"": {"entityTypes": {"User": {}}, "actions": {"view": {"appliesTo": {"principalTypes": [], "resourceTypes": []}}}}}`,

		// Deeply nested record type
		`{"": {"entityTypes": {"User": {"shape": {"type": "Record", "attributes": {"a": {"type": "Record", "attributes": {"b": {"type": "Record", "attributes": {"c": {"type": "String"}}}}}}}}}, "actions": {}}}`,

		// Extension type
		`{"": {"entityTypes": {"User": {"shape": {"type": "Record", "attributes": {"ip": {"type": "Extension", "name": "ipaddr"}}}}}, "actions": {"view": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["User"]}}}}}`,

		// Action with member of (action groups)
		`{"": {"entityTypes": {"User": {}}, "actions": {"read": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["User"]}}, "readWrite": {"memberOf": [{"id": "read"}], "appliesTo": {"principalTypes": ["User"], "resourceTypes": ["User"]}}}}}`,
	}

	for _, s := range validSchemas {
		input := SchemaWellFormednessInput{Schema: s}
		data, _ := json.Marshal(input)
		f.Add(data)
	}

	for _, s := range edgeCaseSchemas {
		input := SchemaWellFormednessInput{Schema: s}
		data, _ := json.Marshal(input)
		f.Add(data)
	}
}

// TestSchemaWellFormednessBasic tests basic schema well-formedness scenarios.
func TestSchemaWellFormednessBasic(t *testing.T) {
	tests := []struct {
		name        string
		schema      string
		expectValid bool
	}{
		{
			name:        "minimal valid schema",
			schema:      `{"": {"entityTypes": {"User": {}}, "actions": {"view": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["User"]}}}}}`,
			expectValid: true,
		},
		{
			name:        "empty schema",
			schema:      `{"": {"entityTypes": {}, "actions": {}}}`,
			expectValid: false, // Empty schema has no valid environments, so policies are "impossible"
		},
		{
			name:        "schema with entity hierarchy",
			schema:      `{"": {"entityTypes": {"User": {}, "Admin": {"memberOfTypes": ["User"]}}, "actions": {"view": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["User"]}}}}}`,
			expectValid: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := schema.NewFromJSON([]byte(tc.schema))
			if err != nil {
				if tc.expectValid {
					t.Errorf("Expected valid schema but got parse error: %v", err)
				}
				return
			}

			// If we expect it to be invalid but it parsed, check validation
			trivialPolicy := "permit(principal, action, resource);"
			policies := cedar.NewPolicySet()
			var policy cedar.Policy
			if err := policy.UnmarshalCedar([]byte(trivialPolicy)); err != nil {
				t.Fatalf("Failed to parse trivial policy: %v", err)
			}
			policies.Add("policy0", &policy)

			result := validator.ValidatePolicies(s, policies)
			if result.Valid != tc.expectValid {
				t.Errorf("Expected valid=%v, got valid=%v, errors=%v",
					tc.expectValid, result.Valid, result.Errors)
			}
		})
	}
}

// TestSchemaEntityTypeValidation tests entity type well-formedness properties.
func TestSchemaEntityTypeValidation(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	tests := []struct {
		name   string
		schema string
	}{
		{
			name:   "entity with attributes",
			schema: `{"": {"entityTypes": {"User": {"shape": {"type": "Record", "attributes": {"name": {"type": "String"}}}}}, "actions": {"view": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["User"]}}}}}`,
		},
		{
			name:   "entity with entity reference attribute",
			schema: `{"": {"entityTypes": {"User": {}, "Document": {"shape": {"type": "Record", "attributes": {"owner": {"type": "Entity", "name": "User"}}}}}, "actions": {"view": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["Document"]}}}}}`,
		},
		{
			name:   "entity hierarchy chain",
			schema: `{"": {"entityTypes": {"User": {}, "Admin": {"memberOfTypes": ["User"]}, "SuperAdmin": {"memberOfTypes": ["Admin"]}}, "actions": {"manage": {"appliesTo": {"principalTypes": ["SuperAdmin"], "resourceTypes": ["User"]}}}}}`,
		},
	}

	config := comparison.DefaultConfig()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := schema.NewFromJSON([]byte(tc.schema))
			if err != nil {
				t.Skipf("Schema parse failed: %v", err)
				return
			}

			trivialPolicy := "permit(principal, action, resource);"
			policies := cedar.NewPolicySet()
			var policy cedar.Policy
			if err := policy.UnmarshalCedar([]byte(trivialPolicy)); err != nil {
				t.Fatalf("Failed to parse policy: %v", err)
			}
			policies.Add("policy0", &policy)

			goResult := runSchemaValidation(t, s, policies)
			leanResult := runLeanSchemaValidation(t, s, policies)

			if leanResult == nil {
				t.Skip("Lean validation failed")
				return
			}

			diffs := comparison.CompareValidation(goResult, leanResult, config)
			if len(diffs) > 0 {
				t.Errorf("Divergence:\n%s", comparison.FormatValidationDifferences(diffs))
			}
		})
	}
}

// TestSchemaActionValidation tests action definition well-formedness.
func TestSchemaActionValidation(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	tests := []struct {
		name   string
		schema string
	}{
		{
			name:   "action with context",
			schema: `{"": {"entityTypes": {"User": {}, "Resource": {}}, "actions": {"view": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["Resource"], "context": {"type": "Record", "attributes": {"reason": {"type": "String"}}}}}}}}`,
		},
		{
			name:   "multiple actions",
			schema: `{"": {"entityTypes": {"User": {}, "Document": {}}, "actions": {"read": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["Document"]}}, "write": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["Document"]}}, "delete": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["Document"]}}}}}`,
		},
	}

	config := comparison.DefaultConfig()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := schema.NewFromJSON([]byte(tc.schema))
			if err != nil {
				t.Skipf("Schema parse failed: %v", err)
				return
			}

			trivialPolicy := "permit(principal, action, resource);"
			policies := cedar.NewPolicySet()
			var policy cedar.Policy
			if err := policy.UnmarshalCedar([]byte(trivialPolicy)); err != nil {
				t.Fatalf("Failed to parse policy: %v", err)
			}
			policies.Add("policy0", &policy)

			goResult := runSchemaValidation(t, s, policies)
			leanResult := runLeanSchemaValidation(t, s, policies)

			if leanResult == nil {
				t.Skip("Lean validation failed")
				return
			}

			diffs := comparison.CompareValidation(goResult, leanResult, config)
			if len(diffs) > 0 {
				t.Errorf("Divergence:\n%s", comparison.FormatValidationDifferences(diffs))
			}
		})
	}
}

// hasMalformedFieldCasing checks if the schema JSON contains field names with
// non-standard casing. Go's JSON decoder is case-insensitive while Lean/Rust
// are case-sensitive, causing divergence on malformed input.
func hasMalformedFieldCasing(schemaJSON string) bool {
	// Expected correct field names (case-sensitive)
	correctFields := map[string]bool{
		"entityTypes":    true,
		"actions":        true,
		"memberOfTypes":  true,
		"principalTypes": true,
		"resourceTypes":  true,
		"appliesTo":      true,
		"commonTypes":    true,
		"shape":          true,
		"attributes":     true,
		"type":           true,
		"required":       true,
		"element":        true,
		"name":           true,
		"context":        true,
		"memberOf":       true,
		"id":             true,
	}

	return checkFieldCasingRecursive([]byte(schemaJSON), correctFields)
}

// checkFieldCasingRecursive recursively checks if any JSON field has incorrect casing.
func checkFieldCasingRecursive(data []byte, correctFields map[string]bool) bool {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return false
	}

	for key, value := range raw {
		if hasIncorrectCasing(key, correctFields) {
			return true
		}
		if checkNestedValue(value, correctFields) {
			return true
		}
	}

	return false
}

// hasIncorrectCasing checks if a key has incorrect casing compared to known correct fields.
func hasIncorrectCasing(key string, correctFields map[string]bool) bool {
	keyLower := strings.ToLower(key)
	for correct := range correctFields {
		if strings.ToLower(correct) == keyLower && correct != key {
			return true
		}
	}
	return false
}

// checkNestedValue checks nested objects and arrays for incorrect field casing.
func checkNestedValue(value json.RawMessage, correctFields map[string]bool) bool {
	if len(value) == 0 {
		return false
	}
	if value[0] == '{' {
		return checkFieldCasingRecursive(value, correctFields)
	}
	if value[0] == '[' {
		return checkArrayItems(value, correctFields)
	}
	return false
}

// checkArrayItems checks array items for incorrect field casing.
func checkArrayItems(value json.RawMessage, correctFields map[string]bool) bool {
	var arr []json.RawMessage
	if err := json.Unmarshal(value, &arr); err != nil {
		return false
	}
	for _, item := range arr {
		if len(item) > 0 && item[0] == '{' {
			if checkFieldCasingRecursive(item, correctFields) {
				return true
			}
		}
	}
	return false
}
