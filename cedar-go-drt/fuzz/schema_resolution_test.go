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
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
	"github.com/cedar-policy/cedar-go/x/exp/validator"

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/typegen"
)

type schemaResolutionContext struct {
	schemaFromJSON  schema.Schema
	schemaFromCedar schema.Schema
}

// FuzzSchemaResolution tests that schemas parsed from different formats
// (JSON vs Cedar) produce equivalent validation results.
//
// This is analogous to the Rust common-type-resolution target which tests
// that schemas with and without common types produce equivalent validator schemas.
func FuzzSchemaResolution(f *testing.F) {
	f.Add([]byte("schema-resolution-seed-1"))
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 128))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		input, ctx, ok := prepareSchemaResolutionInput(t, data, inputGen)
		if !ok {
			return
		}
		validatePoliciesWithBothSchemas(t, input, ctx)
	})
}

func prepareSchemaResolutionInput(t *testing.T, data []byte, inputGen *typegen.InputGenerator) (*typegen.TypeDirectedInput, *schemaResolutionContext, bool) {
	if len(data) < 32 {
		return nil, nil, false
	}

	input, err := inputGen.GenerateForAuthorization(data)
	if err != nil {
		return nil, nil, false
	}

	if input.Schema == nil || len(input.SchemaJSON) == 0 {
		return nil, nil, false
	}

	var ctx schemaResolutionContext

	if err := ctx.schemaFromJSON.UnmarshalJSON(input.SchemaJSON); err != nil {
		return nil, nil, false
	}

	cedarBytes, err := ctx.schemaFromJSON.MarshalCedar()
	if err != nil {
		return nil, nil, false
	}

	if err := ctx.schemaFromCedar.UnmarshalCedar(cedarBytes); err != nil {
		t.Errorf("Failed to parse schema from Cedar text: %v\nCedar: %s", err, string(cedarBytes))
		return nil, nil, false
	}

	return input, &ctx, true
}

func validatePoliciesWithBothSchemas(t *testing.T, input *typegen.TypeDirectedInput, ctx *schemaResolutionContext) {
	for _, policy := range input.Policies.All() {
		comparePolicyValidation(t, policy, ctx)
	}
}

func comparePolicyValidation(t *testing.T, policy *cedar.Policy, ctx *schemaResolutionContext) {
	singlePolicy := cedar.NewPolicySet()
	singlePolicy.Add("test", policy)

	diagJSON := validator.ValidatePolicies(&ctx.schemaFromJSON, singlePolicy)
	diagCedar := validator.ValidatePolicies(&ctx.schemaFromCedar, singlePolicy)

	jsonPassed := len(diagJSON.Errors) == 0
	cedarPassed := len(diagCedar.Errors) == 0

	if jsonPassed != cedarPassed {
		t.Errorf("Schema resolution inconsistency!\n"+
			"JSON schema validation passed: %v (errors: %d)\n"+
			"Cedar schema validation passed: %v (errors: %d)\n"+
			"Policy: %s",
			jsonPassed, len(diagJSON.Errors),
			cedarPassed, len(diagCedar.Errors),
			string(policy.MarshalCedar()))
	}
}

// FuzzSchemaEquivalence tests that roundtripping a schema through different
// formats produces equivalent schemas.
func FuzzSchemaEquivalence(f *testing.F) {
	f.Add([]byte("schema-equiv-seed-1"))
	f.Add(make([]byte, 64))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		testSchemaEquivalence(t, data, inputGen)
	})
}

func testSchemaEquivalence(t *testing.T, data []byte, inputGen *typegen.InputGenerator) {
	if len(data) < 32 {
		return
	}

	input, err := inputGen.GenerateForAuthorization(data)
	if err != nil || input.Schema == nil || len(input.SchemaJSON) == 0 {
		return
	}

	schemaFromJSON, schemaViaCedar, ok := parseSchemasBothWays(input.SchemaJSON)
	if !ok {
		return
	}

	compareSchemaJSON(t, schemaFromJSON, schemaViaCedar)
}

func parseSchemasBothWays(schemaJSON []byte) (*schema.Schema, *schema.Schema, bool) {
	var schemaFromJSON schema.Schema
	if err := schemaFromJSON.UnmarshalJSON(schemaJSON); err != nil {
		return nil, nil, false
	}

	cedarBytes, err := schemaFromJSON.MarshalCedar()
	if err != nil {
		return nil, nil, false
	}

	var schemaViaCedar schema.Schema
	if err := schemaViaCedar.UnmarshalCedar(cedarBytes); err != nil {
		return nil, nil, false
	}

	return &schemaFromJSON, &schemaViaCedar, true
}

func compareSchemaJSON(t *testing.T, s1, s2 *schema.Schema) {
	json1, err1 := s1.MarshalJSON()
	json2, err2 := s2.MarshalJSON()

	if err1 != nil || err2 != nil {
		return
	}

	norm1 := normalizeJSON(json1)
	norm2 := normalizeJSON(json2)

	if string(norm1) != string(norm2) {
		t.Errorf("Schema equivalence violation!\n"+
			"Original JSON: %s\n"+
			"Via Cedar: %s",
			string(norm1), string(norm2))
	}
}

func normalizeJSON(data []byte) []byte {
	var m map[string]any
	_ = json.Unmarshal(data, &m)
	norm, _ := json.Marshal(m)
	return norm
}

type schemaResolutionTestCase struct {
	name        string
	schemaCedar string
	policy      string
	expectPass  bool
}

// TestSchemaResolutionBasic tests basic schema resolution scenarios.
func TestSchemaResolutionBasic(t *testing.T) {
	tests := getSchemaResolutionTestCases()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runSchemaResolutionTestCase(t, tc)
		})
	}
}

func getSchemaResolutionTestCases() []schemaResolutionTestCase {
	return []schemaResolutionTestCase{
		{
			name: "simple entity type",
			schemaCedar: `
				entity User;
				entity Doc;
				action view appliesTo { principal: User, resource: Doc };
			`,
			policy:     `permit(principal == User::"alice", action == Action::"view", resource);`,
			expectPass: true,
		},
		{
			name: "entity with attributes",
			schemaCedar: `
				entity User { name: String, age: Long };
				entity Doc;
				action view appliesTo { principal: User, resource: Doc };
			`,
			policy:     `permit(principal, action, resource) when { principal.name == "alice" };`,
			expectPass: true,
		},
		{
			name: "entity hierarchy",
			schemaCedar: `
				entity Group;
				entity User in [Group];
				entity Doc;
				action view appliesTo { principal: User, resource: Doc };
			`,
			policy:     `permit(principal, action, resource) when { principal in Group::"admins" };`,
			expectPass: true,
		},
	}
}

func runSchemaResolutionTestCase(t *testing.T, tc schemaResolutionTestCase) {
	schemaFromCedar, schemaFromJSON := parseTestCaseSchemas(t, tc.schemaCedar)
	policies := parseTestCasePolicy(t, tc.policy)
	validateAndCompareSchemas(t, tc, schemaFromCedar, schemaFromJSON, policies)
}

func parseTestCaseSchemas(t *testing.T, schemaCedar string) (*schema.Schema, *schema.Schema) {
	var schemaFromCedar schema.Schema
	if err := schemaFromCedar.UnmarshalCedar([]byte(schemaCedar)); err != nil {
		t.Fatalf("Failed to parse Cedar schema: %v", err)
	}

	jsonBytes, err := schemaFromCedar.MarshalJSON()
	if err != nil {
		t.Fatalf("Failed to marshal schema to JSON: %v", err)
	}

	var schemaFromJSON schema.Schema
	if err := schemaFromJSON.UnmarshalJSON(jsonBytes); err != nil {
		t.Fatalf("Failed to parse JSON schema: %v", err)
	}

	return &schemaFromCedar, &schemaFromJSON
}

func parseTestCasePolicy(t *testing.T, policy string) *cedar.PolicySet {
	policies, err := cedar.NewPolicySetFromBytes("test.cedar", []byte(policy))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	return policies
}

func validateAndCompareSchemas(t *testing.T, tc schemaResolutionTestCase, schemaFromCedar, schemaFromJSON *schema.Schema, policies *cedar.PolicySet) {
	diagCedar := validator.ValidatePolicies(schemaFromCedar, policies)
	diagJSON := validator.ValidatePolicies(schemaFromJSON, policies)

	cedarPassed := len(diagCedar.Errors) == 0
	jsonPassed := len(diagJSON.Errors) == 0

	if cedarPassed != jsonPassed {
		t.Errorf("Validation results differ:\nCedar schema: %v\nJSON schema: %v",
			cedarPassed, jsonPassed)
	}

	if cedarPassed != tc.expectPass {
		t.Errorf("Expected validation to pass=%v, got %v (errors: %v)",
			tc.expectPass, cedarPassed, diagCedar.Errors)
	}
}

// TestSchemaJSONRoundtrip tests that schema JSON roundtrips correctly.
func TestSchemaJSONRoundtrip(t *testing.T) {
	schemaCedar := `
		entity User { name: String };
		entity Doc { owner: User };
		action view appliesTo { principal: User, resource: Doc };
	`

	var s schema.Schema
	if err := s.UnmarshalCedar([]byte(schemaCedar)); err != nil {
		t.Fatalf("Failed to parse Cedar schema: %v", err)
	}

	// Cedar -> JSON
	jsonBytes, err := s.MarshalJSON()
	if err != nil {
		t.Fatalf("Failed to marshal to JSON: %v", err)
	}

	// Verify it's valid JSON
	var jsonMap map[string]any
	if err := json.Unmarshal(jsonBytes, &jsonMap); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	// JSON -> Schema
	var roundtripped schema.Schema
	if err := roundtripped.UnmarshalJSON(jsonBytes); err != nil {
		t.Fatalf("Failed to parse JSON schema: %v", err)
	}

	// Verify roundtripped schema works
	policy := `permit(principal, action, resource) when { principal.name == "alice" };`
	policies, _ := cedar.NewPolicySetFromBytes("test.cedar", []byte(policy))

	diag := validator.ValidatePolicies(&roundtripped, policies)
	if len(diag.Errors) > 0 {
		t.Errorf("Roundtripped schema validation failed: %v", diag.Errors)
	}
}
