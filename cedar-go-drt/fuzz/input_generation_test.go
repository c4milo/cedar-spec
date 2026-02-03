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
	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
	"github.com/cedar-policy/cedar-go/x/exp/validator"

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/typegen"
)

// FuzzInputGeneration tests that our type-directed input generator produces
// valid inputs that can be successfully authorized.
func FuzzInputGeneration(f *testing.F) {
	f.Add([]byte("input-gen-seed-1"))
	f.Add([]byte("input-gen-seed-2"))
	f.Add(make([]byte, 32))
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 128))
	f.Add(make([]byte, 256))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		input, ok := prepareInputGenerationTest(data, inputGen)
		if !ok {
			return
		}

		validateGeneratedPolicies(t, input)
		validateGeneratedEntities(t, input)
		validateGeneratedRequests(t, input)
		validateSchemaConformance(t, input)
	})
}

func prepareInputGenerationTest(data []byte, inputGen *typegen.InputGenerator) (*typegen.TypeDirectedInput, bool) {
	if len(data) < 16 {
		return nil, false
	}

	input, err := inputGen.GenerateForAuthorization(data)
	if err != nil {
		return nil, false
	}

	if input.Policies == nil {
		return nil, false
	}

	if countPolicies(input.Policies) == 0 {
		return nil, false
	}

	return input, true
}

func validateGeneratedPolicies(t *testing.T, input *typegen.TypeDirectedInput) {
	for _, policy := range input.Policies.All() {
		validateSinglePolicy(t, policy)
	}
}

func validateSinglePolicy(t *testing.T, policy *cedar.Policy) {
	cedarBytes := policy.MarshalCedar()
	if len(cedarBytes) == 0 {
		t.Error("Policy serialized to empty string")
		return
	}

	var reparsed cedar.Policy
	if err := reparsed.UnmarshalCedar(cedarBytes); err != nil {
		t.Errorf("Generated policy cannot be re-parsed: %v\nCedar: %s", err, string(cedarBytes))
	}
}

func validateGeneratedEntities(t *testing.T, input *typegen.TypeDirectedInput) {
	for uid, entity := range input.Entities.Entities {
		validateSingleEntity(t, input, uid, entity)
	}
}

func validateSingleEntity(t *testing.T, input *typegen.TypeDirectedInput, uid types.EntityUID, entity types.Entity) {
	if entity.UID != uid {
		t.Errorf("Entity UID mismatch: map key=%v, entity UID=%v", uid, entity.UID)
	}

	for parent := range entity.Parents.All() {
		if _, exists := input.Entities.Entities[parent]; !exists {
			t.Logf("Entity %v references non-existent parent %v", uid, parent)
		}
	}
}

func validateGeneratedRequests(t *testing.T, input *typegen.TypeDirectedInput) {
	for i, req := range input.Requests {
		validateSingleRequest(t, input, i, req)
	}
}

func validateSingleRequest(t *testing.T, input *typegen.TypeDirectedInput, idx int, req cedar.Request) {
	decision, diag := cedar.Authorize(input.Policies, input.Entities.Entities, req)

	if decision != types.Allow && decision != types.Deny {
		t.Errorf("Request %d: invalid decision %v", idx, decision)
	}

	for _, diagErr := range diag.Errors {
		t.Logf("Request %d: diagnostic error: %s", idx, diagErr.Message)
	}
}

func validateSchemaConformance(t *testing.T, input *typegen.TypeDirectedInput) {
	if input.Schema == nil || len(input.SchemaJSON) == 0 {
		return
	}

	var s schema.Schema
	if err := s.UnmarshalJSON(input.SchemaJSON); err != nil {
		return
	}

	diag := validator.ValidatePolicies(&s, input.Policies)
	if len(diag.Errors) > 0 {
		t.Logf("Schema validation produced %d errors", len(diag.Errors))
	}
}

// FuzzInputGenerationDiversity tests that the input generator produces diverse inputs.
func FuzzInputGenerationDiversity(f *testing.F) {
	f.Add([]byte("diversity-seed-1"))
	f.Add(make([]byte, 64))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 32 {
			return
		}

		input, err := inputGen.GenerateForAuthorization(data)
		if err != nil {
			return
		}

		metrics := collectDiversityMetrics(input)
		t.Logf("Input diversity: effects=%v, hasConditions=%v, hasConstraints=%v, policies=%d, entities=%d, requests=%d",
			metrics.effectCount, metrics.hasConditions, metrics.hasConstraints,
			countPolicies(input.Policies), len(input.Entities.Entities), len(input.Requests))
	})
}

type diversityMetrics struct {
	effectCount   int
	hasConditions bool
	hasConstraints bool
}

func collectDiversityMetrics(input *typegen.TypeDirectedInput) diversityMetrics {
	effects := make(map[cedar.Effect]bool)
	var hasConditions, hasConstraints bool

	for _, policy := range input.Policies.All() {
		effects[policy.Effect()] = true
		cedarStr := string(policy.MarshalCedar())

		if contains(cedarStr, "when") || contains(cedarStr, "unless") {
			hasConditions = true
		}
		if contains(cedarStr, "==") || contains(cedarStr, "in") {
			hasConstraints = true
		}
	}

	return diversityMetrics{
		effectCount:    len(effects),
		hasConditions:  hasConditions,
		hasConstraints: hasConstraints,
	}
}

// FuzzInputGenerationStress tests that the input generator handles various data sizes.
func FuzzInputGenerationStress(f *testing.F) {
	for size := 16; size <= 512; size *= 2 {
		f.Add(make([]byte, size))
	}

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 16 {
			return
		}

		input, err := inputGen.GenerateForAuthorization(data)
		if err != nil {
			return
		}

		for _, req := range input.Requests {
			cedar.Authorize(input.Policies, input.Entities.Entities, req)
		}
	})
}

// TestInputGenerationBasic tests basic input generation.
func TestInputGenerationBasic(t *testing.T) {
	inputGen := typegen.TypeDirectedInputGenerator()

	seeds := [][]byte{
		[]byte("test-seed-1"),
		[]byte("test-seed-2"),
		make([]byte, 64),
		make([]byte, 128),
	}

	for i, seed := range seeds {
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			runBasicInputGenerationTest(t, inputGen, seed)
		})
	}
}

func runBasicInputGenerationTest(t *testing.T, inputGen *typegen.InputGenerator, seed []byte) {
	input, err := inputGen.GenerateForAuthorization(seed)
	if err != nil {
		t.Skipf("Generation failed (acceptable): %v", err)
	}

	verifyBasicStructure(t, input)
	logRequestDecisions(t, input)
}

func verifyBasicStructure(t *testing.T, input *typegen.TypeDirectedInput) {
	if input.Policies == nil {
		t.Error("Policies is nil")
	}
	if input.Entities.Entities == nil {
		t.Error("Entities is nil")
	}
	if len(input.Requests) == 0 {
		t.Log("No requests generated")
	}
}

func logRequestDecisions(t *testing.T, input *typegen.TypeDirectedInput) {
	for j, req := range input.Requests {
		decision, _ := cedar.Authorize(input.Policies, input.Entities.Entities, req)
		t.Logf("Request %d: decision=%v", j, decision)
	}
}

// TestInputGenerationReproducibility tests that the same seed produces the same output.
func TestInputGenerationReproducibility(t *testing.T) {
	inputGen := typegen.TypeDirectedInputGenerator()
	seed := []byte("reproducibility-test-seed")

	input1, err1 := inputGen.GenerateForAuthorization(seed)
	input2, err2 := inputGen.GenerateForAuthorization(seed)

	if err1 != nil || err2 != nil {
		t.Skip("Generation failed")
	}

	count1, count2 := countPolicies(input1.Policies), countPolicies(input2.Policies)
	if count1 != count2 {
		t.Errorf("Policy count differs: %d vs %d", count1, count2)
	}

	if len(input1.Entities.Entities) != len(input2.Entities.Entities) {
		t.Errorf("Entity count differs: %d vs %d",
			len(input1.Entities.Entities), len(input2.Entities.Entities))
	}

	if len(input1.Requests) != len(input2.Requests) {
		t.Errorf("Request count differs: %d vs %d",
			len(input1.Requests), len(input2.Requests))
	}
}

// Helper functions

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func countPolicies(ps *cedar.PolicySet) int {
	count := 0
	for range ps.All() {
		count++
	}
	return count
}
