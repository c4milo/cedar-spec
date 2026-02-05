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
	"runtime"
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
	"github.com/cedar-policy/cedar-go/x/exp/validator"

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/comparison"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/lean"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/proto"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/typegen"
)

// FuzzValidationTypeDirected is a type-directed fuzz target for validation.
// It generates well-typed schemas and policies for validation testing.
func FuzzValidationTypeDirected(f *testing.F) {
	f.Add([]byte("validation-seed"))
	f.Add([]byte("type-directed-validation"))
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 256))

	config := comparison.DefaultConfig()
	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 16 {
			return
		}

		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		input, err := inputGen.GenerateForValidation(data)
		if err != nil {
			return
		}

		s, schemaErr := schema.NewFromJSON(input.SchemaJSON)
		if schemaErr != nil {
			return
		}

		goResult := runTypeDirectedGoValidation(s, input.Policies)
		leanResult := buildTypeDirectedLeanResult(t, input)
		if leanResult == nil {
			return
		}

		reportTypeDirectedDiffs(t, goResult, leanResult, input, config)
	})
}

func runTypeDirectedGoValidation(s *schema.Schema, policies *cedar.PolicySet) *comparison.ValidationResult {
	goValidationResult := validator.ValidatePolicies(s, policies)
	result := &comparison.ValidationResult{Valid: goValidationResult.Valid}
	for _, verr := range goValidationResult.Errors {
		result.Errors = append(result.Errors, verr.Message)
	}
	return result
}

func buildTypeDirectedLeanResult(t *testing.T, input *typegen.TypeDirectedInput) *comparison.ValidationResult {
	leanResp := runTypeDirectedLeanValidation(t, input)
	if leanResp == nil {
		return nil
	}
	return &comparison.ValidationResult{Valid: leanResp.Valid, Errors: []string{leanResp.Errors}}
}

func reportTypeDirectedDiffs(t *testing.T, goResult, leanResult *comparison.ValidationResult, input *typegen.TypeDirectedInput, config comparison.ComparisonConfig) {
	t.Helper()
	diffs := comparison.CompareValidation(goResult, leanResult, config)
	if len(diffs) > 0 {
		policyStrings := marshalPoliciesForLog(input.Policies)
		t.Errorf("Type-directed validation divergence:\n%s\nSchema: %s\nPolicies: %v",
			comparison.FormatValidationDifferences(diffs), string(input.SchemaJSON), policyStrings)
	}
	if err := comparison.CheckTypeSoundness(goResult, leanResult); err != nil {
		policyStrings := marshalPoliciesForLog(input.Policies)
		t.Errorf("Type soundness violation: %v\nSchema: %s\nPolicies: %v", err, string(input.SchemaJSON), policyStrings)
	}
}

func marshalPoliciesForLog(policies *cedar.PolicySet) []string {
	var result []string
	for _, p := range policies.All() {
		result = append(result, string(p.MarshalCedar()))
	}
	return result
}

func runTypeDirectedLeanValidation(t *testing.T, input *typegen.TypeDirectedInput) *lean.ValidationResponse {
	t.Helper()

	// Parse schema for proto conversion
	s, err := schema.NewFromJSON(input.SchemaJSON)
	if err != nil {
		t.Logf("Failed to parse schema for Lean: %v", err)
		return nil
	}

	valReq := proto.ValidationFromCedar(input.Policies, s)
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
