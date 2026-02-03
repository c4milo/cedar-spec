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
	// Add seeds
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

		// Generate type-directed input
		input, err := inputGen.GenerateForValidation(data)
		if err != nil {
			return
		}

		// Parse the schema for cedar-go validator
		var s schema.Schema
		if err := s.UnmarshalJSON(input.SchemaJSON); err != nil {
			return // Schema parse error, skip
		}

		// Run cedar-go validation
		goValidationResult := validator.ValidatePolicies(&s, input.Policies)
		goResult := &comparison.ValidationResult{
			Valid: goValidationResult.Valid,
		}
		for _, verr := range goValidationResult.Errors {
			goResult.Errors = append(goResult.Errors, verr.Message)
		}

		// Run Lean validation
		leanResp := runTypeDirectedLeanValidation(t, input)
		if leanResp == nil {
			return
		}

		leanResult := &comparison.ValidationResult{
			Valid:  leanResp.Valid,
			Errors: []string{leanResp.Errors},
		}

		// Compare results
		diffs := comparison.CompareValidation(goResult, leanResult, config)
		if len(diffs) > 0 {
			t.Errorf("Type-directed validation divergence:\n%s\nSchema: %s",
				comparison.FormatValidationDifferences(diffs), string(input.SchemaJSON))
		}

		// Type soundness check
		if err := comparison.CheckTypeSoundness(goResult, leanResult); err != nil {
			t.Errorf("Type soundness violation: %v\nSchema: %s", err, string(input.SchemaJSON))
		}
	})
}

func runTypeDirectedLeanValidation(t *testing.T, input *typegen.TypeDirectedInput) *lean.ValidationResponse {
	t.Helper()

	// Parse schema for proto conversion
	var s schema.Schema
	if err := s.UnmarshalJSON(input.SchemaJSON); err != nil {
		t.Logf("Failed to parse schema for Lean: %v", err)
		return nil
	}

	valReq := proto.ValidationFromCedar(input.Policies, &s)
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
