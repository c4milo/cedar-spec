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

package comparison

import (
	"testing"
)

func TestCompareValidation_BothValid(t *testing.T) {
	goResult := &ValidationResult{Valid: true}
	leanResult := &ValidationResult{Valid: true}

	config := DefaultConfig()
	diffs := CompareValidation(goResult, leanResult, config)

	if len(diffs) != 0 {
		t.Errorf("Expected no differences, got %d: %v", len(diffs), diffs)
	}
}

func TestCompareValidation_BothInvalid(t *testing.T) {
	goResult := &ValidationResult{Valid: false, Errors: []string{"error1"}}
	leanResult := &ValidationResult{Valid: false, Errors: []string{"error2"}}

	config := DefaultConfig()
	diffs := CompareValidation(goResult, leanResult, config)

	// Default config uses AgreeOnValid, so both invalid should match
	if len(diffs) != 0 {
		t.Errorf("Expected no differences with AgreeOnValid, got %d: %v", len(diffs), diffs)
	}
}

func TestCompareValidation_GoValidLeanInvalid(t *testing.T) {
	goResult := &ValidationResult{Valid: true}
	leanResult := &ValidationResult{Valid: false, Errors: []string{"type error"}}

	config := DefaultConfig()
	diffs := CompareValidation(goResult, leanResult, config)

	// Type soundness: if Go says valid, Lean should also say valid
	if len(diffs) == 0 {
		t.Error("Expected type soundness violation")
	}
}

func TestCompareValidation_GoInvalidLeanValid(t *testing.T) {
	goResult := &ValidationResult{Valid: false, Errors: []string{"go error"}}
	leanResult := &ValidationResult{Valid: true}

	config := DefaultConfig()
	diffs := CompareValidation(goResult, leanResult, config)

	// With AgreeOnValid, Go invalid + Lean valid is allowed (Go may be stricter)
	if len(diffs) != 0 {
		t.Errorf("Expected no differences (Go stricter), got %d: %v", len(diffs), diffs)
	}
}

func TestCompareValidation_StrictMode(t *testing.T) {
	goResult := &ValidationResult{Valid: false}
	leanResult := &ValidationResult{Valid: true}

	config := StrictConfig()
	diffs := CompareValidation(goResult, leanResult, config)

	// Strict mode requires exact match
	if len(diffs) == 0 {
		t.Error("Expected differences in strict mode")
	}
}

func TestCheckTypeSoundness_Valid(t *testing.T) {
	goResult := &ValidationResult{Valid: true}
	leanResult := &ValidationResult{Valid: true}

	err := CheckTypeSoundness(goResult, leanResult)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestCheckTypeSoundness_Violation(t *testing.T) {
	goResult := &ValidationResult{Valid: true}
	leanResult := &ValidationResult{Valid: false}

	err := CheckTypeSoundness(goResult, leanResult)
	if err == nil {
		t.Error("Expected type soundness error")
	}
}

func TestCheckTypeSoundness_GoStricter(t *testing.T) {
	goResult := &ValidationResult{Valid: false}
	leanResult := &ValidationResult{Valid: true}

	err := CheckTypeSoundness(goResult, leanResult)
	// Go being stricter is not a type soundness violation
	if err != nil {
		t.Errorf("Expected no error (Go stricter is ok), got %v", err)
	}
}

func TestFormatValidationDifferences(t *testing.T) {
	diffs := []ValidationDifference{
		{Field: "valid", Description: "validity mismatch"},
	}

	result := FormatValidationDifferences(diffs)
	if result == "no differences" {
		t.Error("Expected formatted differences")
	}

	result = FormatValidationDifferences(nil)
	if result != "no differences" {
		t.Errorf("Expected 'no differences', got %q", result)
	}
}
