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
	"fmt"
	"strings"
)

// ValidationResult represents a validation outcome from either implementation.
type ValidationResult struct {
	// Valid is true if validation passed
	Valid bool

	// Errors contains validation error messages (if any)
	Errors []string
}

// ValidationDifference describes a difference in validation results.
type ValidationDifference struct {
	Field       string
	GoValue     any
	LeanValue   any
	Description string
}

// CompareValidation compares validation results from cedar-go and Lean.
// Returns nil if the results are equivalent according to the config,
// or a list of differences otherwise.
func CompareValidation(goResult, leanResult *ValidationResult, config ComparisonConfig) []ValidationDifference {
	var diffs []ValidationDifference

	switch config.ValidationMode {
	case ValidationComparisonModeAgreeOnValid:
		// Type soundness: if cedar-go says valid, Lean must also say valid
		// Exception: Known Lean strictness cases (impossiblePolicy, unknownEntity) are skipped
		if goResult.Valid && !leanResult.Valid && !isKnownLeanStrictnessError(leanResult) {
			diffs = append(diffs, ValidationDifference{
				Field:       "valid",
				GoValue:     true,
				LeanValue:   false,
				Description: "cedar-go validated but Lean rejected (type soundness violation)",
			})
		}
		// Note: It's acceptable for Lean to be stricter than cedar-go,
		// so we don't flag when go=invalid, lean=valid

	case ValidationComparisonModeAgreeOnAll:
		// Both must agree completely, except for known Lean strictness cases
		if goResult.Valid != leanResult.Valid {
			// Skip known Lean strictness cases (Lean being stricter than cedar-go/cedar-rust)
			if goResult.Valid && !leanResult.Valid && isKnownLeanStrictnessError(leanResult) {
				// Lean is stricter - this is expected, not a divergence
				break
			}
			diffs = append(diffs, ValidationDifference{
				Field:       "valid",
				GoValue:     goResult.Valid,
				LeanValue:   leanResult.Valid,
				Description: fmt.Sprintf("validation outcome differs: go=%v lean=%v", goResult.Valid, leanResult.Valid),
			})
		}
	}

	return diffs
}

// FormatValidationDifferences formats validation differences for display.
func FormatValidationDifferences(diffs []ValidationDifference) string {
	if len(diffs) == 0 {
		return "no differences"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Found %d validation difference(s):\n", len(diffs)))
	for i, diff := range diffs {
		sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, diff.Description))
		if diff.GoValue != nil {
			sb.WriteString(fmt.Sprintf("      Go value: %v\n", diff.GoValue))
		}
		if diff.LeanValue != nil {
			sb.WriteString(fmt.Sprintf("      Lean value: %v\n", diff.LeanValue))
		}
	}
	return sb.String()
}

// knownLeanStrictnessErrors contains error patterns where Lean's validator is
// intentionally stricter than cedar-go/cedar-rust. These are not type soundness
// violations but rather Lean-specific analyses that the production implementations
// don't perform.
var knownLeanStrictnessErrors = []string{
	// impossiblePolicy: Lean performs satisfiability analysis to detect policies
	// whose scope can never be satisfied (e.g., principal constraints that exclude
	// all possible types for the action). This is a semantic analysis, not a type check.
	"impossiblePolicy",

	// unknownEntity: Lean strictly validates that all entity types referenced in
	// action appliesTo constraints exist in the schema. Cedar-go/cedar-rust are
	// more permissive about undefined entity type references.
	"unknownEntity",
}

// isKnownLeanStrictnessError checks if Lean's errors are all known cases where
// Lean is intentionally stricter than cedar-go/cedar-rust.
func isKnownLeanStrictnessError(leanResult *ValidationResult) bool {
	if leanResult.Valid || len(leanResult.Errors) == 0 {
		return false
	}
	for _, err := range leanResult.Errors {
		isKnown := false
		for _, pattern := range knownLeanStrictnessErrors {
			if strings.Contains(err, pattern) {
				isKnown = true
				break
			}
		}
		if !isKnown {
			return false
		}
	}
	return true
}

// CheckTypeSoundness is a convenience function that checks the type soundness
// property: if cedar-go validates a policy set, Lean must also validate it.
//
// Note: Known Lean strictness cases (impossiblePolicy, unknownEntity) are
// excluded from this check. These represent cases where Lean's formal specification
// is intentionally stricter than the production cedar-go/cedar-rust implementations,
// not bugs in the DRT conversion code.
func CheckTypeSoundness(goResult, leanResult *ValidationResult) error {
	if goResult.Valid && !leanResult.Valid {
		// Skip known Lean strictness cases (not true type soundness violations)
		if isKnownLeanStrictnessError(leanResult) {
			return nil
		}
		return fmt.Errorf("type soundness violation: cedar-go accepted but Lean rejected with errors: %v",
			leanResult.Errors)
	}
	return nil
}
