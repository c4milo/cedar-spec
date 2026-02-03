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
	"slices"
	"sort"
	"strings"
)

// AuthorizationResult represents an authorization decision from either implementation.
type AuthorizationResult struct {
	// Decision is "allow" or "deny"
	Decision string

	// DeterminingPolicies lists policy IDs that contributed to the decision
	DeterminingPolicies []string

	// ErroringPolicies lists policy IDs that encountered errors
	ErroringPolicies []string

	// Errors maps policy IDs to error messages (if available)
	Errors map[string]string
}

// AuthorizationDifference describes a difference in authorization results.
type AuthorizationDifference struct {
	Field       string
	GoValue     any
	LeanValue   any
	Description string
}

// CompareAuthorization compares authorization results from cedar-go and Lean.
// Returns nil if the results are equivalent according to the config,
// or a list of differences otherwise.
func CompareAuthorization(goResult, leanResult *AuthorizationResult, config ComparisonConfig) []AuthorizationDifference {
	var diffs []AuthorizationDifference

	diffs = append(diffs, compareDecision(goResult, leanResult, config)...)
	diffs = append(diffs, compareDeterminingPolicies(goResult, leanResult)...)
	diffs = append(diffs, compareErroringPolicies(goResult, leanResult, config)...)

	return diffs
}

// compareDecision compares the authorization decision.
func compareDecision(goResult, leanResult *AuthorizationResult, config ComparisonConfig) []AuthorizationDifference {
	goHasErrors := len(goResult.ErroringPolicies) > 0
	leanHasErrors := len(leanResult.ErroringPolicies) > 0

	if config.IgnoreDecisionOnError && (goHasErrors || leanHasErrors) {
		return nil
	}

	if goResult.Decision == leanResult.Decision {
		return nil
	}

	return []AuthorizationDifference{{
		Field:       "decision",
		GoValue:     goResult.Decision,
		LeanValue:   leanResult.Decision,
		Description: fmt.Sprintf("decision mismatch: go=%s lean=%s", goResult.Decision, leanResult.Decision),
	}}
}

// compareDeterminingPolicies compares the determining policies.
func compareDeterminingPolicies(goResult, leanResult *AuthorizationResult) []AuthorizationDifference {
	if compareStringSlices(goResult.DeterminingPolicies, leanResult.DeterminingPolicies) {
		return nil
	}

	return []AuthorizationDifference{{
		Field:       "determiningPolicies",
		GoValue:     goResult.DeterminingPolicies,
		LeanValue:   leanResult.DeterminingPolicies,
		Description: fmt.Sprintf("determining policies differ: go=%v lean=%v", goResult.DeterminingPolicies, leanResult.DeterminingPolicies),
	}}
}

// compareErroringPolicies compares the erroring policies based on config.
func compareErroringPolicies(goResult, leanResult *AuthorizationResult, config ComparisonConfig) []AuthorizationDifference {
	if config.ErrorMode == ErrorComparisonModeIgnore {
		return nil
	}

	var diffs []AuthorizationDifference

	if !compareStringSlices(goResult.ErroringPolicies, leanResult.ErroringPolicies) {
		diffs = append(diffs, AuthorizationDifference{
			Field:       "erroringPolicies",
			GoValue:     goResult.ErroringPolicies,
			LeanValue:   leanResult.ErroringPolicies,
			Description: fmt.Sprintf("erroring policies differ: go=%v lean=%v", goResult.ErroringPolicies, leanResult.ErroringPolicies),
		})
	}

	if config.ErrorMode == ErrorComparisonModeFull {
		diffs = append(diffs, compareErrorMessages(goResult.Errors, leanResult.Errors)...)
	}

	return diffs
}

// compareErrorMessages compares error messages for matching policies.
func compareErrorMessages(goErrors, leanErrors map[string]string) []AuthorizationDifference {
	var diffs []AuthorizationDifference

	for policyID, goErr := range goErrors {
		leanErr, ok := leanErrors[policyID]
		if !ok || goErr == leanErr {
			continue
		}

		diffs = append(diffs, AuthorizationDifference{
			Field:       fmt.Sprintf("errors[%s]", policyID),
			GoValue:     goErr,
			LeanValue:   leanErr,
			Description: fmt.Sprintf("error message differs for policy %s", policyID),
		})
	}

	return diffs
}

// compareStringSlices compares two string slices for equality (order-independent).
func compareStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	sortedA := slices.Clone(a)
	sortedB := slices.Clone(b)
	sort.Strings(sortedA)
	sort.Strings(sortedB)

	return slices.Equal(sortedA, sortedB)
}

// FormatDifferences formats a list of differences for display.
func FormatDifferences(diffs []AuthorizationDifference) string {
	if len(diffs) == 0 {
		return "no differences"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Found %d difference(s):\n", len(diffs)))
	for i, diff := range diffs {
		sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, diff.Description))
	}
	return sb.String()
}
