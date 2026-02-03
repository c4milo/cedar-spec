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

/*
Package comparison provides utilities for comparing authorization and
validation results between the cedar-go implementation and the Lean
formalization of Cedar.

# Overview

Differential Randomized Testing (DRT) requires comparing outputs from two
implementations. This package provides structured comparison with configurable
strictness levels to handle known differences between implementations while
still catching real bugs.

# Comparison Modes

The package supports different comparison modes for flexibility:

Error Comparison Modes (for authorization):

  - [ErrorComparisonModeIgnore]: Skip error comparison entirely
  - [ErrorComparisonModePolicyIDs]: Compare which policies errored (default)
  - [ErrorComparisonModeFull]: Compare error messages exactly

Validation Comparison Modes:

  - [ValidationComparisonModeAgreeOnValid]: Type soundness check (default)
  - [ValidationComparisonModeAgreeOnAll]: Require exact agreement

# Configuration

Use [ComparisonConfig] to control comparison behavior:

	// Default: reasonable settings for Lean comparison
	config := comparison.DefaultConfig()

	// Strict: require exact agreement on everything
	config := comparison.StrictConfig()

	// Lenient: for initial testing or known differences
	config := comparison.LenientConfig()

	// Custom configuration
	config := comparison.ComparisonConfig{
	    ErrorMode:             comparison.ErrorComparisonModePolicyIDs,
	    ValidationMode:        comparison.ValidationComparisonModeAgreeOnValid,
	    IgnoreDecisionOnError: false,
	}

# Authorization Comparison

Compare authorization results using [CompareAuthorization]:

	goResult := &comparison.AuthorizationResult{
	    Decision:            "allow",
	    DeterminingPolicies: []string{"policy0"},
	    ErroringPolicies:    nil,
	}

	leanResult := &comparison.AuthorizationResult{
	    Decision:            "allow",
	    DeterminingPolicies: []string{"policy0"},
	    ErroringPolicies:    nil,
	}

	diffs := comparison.CompareAuthorization(goResult, leanResult, config)
	if len(diffs) > 0 {
	    fmt.Println(comparison.FormatDifferences(diffs))
	}

The comparison checks:
  - Decision (allow/deny)
  - Determining policies (which policies contributed to the decision)
  - Erroring policies (based on configured error mode)

# Validation Comparison

Compare validation results using [CompareValidation]:

	goResult := &comparison.ValidationResult{
	    Valid:  true,
	    Errors: nil,
	}

	leanResult := &comparison.ValidationResult{
	    Valid:  true,
	    Errors: nil,
	}

	diffs := comparison.CompareValidation(goResult, leanResult, config)

The default mode ([ValidationComparisonModeAgreeOnValid]) implements
type soundness checking: if cedar-go validates a policy, Lean must also
validate it. This catches cases where cedar-go is too permissive.

# Type Soundness

The [CheckTypeSoundness] helper provides a quick type soundness check:

	err := comparison.CheckTypeSoundness(goResult, leanResult)
	if err != nil {
	    // cedar-go accepted something Lean rejected - potential bug!
	    log.Printf("Type soundness violation: %v", err)
	}

This is a critical property: the Lean formalization is the authoritative
specification, so if it rejects something that cedar-go accepts, there
may be a bug in cedar-go.

# Difference Reporting

When differences are found, they are returned as structured objects:

	type AuthorizationDifference struct {
	    Field       string      // "decision", "determiningPolicies", etc.
	    GoValue     any         // Value from cedar-go
	    LeanValue   any         // Value from Lean
	    Description string      // Human-readable description
	}

Use [FormatDifferences] or [FormatValidationDifferences] to get
human-readable output for logging or test failures.

# Example: Fuzz Test Integration

	func FuzzAuthorization(f *testing.F) {
	    config := comparison.DefaultConfig()

	    f.Fuzz(func(t *testing.T, data []byte) {
	        // ... parse and run both implementations ...

	        goResult := &comparison.AuthorizationResult{...}
	        leanResult := &comparison.AuthorizationResult{...}

	        diffs := comparison.CompareAuthorization(goResult, leanResult, config)
	        if len(diffs) > 0 {
	            t.Errorf("Divergence: %s", comparison.FormatDifferences(diffs))
	        }
	    })
	}
*/
package comparison
