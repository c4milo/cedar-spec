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

// Package comparison provides utilities for comparing results between
// cedar-go and the Lean formalization.
package comparison

// ErrorComparisonMode determines how errors are compared between implementations.
type ErrorComparisonMode int

const (
	// ErrorComparisonModeIgnore ignores all errors during comparison.
	// Use when error behavior is known to differ between implementations.
	ErrorComparisonModeIgnore ErrorComparisonMode = iota

	// ErrorComparisonModePolicyIDs compares only which policies errored,
	// not the specific error messages. This is the default for Lean comparison.
	ErrorComparisonModePolicyIDs

	// ErrorComparisonModeFull compares both erroring policies and error messages.
	// Use when exact error parity is expected.
	ErrorComparisonModeFull
)

// ValidationComparisonMode determines how validation results are compared.
type ValidationComparisonMode int

const (
	// ValidationComparisonModeAgreeOnValid requires both implementations
	// to agree when cedar-go reports valid. If cedar-go validates,
	// Lean must also validate (type soundness property).
	ValidationComparisonModeAgreeOnValid ValidationComparisonMode = iota

	// ValidationComparisonModeAgreeOnAll requires both implementations
	// to always agree on validation outcome.
	ValidationComparisonModeAgreeOnAll
)

// ComparisonConfig holds settings for DRT comparison.
type ComparisonConfig struct {
	// ErrorMode controls how authorization errors are compared.
	ErrorMode ErrorComparisonMode

	// ValidationMode controls how validation results are compared.
	ValidationMode ValidationComparisonMode

	// IgnoreDecisionOnError controls whether to compare decisions
	// when either implementation produces errors.
	IgnoreDecisionOnError bool
}

// DefaultConfig returns the default comparison configuration.
func DefaultConfig() ComparisonConfig {
	return ComparisonConfig{
		ErrorMode:             ErrorComparisonModePolicyIDs,
		ValidationMode:        ValidationComparisonModeAgreeOnValid,
		IgnoreDecisionOnError: false,
	}
}

// StrictConfig returns a strict comparison configuration that
// requires exact agreement on all aspects.
func StrictConfig() ComparisonConfig {
	return ComparisonConfig{
		ErrorMode:             ErrorComparisonModeFull,
		ValidationMode:        ValidationComparisonModeAgreeOnAll,
		IgnoreDecisionOnError: false,
	}
}

// LenientConfig returns a lenient comparison configuration
// suitable for initial testing or known-different behaviors.
func LenientConfig() ComparisonConfig {
	return ComparisonConfig{
		ErrorMode:             ErrorComparisonModeIgnore,
		ValidationMode:        ValidationComparisonModeAgreeOnValid,
		IgnoreDecisionOnError: true,
	}
}
