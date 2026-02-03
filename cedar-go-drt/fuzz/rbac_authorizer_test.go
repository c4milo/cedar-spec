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
	"fmt"
	"runtime"
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/comparison"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/lean"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/proto"
)

// AbstractPolicy represents the possible behaviors of a policy.
// This mirrors the Rust DRT's AbstractPolicy enum.
type AbstractPolicy int

const (
	// PermitTrue - a permit policy whose condition is always true
	PermitTrue AbstractPolicy = iota
	// PermitFalse - a permit policy whose condition is always false
	PermitFalse
	// PermitError - a permit policy that errors during evaluation
	PermitError
	// ForbidTrue - a forbid policy whose condition is always true
	ForbidTrue
	// ForbidFalse - a forbid policy whose condition is always false
	ForbidFalse
	// ForbidError - a forbid policy that errors during evaluation
	ForbidError
)

// abstractPolicyCedar returns the Cedar policy string for an abstract policy.
func abstractPolicyCedar(ap AbstractPolicy) string {
	switch ap {
	case PermitTrue:
		return `permit(principal, action, resource) when { true };`
	case PermitFalse:
		return `permit(principal, action, resource) when { false };`
	case PermitError:
		// Error: accessing undefined attribute
		return `permit(principal, action, resource) when { principal.undefined_attr_xyz };`
	case ForbidTrue:
		return `forbid(principal, action, resource) when { true };`
	case ForbidFalse:
		return `forbid(principal, action, resource) when { false };`
	case ForbidError:
		// Error: accessing undefined attribute
		return `forbid(principal, action, resource) when { principal.undefined_attr_xyz };`
	default:
		return `permit(principal, action, resource) when { false };`
	}
}

// FuzzRBACAuthorizer tests abstract policy combinations to verify
// authorization decision logic. This tests properties like:
// - Forbid trumps permit
// - Errors are tracked correctly
// - Default deny when no policies apply
func FuzzRBACAuthorizer(f *testing.F) {
	// Seeds encode combinations of abstract policies
	f.Add([]byte{0})                             // Single PermitTrue
	f.Add([]byte{3})                             // Single ForbidTrue
	f.Add([]byte{0, 3})                          // PermitTrue + ForbidTrue (forbid wins)
	f.Add([]byte{0, 1, 2, 3, 4, 5})              // All policy types
	f.Add([]byte{2, 5})                          // Both error types
	f.Add(make([]byte, 16))                      // Random combination
	f.Add([]byte{0, 0, 0, 3})                    // Multiple permits, one forbid
	f.Add([]byte{1, 1, 1, 1})                    // All false conditions
	f.Add([]byte{0, 2})                          // PermitTrue + PermitError
	f.Add([]byte{3, 5})                          // ForbidTrue + ForbidError
	f.Add([]byte("abstract-policy-combination")) // Text seed

	config := comparison.DefaultConfig()

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}

		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		// Generate policy set from abstract policies
		ps := cedar.NewPolicySet()
		for i, b := range data {
			ap := AbstractPolicy(b % 6) // 6 abstract policy types
			policyStr := abstractPolicyCedar(ap)
			var policy cedar.Policy
			if err := policy.UnmarshalCedar([]byte(policyStr)); err != nil {
				continue
			}
			ps.Add(cedar.PolicyID(fmt.Sprintf("policy%d", i)), &policy)
		}

		// Count policies
		count := 0
		for range ps.All() {
			count++
		}
		if count == 0 {
			return
		}

		// Simple entities and request
		entities := types.EntityMap{
			types.EntityUID{Type: "User", ID: "test"}: types.Entity{},
			types.EntityUID{Type: "Doc", ID: "doc"}:   types.Entity{},
		}

		req := cedar.Request{
			Principal: types.EntityUID{Type: "User", ID: "test"},
			Action:    types.EntityUID{Type: "Action", ID: "view"},
			Resource:  types.EntityUID{Type: "Doc", ID: "doc"},
			Context:   types.NewRecord(types.RecordMap{}),
		}

		// Run cedar-go authorization
		goDecision, goDiag := cedar.Authorize(ps, entities, req)

		// Run Lean authorization
		leanResp := runAbstractLeanAuth(t, ps, entities, req)
		if leanResp == nil {
			return
		}

		// Compare results
		goResult := toAuthorizationResult(goDecision, goDiag)
		leanResult := toLeanAuthorizationResult(leanResp)

		diffs := comparison.CompareAuthorization(goResult, leanResult, config)
		if len(diffs) > 0 {
			t.Errorf("Abstract authorizer divergence:\n%s\nPolicies: abstract combination from %d bytes",
				comparison.FormatDifferences(diffs), len(data))
		}
	})
}

// runAbstractLeanAuth runs Lean authorization for abstract authorizer tests.
func runAbstractLeanAuth(t *testing.T, policies *cedar.PolicySet, entities types.EntityMap, req cedar.Request) *lean.AuthorizationResponse {
	t.Helper()

	authReq := proto.PolicySetFromCedar(policies, entities, &req)
	protoBytes, err := authReq.ToProtobuf()
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

	leanResp, err := lean.IsAuthorized(protoBytes)
	if err != nil {
		t.Logf("Lean FFI error: %v", err)
		return nil
	}

	return leanResp
}

// TestAbstractAuthorizerProperties tests fundamental authorization properties.
func TestAbstractAuthorizerProperties(t *testing.T) {
	entities := types.EntityMap{
		types.EntityUID{Type: "User", ID: "test"}: types.Entity{},
		types.EntityUID{Type: "Doc", ID: "doc"}:   types.Entity{},
	}

	req := cedar.Request{
		Principal: types.EntityUID{Type: "User", ID: "test"},
		Action:    types.EntityUID{Type: "Action", ID: "view"},
		Resource:  types.EntityUID{Type: "Doc", ID: "doc"},
		Context:   types.NewRecord(types.RecordMap{}),
	}

	tests := []struct {
		name           string
		policies       []AbstractPolicy
		expectDecision cedar.Decision
		expectErrors   bool
	}{
		{
			name:           "empty policy set denies",
			policies:       []AbstractPolicy{},
			expectDecision: cedar.Deny,
			expectErrors:   false,
		},
		{
			name:           "single permit true allows",
			policies:       []AbstractPolicy{PermitTrue},
			expectDecision: cedar.Allow,
			expectErrors:   false,
		},
		{
			name:           "single permit false denies",
			policies:       []AbstractPolicy{PermitFalse},
			expectDecision: cedar.Deny,
			expectErrors:   false,
		},
		{
			name:           "single forbid true denies",
			policies:       []AbstractPolicy{ForbidTrue},
			expectDecision: cedar.Deny,
			expectErrors:   false,
		},
		{
			name:           "forbid trumps permit",
			policies:       []AbstractPolicy{PermitTrue, ForbidTrue},
			expectDecision: cedar.Deny,
			expectErrors:   false,
		},
		{
			name:           "multiple permits one forbid",
			policies:       []AbstractPolicy{PermitTrue, PermitTrue, PermitTrue, ForbidTrue},
			expectDecision: cedar.Deny,
			expectErrors:   false,
		},
		{
			name:           "permit error produces error",
			policies:       []AbstractPolicy{PermitError},
			expectDecision: cedar.Deny,
			expectErrors:   true,
		},
		{
			name:           "forbid error produces error",
			policies:       []AbstractPolicy{ForbidError},
			expectDecision: cedar.Deny,
			expectErrors:   true,
		},
		{
			name:           "permit true with permit error still allows",
			policies:       []AbstractPolicy{PermitTrue, PermitError},
			expectDecision: cedar.Allow,
			expectErrors:   true,
		},
		{
			name:           "forbid true with forbid error still denies",
			policies:       []AbstractPolicy{ForbidTrue, ForbidError},
			expectDecision: cedar.Deny,
			expectErrors:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ps := cedar.NewPolicySet()
			for i, ap := range tc.policies {
				policyStr := abstractPolicyCedar(ap)
				var policy cedar.Policy
				if err := policy.UnmarshalCedar([]byte(policyStr)); err != nil {
					t.Fatalf("Failed to parse policy: %v", err)
				}
				ps.Add(cedar.PolicyID(fmt.Sprintf("policy%d", i)), &policy)
			}

			decision, diag := cedar.Authorize(ps, entities, req)

			if decision != tc.expectDecision {
				t.Errorf("Expected decision %v, got %v", tc.expectDecision, decision)
			}

			hasErrors := len(diag.Errors) > 0
			if hasErrors != tc.expectErrors {
				t.Errorf("Expected errors=%v, got errors=%v (errors: %v)",
					tc.expectErrors, hasErrors, diag.Errors)
			}
		})
	}
}

// TestForbidTrumpsPermitProperty verifies the fundamental Cedar property
// that any applicable forbid policy overrides all permit policies.
func TestForbidTrumpsPermitProperty(t *testing.T) {
	entities := types.EntityMap{
		types.EntityUID{Type: "User", ID: "test"}: types.Entity{},
		types.EntityUID{Type: "Doc", ID: "doc"}:   types.Entity{},
	}

	req := cedar.Request{
		Principal: types.EntityUID{Type: "User", ID: "test"},
		Action:    types.EntityUID{Type: "Action", ID: "view"},
		Resource:  types.EntityUID{Type: "Doc", ID: "doc"},
		Context:   types.NewRecord(types.RecordMap{}),
	}

	// Test with varying numbers of permit policies
	for numPermits := 1; numPermits <= 10; numPermits++ {
		ps := cedar.NewPolicySet()

		// Add permit policies
		for i := range numPermits {
			var policy cedar.Policy
			err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource);`))
			if err != nil {
				t.Fatalf("Failed to parse permit policy: %v", err)
			}
			ps.Add(cedar.PolicyID(fmt.Sprintf("permit%d", i)), &policy)
		}

		// Add single forbid policy
		var forbidPolicy cedar.Policy
		err := forbidPolicy.UnmarshalCedar([]byte(`forbid(principal, action, resource);`))
		if err != nil {
			t.Fatalf("Failed to parse forbid policy: %v", err)
		}
		ps.Add("forbid", &forbidPolicy)

		decision, _ := cedar.Authorize(ps, entities, req)
		if decision != cedar.Deny {
			t.Errorf("With %d permits and 1 forbid, expected Deny, got %v", numPermits, decision)
		}
	}
}

// TestErrorHandlingProperty tests that errors are correctly tracked
// and do not affect the decision when valid policies determine the outcome.
func TestErrorHandlingProperty(t *testing.T) {
	entities := types.EntityMap{
		types.EntityUID{Type: "User", ID: "test"}: types.Entity{},
		types.EntityUID{Type: "Doc", ID: "doc"}:   types.Entity{},
	}

	req := cedar.Request{
		Principal: types.EntityUID{Type: "User", ID: "test"},
		Action:    types.EntityUID{Type: "Action", ID: "view"},
		Resource:  types.EntityUID{Type: "Doc", ID: "doc"},
		Context:   types.NewRecord(types.RecordMap{}),
	}

	ps := cedar.NewPolicySet()

	// Add a permit that will succeed
	var permitPolicy cedar.Policy
	err := permitPolicy.UnmarshalCedar([]byte(`permit(principal, action, resource);`))
	if err != nil {
		t.Fatalf("Failed to parse permit policy: %v", err)
	}
	ps.Add("permit", &permitPolicy)

	// Add policies that will error
	for i := range 5 {
		var errorPolicy cedar.Policy
		err := errorPolicy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { principal.nonexistent };`))
		if err != nil {
			t.Fatalf("Failed to parse error policy: %v", err)
		}
		ps.Add(cedar.PolicyID(fmt.Sprintf("error%d", i)), &errorPolicy)
	}

	decision, diag := cedar.Authorize(ps, entities, req)

	// Decision should be Allow (the non-erroring permit applies)
	if decision != cedar.Allow {
		t.Errorf("Expected Allow despite errors, got %v", decision)
	}

	// Should have exactly 5 errors
	if len(diag.Errors) != 5 {
		t.Errorf("Expected 5 errors, got %d", len(diag.Errors))
	}
}
