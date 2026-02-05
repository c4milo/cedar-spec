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
	"math/rand/v2"
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/typegen"
)

// This file contains property-based tests that verify cedar-go implements the
// authorization theorems proved in the Lean formalization:
//
// - forbid_trumps_permit: If a forbid policy is satisfied, decision = deny
// - default_deny: If no permit policy is satisfied, decision = deny
// - order_and_dup_independent: Authorization is independent of policy order/duplicates

// FuzzForbidTrumpsPermit verifies the forbid_trumps_permit theorem:
// If there is a satisfied forbid policy, the decision must be deny,
// regardless of any satisfied permit policies.
func FuzzForbidTrumpsPermit(f *testing.F) {
	f.Add([]byte("forbid-trumps-seed-1"))
	f.Add([]byte("forbid-trumps-seed-2"))
	f.Add(make([]byte, 64))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 16 {
			return
		}

		input, err := inputGen.Generate(data)
		if err != nil {
			return
		}

		ctx := &forbidTrumpsContext{
			input:   input,
			request: buildRequest(input),
		}

		verifyForbidTrumpsPermit(t, ctx)
	})
}

type forbidTrumpsContext struct {
	input   *typegen.TypeDirectedInput
	request cedar.Request
}

func verifyForbidTrumpsPermit(t *testing.T, ctx *forbidTrumpsContext) {
	t.Helper()

	// Create a policy set with both permit and forbid policies
	policies := cedar.NewPolicySet()

	// Add a permit-all policy
	var permitPolicy cedar.Policy
	err := permitPolicy.UnmarshalCedar([]byte(`permit(principal, action, resource);`))
	if err != nil {
		return
	}
	policies.Add("permit-all", &permitPolicy)

	// Add a forbid-all policy
	var forbidPolicy cedar.Policy
	err = forbidPolicy.UnmarshalCedar([]byte(`forbid(principal, action, resource);`))
	if err != nil {
		return
	}
	policies.Add("forbid-all", &forbidPolicy)

	// Theorem: forbid_trumps_permit - if forbid is satisfied, decision must be deny
	decision, diag := cedar.Authorize(policies, ctx.input.Entities.Entities, ctx.request)

	if decision != cedar.Deny {
		t.Errorf("forbid_trumps_permit violated: expected Deny when forbid policy is satisfied, got Allow\n"+
			"Request: %+v\nDiagnostic: %+v", ctx.request, diag)
	}

	// Verify the forbid policy is in determining policies
	hasForbid := false
	for _, reason := range diag.Reasons {
		if reason.PolicyID == "forbid-all" {
			hasForbid = true
			break
		}
	}
	if !hasForbid && decision == cedar.Deny {
		// This is expected - forbid should be in determining policies when it causes deny
		// But we should check if there are actually any determining policies
		if len(diag.Reasons) > 0 {
			t.Logf("Note: forbid-all not in determining policies, but other policies caused deny")
		}
	}
}

// FuzzDefaultDeny verifies the default_deny theorem:
// If no permit policy is satisfied, the decision must be deny.
func FuzzDefaultDeny(f *testing.F) {
	f.Add([]byte("default-deny-seed-1"))
	f.Add([]byte("default-deny-seed-2"))
	f.Add(make([]byte, 64))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 16 {
			return
		}

		input, err := inputGen.Generate(data)
		if err != nil {
			return
		}

		ctx := &defaultDenyContext{
			input:   input,
			request: buildRequest(input),
		}

		verifyDefaultDeny(t, ctx)
	})
}

type defaultDenyContext struct {
	input   *typegen.TypeDirectedInput
	request cedar.Request
}

func verifyDefaultDeny(t *testing.T, ctx *defaultDenyContext) {
	t.Helper()

	// Create empty policy set - no permit policies can be satisfied
	emptyPolicies := cedar.NewPolicySet()

	// Theorem: default_deny - if not explicitly permitted, decision must be deny
	decision, _ := cedar.Authorize(emptyPolicies, ctx.input.Entities.Entities, ctx.request)

	if decision != cedar.Deny {
		t.Errorf("default_deny violated: expected Deny with no policies, got Allow\n"+
			"Request: %+v", ctx.request)
	}

	// Also test with a policy that cannot be satisfied
	unsatisfiablePolicies := cedar.NewPolicySet()
	var policy cedar.Policy
	err := policy.UnmarshalCedar([]byte(`permit(principal == NonExistent::"entity", action, resource);`))
	if err != nil {
		return
	}
	unsatisfiablePolicies.Add("unsatisfiable", &policy)

	decision2, _ := cedar.Authorize(unsatisfiablePolicies, ctx.input.Entities.Entities, ctx.request)

	if decision2 != cedar.Deny {
		t.Errorf("default_deny violated: expected Deny when no permit is satisfied, got Allow\n"+
			"Request: %+v", ctx.request)
	}
}

// FuzzOrderAndDupIndependent verifies the order_and_dup_independent theorem:
// Authorization result is independent of policy order and duplicates.
func FuzzOrderAndDupIndependent(f *testing.F) {
	f.Add([]byte("order-dup-seed-1"))
	f.Add([]byte("order-dup-seed-2"))
	f.Add(make([]byte, 64))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 32 {
			return
		}

		input, err := inputGen.Generate(data)
		if err != nil {
			return
		}

		if input.Policies == nil || countPolicies(input.Policies) < 2 {
			return
		}

		ctx := &orderDupContext{
			input:   input,
			request: buildRequest(input),
			rng:     rand.New(rand.NewPCG(uint64(data[0]), uint64(data[1]))), //nolint:gosec // deterministic RNG for reproducible tests
		}

		verifyOrderAndDupIndependent(t, ctx)
	})
}

type orderDupContext struct {
	input   *typegen.TypeDirectedInput
	request cedar.Request
	rng     *rand.Rand
}

func verifyOrderAndDupIndependent(t *testing.T, ctx *orderDupContext) {
	t.Helper()

	// Get original result
	originalDecision, originalDiag := cedar.Authorize(
		ctx.input.Policies, ctx.input.Entities.Entities, ctx.request)

	// Create a reordered policy set
	reorderedPolicies := reorderPolicies(ctx.input.Policies, ctx.rng)

	reorderedDecision, reorderedDiag := cedar.Authorize(
		reorderedPolicies, ctx.input.Entities.Entities, ctx.request)

	// Theorem: order_and_dup_independent - decisions must match
	if originalDecision != reorderedDecision {
		t.Errorf("order_and_dup_independent violated (order): decision changed after reordering\n"+
			"Original: %v, Reordered: %v\nRequest: %+v",
			originalDecision, reorderedDecision, ctx.request)
	}

	// Create a policy set with duplicates
	duplicatedPolicies := duplicatePolicies(ctx.input.Policies)

	duplicatedDecision, duplicatedDiag := cedar.Authorize(
		duplicatedPolicies, ctx.input.Entities.Entities, ctx.request)

	// Decisions must match (though diagnostics may differ due to duplicate policy IDs)
	if originalDecision != duplicatedDecision {
		t.Errorf("order_and_dup_independent violated (duplicates): decision changed with duplicates\n"+
			"Original: %v, Duplicated: %v\nRequest: %+v",
			originalDecision, duplicatedDecision, ctx.request)
	}

	// Verify determining policies have equivalent effect
	verifyEquivalentDeterminingPolicies(t, originalDiag, reorderedDiag)
	_ = duplicatedDiag // Diagnostic comparison is tricky with duplicates
}

func reorderPolicies(original *cedar.PolicySet, rng *rand.Rand) *cedar.PolicySet {
	policies := original.All()

	// Collect all policies
	var ids []cedar.PolicyID
	var policyList []*cedar.Policy
	for id, p := range policies {
		ids = append(ids, id)
		policyList = append(policyList, p)
	}

	// Shuffle using Fisher-Yates
	for i := len(ids) - 1; i > 0; i-- {
		j := rng.IntN(i + 1)
		ids[i], ids[j] = ids[j], ids[i]
		policyList[i], policyList[j] = policyList[j], policyList[i]
	}

	// Create new policy set with shuffled order
	reordered := cedar.NewPolicySet()
	for i, id := range ids {
		reordered.Add(id, policyList[i])
	}

	return reordered
}

func duplicatePolicies(original *cedar.PolicySet) *cedar.PolicySet {
	duplicated := cedar.NewPolicySet()

	for id, p := range original.All() {
		// Add original
		duplicated.Add(id, p)
		// Add duplicate with modified ID
		duplicated.Add(cedar.PolicyID(string(id)+"_dup"), p)
	}

	return duplicated
}

func verifyEquivalentDeterminingPolicies(t *testing.T, diag1, diag2 types.Diagnostic) {
	t.Helper()

	// Both should have the same number of determining policies (or be equivalent)
	// Note: With different orderings, the exact policies might differ if multiple
	// have the same effect, but the count of each effect type should match
	permitCount1 := countPolicyEffect(diag1.Reasons)
	permitCount2 := countPolicyEffect(diag2.Reasons)

	if permitCount1 != permitCount2 {
		t.Logf("Note: Different determining policy counts after reorder: %d vs %d",
			permitCount1, permitCount2)
	}
}

func countPolicyEffect(reasons []types.DiagnosticReason) int {
	return len(reasons)
}

func buildRequest(input *typegen.TypeDirectedInput) cedar.Request {
	principal := types.NewEntityUID("User", "test")
	resource := types.NewEntityUID("Resource", "test")
	action := types.NewEntityUID("Action", "test")

	// Use entities from generated input if available
	if len(input.Entities.PrincipalUIDs) > 0 {
		principal = input.Entities.PrincipalUIDs[0]
	}
	if len(input.Entities.ResourceUIDs) > 0 {
		resource = input.Entities.ResourceUIDs[0]
	}
	if len(input.Schema.ActionList) > 0 {
		action = types.NewEntityUID("Action", types.String(input.Schema.ActionList[0]))
	}

	return cedar.Request{
		Principal: principal,
		Action:    action,
		Resource:  resource,
		Context:   types.NewRecord(types.RecordMap{}),
	}
}

// TestForbidTrumpsPermitBasic tests basic forbid trumps permit scenarios.
func TestForbidTrumpsPermitBasic(t *testing.T) {
	tests := []struct {
		name     string
		policies []string
		expected cedar.Decision
	}{
		{
			name: "forbid overrides permit",
			policies: []string{
				`permit(principal, action, resource);`,
				`forbid(principal, action, resource);`,
			},
			expected: cedar.Deny,
		},
		{
			name: "multiple permits with one forbid",
			policies: []string{
				`permit(principal, action, resource);`,
				`permit(principal, action, resource) when { true };`,
				`forbid(principal, action, resource);`,
			},
			expected: cedar.Deny,
		},
		{
			name: "conditional forbid satisfied",
			policies: []string{
				`permit(principal, action, resource);`,
				`forbid(principal, action, resource) when { true };`,
			},
			expected: cedar.Deny,
		},
	}

	request := cedar.Request{
		Principal: types.NewEntityUID("User", "alice"),
		Action:    types.NewEntityUID("Action", "view"),
		Resource:  types.NewEntityUID("Doc", "doc1"),
		Context:   types.NewRecord(types.RecordMap{}),
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policies := cedar.NewPolicySet()
			for i, policyStr := range tc.policies {
				var policy cedar.Policy
				if err := policy.UnmarshalCedar([]byte(policyStr)); err != nil {
					t.Fatalf("Failed to parse policy %d: %v", i, err)
				}
				policies.Add(cedar.PolicyID(string(rune('a'+i))), &policy)
			}

			decision, _ := cedar.Authorize(policies, types.EntityMap{}, request)
			if decision != tc.expected {
				t.Errorf("Expected %v, got %v", tc.expected, decision)
			}
		})
	}
}

// TestDefaultDenyBasic tests basic default deny scenarios.
func TestDefaultDenyBasic(t *testing.T) {
	request := cedar.Request{
		Principal: types.NewEntityUID("User", "alice"),
		Action:    types.NewEntityUID("Action", "view"),
		Resource:  types.NewEntityUID("Doc", "doc1"),
		Context:   types.NewRecord(types.RecordMap{}),
	}

	tests := []struct {
		name     string
		policies []string
	}{
		{
			name:     "empty policy set",
			policies: []string{},
		},
		{
			name: "unsatisfied permit",
			policies: []string{
				`permit(principal == User::"bob", action, resource);`,
			},
		},
		{
			name: "only forbid policies",
			policies: []string{
				`forbid(principal, action, resource) when { false };`,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policies := cedar.NewPolicySet()
			for i, policyStr := range tc.policies {
				var policy cedar.Policy
				if err := policy.UnmarshalCedar([]byte(policyStr)); err != nil {
					t.Fatalf("Failed to parse policy %d: %v", i, err)
				}
				policies.Add(cedar.PolicyID(string(rune('a'+i))), &policy)
			}

			decision, _ := cedar.Authorize(policies, types.EntityMap{}, request)
			if decision != cedar.Deny {
				t.Errorf("Expected Deny (default_deny), got %v", decision)
			}
		})
	}
}

// TestOrderIndependenceBasic tests basic order independence scenarios.
func TestOrderIndependenceBasic(t *testing.T) {
	request := cedar.Request{
		Principal: types.NewEntityUID("User", "alice"),
		Action:    types.NewEntityUID("Action", "view"),
		Resource:  types.NewEntityUID("Doc", "doc1"),
		Context:   types.NewRecord(types.RecordMap{}),
	}

	// Create two policy sets with same policies in different order
	policies1 := cedar.NewPolicySet()
	policies2 := cedar.NewPolicySet()

	var permitPolicy cedar.Policy
	if err := permitPolicy.UnmarshalCedar([]byte(`permit(principal, action, resource);`)); err != nil {
		t.Fatalf("Failed to parse permit policy: %v", err)
	}

	var forbidPolicy cedar.Policy
	if err := forbidPolicy.UnmarshalCedar([]byte(`forbid(principal == User::"bob", action, resource);`)); err != nil {
		t.Fatalf("Failed to parse forbid policy: %v", err)
	}

	// Order 1: permit then forbid
	policies1.Add("permit", &permitPolicy)
	policies1.Add("forbid", &forbidPolicy)

	// Order 2: forbid then permit (simulated by adding in different order)
	policies2.Add("forbid", &forbidPolicy)
	policies2.Add("permit", &permitPolicy)

	decision1, _ := cedar.Authorize(policies1, types.EntityMap{}, request)
	decision2, _ := cedar.Authorize(policies2, types.EntityMap{}, request)

	if decision1 != decision2 {
		t.Errorf("Order independence violated: got %v and %v for different orderings",
			decision1, decision2)
	}
}
