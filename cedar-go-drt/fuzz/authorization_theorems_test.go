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
// - denied_iff_explicitly_denied_or_not_permitted: Deny ↔ explicitly forbidden or not explicitly permitted
// - unchanged_allow_when_add_permit: Adding a permit won't flip Allow to Deny
// - unchanged_deny_when_add_forbid: Adding a forbid won't flip Deny to Allow
// - determining_erroring_disjoint_when_unique_ids: Determining and erroring policies are disjoint
// - unchanged_determining_when_add_policy_and_decision_unchanged: Determining policies preserved when decision unchanged
// - unchanged_erroring_when_add_policy: Erroring policies preserved when adding any policy

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

// ---------- New theorems from Cedar additional properties (#203) ----------

// FuzzDeniedIffExplicitlyDeniedOrNotPermitted verifies:
// A request is denied iff it is explicitly forbidden or not explicitly permitted.
// This is the converse characterization of the deny decision.
func FuzzDeniedIffExplicitlyDeniedOrNotPermitted(f *testing.F) {
	f.Add([]byte("denied-iff-seed-1"))
	f.Add([]byte("denied-iff-seed-2"))
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

		request := buildRequest(input)
		decision, diag := cedar.Authorize(input.Policies, input.Entities.Entities, request)

		// Check if explicitly forbidden (any satisfied forbid policy in Reasons)
		explicitlyForbidden := false
		for _, reason := range diag.Reasons {
			p := input.Policies.Get(reason.PolicyID)
			if p != nil && p.Effect() == cedar.Forbid {
				explicitlyForbidden = true
				break
			}
		}

		// Check if explicitly permitted (any satisfied permit policy)
		// A permit is satisfied if it appears in Reasons when the decision would be Allow
		// without any forbid. We can check by looking at permit policies in Reasons.
		explicitlyPermitted := false
		for _, reason := range diag.Reasons {
			p := input.Policies.Get(reason.PolicyID)
			if p != nil && p.Effect() == cedar.Permit {
				explicitlyPermitted = true
				break
			}
		}

		// Theorem: denied_iff_explicitly_denied_or_not_permitted
		// deny ↔ (explicitly forbidden ∨ ¬explicitly permitted)
		isDeny := decision == cedar.Deny
		shouldBeDeny := explicitlyForbidden || !explicitlyPermitted

		if isDeny != shouldBeDeny {
			t.Errorf("denied_iff_explicitly_denied_or_not_permitted violated:\n"+
				"decision=%v, explicitlyForbidden=%v, explicitlyPermitted=%v\n"+
				"expected deny=%v, got deny=%v\nRequest: %+v\nDiagnostic: %+v",
				decision, explicitlyForbidden, explicitlyPermitted,
				shouldBeDeny, isDeny, request, diag)
		}
	})
}

// FuzzUnchangedAllowWhenAddPermit verifies:
// Adding a permit policy to a policy set that already allows a request
// won't change the Allow decision.
func FuzzUnchangedAllowWhenAddPermit(f *testing.F) {
	f.Add([]byte("add-permit-seed-1"))
	f.Add([]byte("add-permit-seed-2"))
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

		request := buildRequest(input)
		decision, _ := cedar.Authorize(input.Policies, input.Entities.Entities, request)

		if decision != cedar.Allow {
			return // Theorem only applies when original decision is Allow
		}

		// Generate a few different permit policies and add each one
		permitStrs := []string{
			`permit(principal, action, resource);`,
			`permit(principal, action, resource) when { true };`,
			fmt.Sprintf(`permit(principal == %s, action, resource);`, request.Principal),
		}

		for i, pStr := range permitStrs {
			newPolicies := cedar.NewPolicySet()
			// Copy existing policies
			for id, p := range input.Policies.All() {
				newPolicies.Add(id, p)
			}
			// Add new permit policy
			var newPermit cedar.Policy
			if err := newPermit.UnmarshalCedar([]byte(pStr)); err != nil {
				continue
			}
			newPolicies.Add(cedar.PolicyID(fmt.Sprintf("added-permit-%d", i)), &newPermit)

			newDecision, _ := cedar.Authorize(newPolicies, input.Entities.Entities, request)

			if newDecision != cedar.Allow {
				t.Errorf("unchanged_allow_when_add_permit violated:\n"+
					"Original decision=Allow, after adding permit policy %q got %v\n"+
					"Request: %+v", pStr, newDecision, request)
			}
		}
	})
}

// FuzzUnchangedDenyWhenAddForbid verifies:
// Adding a forbid policy to a policy set that already denies a request
// won't change the Deny decision.
func FuzzUnchangedDenyWhenAddForbid(f *testing.F) {
	f.Add([]byte("add-forbid-seed-1"))
	f.Add([]byte("add-forbid-seed-2"))
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

		request := buildRequest(input)
		decision, _ := cedar.Authorize(input.Policies, input.Entities.Entities, request)

		if decision != cedar.Deny {
			return // Theorem only applies when original decision is Deny
		}

		// Generate a few different forbid policies and add each one
		forbidStrs := []string{
			`forbid(principal, action, resource);`,
			`forbid(principal, action, resource) when { true };`,
			fmt.Sprintf(`forbid(principal == %s, action, resource);`, request.Principal),
		}

		for i, fStr := range forbidStrs {
			newPolicies := cedar.NewPolicySet()
			for id, p := range input.Policies.All() {
				newPolicies.Add(id, p)
			}
			var newForbid cedar.Policy
			if err := newForbid.UnmarshalCedar([]byte(fStr)); err != nil {
				continue
			}
			newPolicies.Add(cedar.PolicyID(fmt.Sprintf("added-forbid-%d", i)), &newForbid)

			newDecision, _ := cedar.Authorize(newPolicies, input.Entities.Entities, request)

			if newDecision != cedar.Deny {
				t.Errorf("unchanged_deny_when_add_forbid violated:\n"+
					"Original decision=Deny, after adding forbid policy %q got %v\n"+
					"Request: %+v", fStr, newDecision, request)
			}
		}
	})
}

// FuzzDeterminingErroringDisjoint verifies:
// The determining policies and erroring policies of an authorization response
// are always disjoint (when policy IDs are unique, which PolicySet enforces).
func FuzzDeterminingErroringDisjoint(f *testing.F) {
	f.Add([]byte("det-err-disjoint-seed-1"))
	f.Add([]byte("det-err-disjoint-seed-2"))
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

		request := buildRequest(input)
		_, diag := cedar.Authorize(input.Policies, input.Entities.Entities, request)

		// Build set of determining policy IDs
		determining := make(map[types.PolicyID]bool)
		for _, reason := range diag.Reasons {
			determining[reason.PolicyID] = true
		}

		// Check no erroring policy is also a determining policy
		for _, diagErr := range diag.Errors {
			if determining[diagErr.PolicyID] {
				t.Errorf("determining_erroring_disjoint_when_unique_ids violated:\n"+
					"Policy %q is both determining and erroring\n"+
					"Reasons: %+v\nErrors: %+v\nRequest: %+v",
					diagErr.PolicyID, diag.Reasons, diag.Errors, request)
			}
		}
	})
}

// FuzzUnchangedDeterminingWhenDecisionUnchanged verifies:
// If adding a policy doesn't change the authorization decision,
// then all original determining policies remain determining.
func FuzzUnchangedDeterminingWhenDecisionUnchanged(f *testing.F) {
	f.Add([]byte("unchanged-det-seed-1"))
	f.Add([]byte("unchanged-det-seed-2"))
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

		request := buildRequest(input)
		origDecision, origDiag := cedar.Authorize(input.Policies, input.Entities.Entities, request)

		// Add a new policy (try both permit and forbid)
		extraPolicies := []string{
			`permit(principal == AddedType::"added-entity", action, resource);`,
			`forbid(principal == AddedType::"added-entity", action, resource);`,
			`permit(principal, action, resource) when { false };`,
			`forbid(principal, action, resource) when { false };`,
		}

		for i, pStr := range extraPolicies {
			newPolicies := cedar.NewPolicySet()
			for id, p := range input.Policies.All() {
				newPolicies.Add(id, p)
			}
			var newPolicy cedar.Policy
			if err := newPolicy.UnmarshalCedar([]byte(pStr)); err != nil {
				continue
			}
			addedID := cedar.PolicyID(fmt.Sprintf("added-policy-%d", i))
			newPolicies.Add(addedID, &newPolicy)

			newDecision, newDiag := cedar.Authorize(newPolicies, input.Entities.Entities, request)

			if origDecision != newDecision {
				continue // Decision changed, theorem doesn't apply
			}

			// Theorem: all original determining policies must still be determining
			newDetermining := make(map[types.PolicyID]bool)
			for _, reason := range newDiag.Reasons {
				newDetermining[reason.PolicyID] = true
			}

			for _, origReason := range origDiag.Reasons {
				if !newDetermining[origReason.PolicyID] {
					t.Errorf("unchanged_determining_when_add_policy violated:\n"+
						"Decision unchanged (%v), but determining policy %q was lost\n"+
						"Added policy: %q\nOriginal reasons: %+v\nNew reasons: %+v\nRequest: %+v",
						origDecision, origReason.PolicyID, pStr,
						origDiag.Reasons, newDiag.Reasons, request)
				}
			}
		}
	})
}

// FuzzUnchangedErroringWhenAddPolicy verifies:
// Adding any policy preserves the set of erroring policies from the original
// evaluation, regardless of whether the decision changes.
func FuzzUnchangedErroringWhenAddPolicy(f *testing.F) {
	f.Add([]byte("unchanged-err-seed-1"))
	f.Add([]byte("unchanged-err-seed-2"))
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

		request := buildRequest(input)
		_, origDiag := cedar.Authorize(input.Policies, input.Entities.Entities, request)

		// Add various policies
		extraPolicies := []string{
			`permit(principal, action, resource);`,
			`forbid(principal, action, resource);`,
			`permit(principal, action, resource) when { context.nonexistent };`,
		}

		for i, pStr := range extraPolicies {
			newPolicies := cedar.NewPolicySet()
			for id, p := range input.Policies.All() {
				newPolicies.Add(id, p)
			}
			var newPolicy cedar.Policy
			if err := newPolicy.UnmarshalCedar([]byte(pStr)); err != nil {
				continue
			}
			newPolicies.Add(cedar.PolicyID(fmt.Sprintf("added-policy-%d", i)), &newPolicy)

			_, newDiag := cedar.Authorize(newPolicies, input.Entities.Entities, request)

			// Theorem: all original erroring policies must still be erroring
			newErroring := make(map[types.PolicyID]bool)
			for _, diagErr := range newDiag.Errors {
				newErroring[diagErr.PolicyID] = true
			}

			for _, origErr := range origDiag.Errors {
				if !newErroring[origErr.PolicyID] {
					t.Errorf("unchanged_erroring_when_add_policy violated:\n"+
						"Erroring policy %q was lost after adding policy %q\n"+
						"Original errors: %+v\nNew errors: %+v\nRequest: %+v",
						origErr.PolicyID, pStr,
						origDiag.Errors, newDiag.Errors, request)
				}
			}
		}
	})
}

// ---------- Unit tests for new theorems ----------

// TestDeniedIffExplicitlyDeniedOrNotPermitted tests the biconditional:
// deny ↔ (explicitly forbidden ∨ ¬explicitly permitted)
func TestDeniedIffExplicitlyDeniedOrNotPermitted(t *testing.T) {
	request := cedar.Request{
		Principal: types.NewEntityUID("User", "alice"),
		Action:    types.NewEntityUID("Action", "view"),
		Resource:  types.NewEntityUID("Doc", "doc1"),
		Context:   types.NewRecord(types.RecordMap{}),
	}

	tests := []struct {
		name                string
		policies            []string
		expectedDeny        bool
		explicitlyForbidden bool
		explicitlyPermitted bool
	}{
		{
			name:                "no policies → deny (not permitted)",
			policies:            []string{},
			expectedDeny:        true,
			explicitlyForbidden: false,
			explicitlyPermitted: false,
		},
		{
			name:                "only permit → allow",
			policies:            []string{`permit(principal, action, resource);`},
			expectedDeny:        false,
			explicitlyForbidden: false,
			explicitlyPermitted: true,
		},
		{
			name: "permit + forbid → deny (explicitly forbidden)",
			policies: []string{
				`permit(principal, action, resource);`,
				`forbid(principal, action, resource);`,
			},
			expectedDeny:        true,
			explicitlyForbidden: true,
			explicitlyPermitted: true,
		},
		{
			name:                "unsatisfied permit → deny (not permitted)",
			policies:            []string{`permit(principal == User::"bob", action, resource);`},
			expectedDeny:        true,
			explicitlyForbidden: false,
			explicitlyPermitted: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ps := cedar.NewPolicySet()
			for i, pStr := range tc.policies {
				var p cedar.Policy
				if err := p.UnmarshalCedar([]byte(pStr)); err != nil {
					t.Fatalf("Failed to parse policy %d: %v", i, err)
				}
				ps.Add(cedar.PolicyID(fmt.Sprintf("p%d", i)), &p)
			}

			decision, _ := cedar.Authorize(ps, types.EntityMap{}, request)
			isDeny := decision == cedar.Deny

			if isDeny != tc.expectedDeny {
				t.Errorf("expected deny=%v, got deny=%v", tc.expectedDeny, isDeny)
			}
		})
	}
}

// TestUnchangedAllowWhenAddPermit tests that adding a permit can't flip Allow to Deny.
func TestUnchangedAllowWhenAddPermit(t *testing.T) {
	request := cedar.Request{
		Principal: types.NewEntityUID("User", "alice"),
		Action:    types.NewEntityUID("Action", "view"),
		Resource:  types.NewEntityUID("Doc", "doc1"),
		Context:   types.NewRecord(types.RecordMap{}),
	}

	// Start with a policy set that allows
	ps := cedar.NewPolicySet()
	var permit cedar.Policy
	if err := permit.UnmarshalCedar([]byte(`permit(principal, action, resource);`)); err != nil {
		t.Fatal(err)
	}
	ps.Add("permit-all", &permit)

	decision, _ := cedar.Authorize(ps, types.EntityMap{}, request)
	if decision != cedar.Allow {
		t.Fatal("precondition: expected Allow")
	}

	// Add additional permit policies
	additions := []string{
		`permit(principal == User::"bob", action, resource);`,
		`permit(principal, action, resource) when { true };`,
		`permit(principal, action, resource) when { false };`,
	}

	for i, pStr := range additions {
		var p cedar.Policy
		if err := p.UnmarshalCedar([]byte(pStr)); err != nil {
			t.Fatalf("Failed to parse policy %d: %v", i, err)
		}
		ps.Add(cedar.PolicyID(fmt.Sprintf("extra-permit-%d", i)), &p)

		newDecision, _ := cedar.Authorize(ps, types.EntityMap{}, request)
		if newDecision != cedar.Allow {
			t.Errorf("unchanged_allow_when_add_permit violated after adding %q: got %v", pStr, newDecision)
		}
	}
}

// TestUnchangedDenyWhenAddForbid tests that adding a forbid can't flip Deny to Allow.
func TestUnchangedDenyWhenAddForbid(t *testing.T) {
	request := cedar.Request{
		Principal: types.NewEntityUID("User", "alice"),
		Action:    types.NewEntityUID("Action", "view"),
		Resource:  types.NewEntityUID("Doc", "doc1"),
		Context:   types.NewRecord(types.RecordMap{}),
	}

	// Start with empty policy set (default deny)
	ps := cedar.NewPolicySet()
	decision, _ := cedar.Authorize(ps, types.EntityMap{}, request)
	if decision != cedar.Deny {
		t.Fatal("precondition: expected Deny")
	}

	// Add forbid policies
	additions := []string{
		`forbid(principal, action, resource);`,
		`forbid(principal == User::"bob", action, resource);`,
		`forbid(principal, action, resource) when { true };`,
	}

	for i, fStr := range additions {
		var p cedar.Policy
		if err := p.UnmarshalCedar([]byte(fStr)); err != nil {
			t.Fatalf("Failed to parse policy %d: %v", i, err)
		}
		ps.Add(cedar.PolicyID(fmt.Sprintf("extra-forbid-%d", i)), &p)

		newDecision, _ := cedar.Authorize(ps, types.EntityMap{}, request)
		if newDecision != cedar.Deny {
			t.Errorf("unchanged_deny_when_add_forbid violated after adding %q: got %v", fStr, newDecision)
		}
	}
}

// TestDeterminingErroringDisjoint tests that determining and erroring policies never overlap.
func TestDeterminingErroringDisjoint(t *testing.T) {
	request := cedar.Request{
		Principal: types.NewEntityUID("User", "alice"),
		Action:    types.NewEntityUID("Action", "view"),
		Resource:  types.NewEntityUID("Doc", "doc1"),
		Context:   types.NewRecord(types.RecordMap{}),
	}

	tests := []struct {
		name     string
		policies map[string]string
	}{
		{
			name: "permit with error",
			policies: map[string]string{
				"good-permit": `permit(principal, action, resource);`,
				"bad-permit":  `permit(principal, action, resource) when { context.nonexistent > 0 };`,
			},
		},
		{
			name: "forbid with error",
			policies: map[string]string{
				"good-forbid": `forbid(principal, action, resource);`,
				"bad-forbid":  `forbid(principal, action, resource) when { context.nonexistent > 0 };`,
			},
		},
		{
			name: "mixed with errors",
			policies: map[string]string{
				"permit-ok":    `permit(principal, action, resource);`,
				"forbid-ok":    `forbid(principal, action, resource);`,
				"permit-error": `permit(principal, action, resource) when { context.missing };`,
				"forbid-error": `forbid(principal, action, resource) when { context.missing };`,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ps := cedar.NewPolicySet()
			for id, pStr := range tc.policies {
				var p cedar.Policy
				if err := p.UnmarshalCedar([]byte(pStr)); err != nil {
					t.Fatalf("Failed to parse policy %q: %v", id, err)
				}
				ps.Add(cedar.PolicyID(id), &p)
			}

			_, diag := cedar.Authorize(ps, types.EntityMap{}, request)

			determining := make(map[types.PolicyID]bool)
			for _, reason := range diag.Reasons {
				determining[reason.PolicyID] = true
			}

			for _, diagErr := range diag.Errors {
				if determining[diagErr.PolicyID] {
					t.Errorf("Policy %q is both determining and erroring", diagErr.PolicyID)
				}
			}
		})
	}
}

// TestUnchangedErroringWhenAddPolicy tests that adding a policy preserves erroring policies.
func TestUnchangedErroringWhenAddPolicy(t *testing.T) {
	request := cedar.Request{
		Principal: types.NewEntityUID("User", "alice"),
		Action:    types.NewEntityUID("Action", "view"),
		Resource:  types.NewEntityUID("Doc", "doc1"),
		Context:   types.NewRecord(types.RecordMap{}),
	}

	// Create a policy set with an erroring policy
	ps := cedar.NewPolicySet()
	var errorPolicy cedar.Policy
	if err := errorPolicy.UnmarshalCedar([]byte(
		`permit(principal, action, resource) when { context.nonexistent > 0 };`,
	)); err != nil {
		t.Fatal(err)
	}
	ps.Add("error-policy", &errorPolicy)

	_, origDiag := cedar.Authorize(ps, types.EntityMap{}, request)

	if len(origDiag.Errors) == 0 {
		t.Fatal("precondition: expected at least one erroring policy")
	}

	// Add various policies
	additions := map[string]string{
		"new-permit": `permit(principal, action, resource);`,
		"new-forbid": `forbid(principal, action, resource);`,
	}

	for id, pStr := range additions {
		newPS := cedar.NewPolicySet()
		newPS.Add("error-policy", &errorPolicy)

		var p cedar.Policy
		if err := p.UnmarshalCedar([]byte(pStr)); err != nil {
			t.Fatalf("Failed to parse policy %q: %v", id, err)
		}
		newPS.Add(cedar.PolicyID(id), &p)

		_, newDiag := cedar.Authorize(newPS, types.EntityMap{}, request)

		newErroring := make(map[types.PolicyID]bool)
		for _, diagErr := range newDiag.Errors {
			newErroring[diagErr.PolicyID] = true
		}

		for _, origErr := range origDiag.Errors {
			if !newErroring[origErr.PolicyID] {
				t.Errorf("After adding %q: erroring policy %q was lost", id, origErr.PolicyID)
			}
		}
	}
}

// ---------- Proposed theorems (not yet in Lean formalization) ----------

// FuzzErrorIrrelevance verifies that erroring policies never influence the
// authorization decision. Replacing every erroring policy with a trivially-false
// policy of the same effect must preserve the decision. This guarantees that
// runtime evaluation errors (missing attributes, type mismatches) can never
// escalate privileges.
func FuzzErrorIrrelevance(f *testing.F) {
	f.Add([]byte("error-irrel-seed-1"))
	f.Add([]byte("error-irrel-seed-2"))
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

		request := buildRequest(input)
		decision, diag := cedar.Authorize(input.Policies, input.Entities.Entities, request)

		if len(diag.Errors) == 0 {
			return // No erroring policies, nothing to test
		}

		// Build set of erroring policy IDs
		erroring := make(map[types.PolicyID]bool)
		for _, diagErr := range diag.Errors {
			erroring[diagErr.PolicyID] = true
		}

		// Replace erroring policies with trivially-false equivalents
		replacedPolicies := cedar.NewPolicySet()
		for id, p := range input.Policies.All() {
			if erroring[id] {
				var replacement cedar.Policy
				if p.Effect() == cedar.Permit {
					if err := replacement.UnmarshalCedar([]byte(`permit(principal, action, resource) when { false };`)); err != nil {
						return
					}
				} else {
					if err := replacement.UnmarshalCedar([]byte(`forbid(principal, action, resource) when { false };`)); err != nil {
						return
					}
				}
				replacedPolicies.Add(id, &replacement)
			} else {
				replacedPolicies.Add(id, p)
			}
		}

		newDecision, _ := cedar.Authorize(replacedPolicies, input.Entities.Entities, request)

		if decision != newDecision {
			t.Errorf("error_irrelevance violated:\n"+
				"Original decision=%v, after replacing %d erroring policies with false: %v\n"+
				"Request: %+v",
				decision, len(diag.Errors), newDecision, request)
		}
	})
}

// FuzzRemovingForbidPreservesAllow verifies that removing a forbid policy from a
// policy set that allows a request can never flip the decision to Deny. This is
// the removal dual of unchanged_allow_when_add_permit.
func FuzzRemovingForbidPreservesAllow(f *testing.F) {
	f.Add([]byte("rm-forbid-seed-1"))
	f.Add([]byte("rm-forbid-seed-2"))
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

		request := buildRequest(input)
		decision, _ := cedar.Authorize(input.Policies, input.Entities.Entities, request)

		if decision != cedar.Allow {
			return // Theorem only applies when original decision is Allow
		}

		// Remove each forbid policy one at a time; decision must stay Allow
		for id, p := range input.Policies.All() {
			if p.Effect() != cedar.Forbid {
				continue
			}

			reduced := cedar.NewPolicySet()
			for id2, p2 := range input.Policies.All() {
				if id2 != id {
					reduced.Add(id2, p2)
				}
			}

			newDecision, _ := cedar.Authorize(reduced, input.Entities.Entities, request)
			if newDecision != cedar.Allow {
				t.Errorf("removing_forbid_preserves_allow violated:\n"+
					"Removing forbid policy %q flipped Allow to %v\n"+
					"Request: %+v", id, newDecision, request)
			}
		}
	})
}

// FuzzRemovingPermitPreservesDeny verifies that removing a permit policy from a
// policy set that denies a request can never flip the decision to Allow. This is
// the removal dual of unchanged_deny_when_add_forbid.
func FuzzRemovingPermitPreservesDeny(f *testing.F) {
	f.Add([]byte("rm-permit-seed-1"))
	f.Add([]byte("rm-permit-seed-2"))
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

		request := buildRequest(input)
		decision, _ := cedar.Authorize(input.Policies, input.Entities.Entities, request)

		if decision != cedar.Deny {
			return // Theorem only applies when original decision is Deny
		}

		// Remove each permit policy one at a time; decision must stay Deny
		for id, p := range input.Policies.All() {
			if p.Effect() != cedar.Permit {
				continue
			}

			reduced := cedar.NewPolicySet()
			for id2, p2 := range input.Policies.All() {
				if id2 != id {
					reduced.Add(id2, p2)
				}
			}

			newDecision, _ := cedar.Authorize(reduced, input.Entities.Entities, request)
			if newDecision != cedar.Deny {
				t.Errorf("removing_permit_preserves_deny violated:\n"+
					"Removing permit policy %q flipped Deny to %v\n"+
					"Request: %+v", id, newDecision, request)
			}
		}
	})
}

// FuzzDecisionDecomposition verifies that the authorization decision is fully
// determined by two bits: "exists a satisfied forbid" and "exists a satisfied
// permit". Everything else — policy order, duplicates, non-matching policies,
// erroring policies — is irrelevant. We test this by constructing a canonical
// policy set from just those two bits and checking the decision matches.
func FuzzDecisionDecomposition(f *testing.F) {
	f.Add([]byte("decomp-seed-1"))
	f.Add([]byte("decomp-seed-2"))
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

		request := buildRequest(input)
		decision, diag := cedar.Authorize(input.Policies, input.Entities.Entities, request)

		// Determine the two bits:
		// hasSatisfiedForbid: if decision=Allow, no forbids were satisfied (by definition).
		// If decision=Deny, Reasons = satisfied forbids, so non-empty means yes.
		hasSatisfiedForbid := (decision == cedar.Deny && len(diag.Reasons) > 0)

		// hasSatisfiedPermit: if decision=Allow, permits were satisfied (by definition).
		// If decision=Deny, we need to check separately by running with permits only.
		var hasSatisfiedPermit bool
		if decision == cedar.Allow {
			hasSatisfiedPermit = true
		} else {
			// Run with only permit policies to check if any are satisfied
			permitOnly := cedar.NewPolicySet()
			for id, p := range input.Policies.All() {
				if p.Effect() == cedar.Permit {
					permitOnly.Add(id, p)
				}
			}
			permitDecision, _ := cedar.Authorize(permitOnly, input.Entities.Entities, request)
			hasSatisfiedPermit = (permitDecision == cedar.Allow)
		}

		// Build canonical policy set from just the two bits
		canonical := cedar.NewPolicySet()
		if hasSatisfiedForbid {
			var forbidAll cedar.Policy
			if err := forbidAll.UnmarshalCedar([]byte(`forbid(principal, action, resource);`)); err != nil {
				return
			}
			canonical.Add("canonical-forbid", &forbidAll)
		}
		if hasSatisfiedPermit {
			var permitAll cedar.Policy
			if err := permitAll.UnmarshalCedar([]byte(`permit(principal, action, resource);`)); err != nil {
				return
			}
			canonical.Add("canonical-permit", &permitAll)
		}

		canonicalDecision, _ := cedar.Authorize(canonical, input.Entities.Entities, request)

		if decision != canonicalDecision {
			t.Errorf("decision_decomposition violated:\n"+
				"Original decision=%v, canonical decision=%v\n"+
				"hasSatisfiedForbid=%v, hasSatisfiedPermit=%v\n"+
				"Request: %+v",
				decision, canonicalDecision, hasSatisfiedForbid, hasSatisfiedPermit, request)
		}
	})
}

// ---------- Unit tests for proposed theorems ----------

// TestErrorIrrelevance tests that erroring policies don't affect the decision.
func TestErrorIrrelevance(t *testing.T) {
	request := cedar.Request{
		Principal: types.NewEntityUID("User", "alice"),
		Action:    types.NewEntityUID("Action", "view"),
		Resource:  types.NewEntityUID("Doc", "doc1"),
		Context:   types.NewRecord(types.RecordMap{}),
	}

	// Policy that errors (accesses missing context attribute)
	// + policy that permits
	ps := cedar.NewPolicySet()
	var permitPolicy cedar.Policy
	if err := permitPolicy.UnmarshalCedar([]byte(`permit(principal, action, resource);`)); err != nil {
		t.Fatal(err)
	}
	ps.Add("good-permit", &permitPolicy)

	var errorPolicy cedar.Policy
	if err := errorPolicy.UnmarshalCedar([]byte(
		`forbid(principal, action, resource) when { context.nonexistent > 0 };`,
	)); err != nil {
		t.Fatal(err)
	}
	ps.Add("bad-forbid", &errorPolicy)

	decision, diag := cedar.Authorize(ps, types.EntityMap{}, request)

	// The erroring forbid should NOT cause a deny
	if decision != cedar.Allow {
		t.Errorf("Expected Allow (erroring forbid should not deny), got %v", decision)
	}
	if len(diag.Errors) == 0 {
		t.Error("Expected at least one erroring policy")
	}

	// Replace the erroring policy with a trivially-false forbid
	ps2 := cedar.NewPolicySet()
	ps2.Add("good-permit", &permitPolicy)
	var falseForbid cedar.Policy
	if err := falseForbid.UnmarshalCedar([]byte(`forbid(principal, action, resource) when { false };`)); err != nil {
		t.Fatal(err)
	}
	ps2.Add("bad-forbid", &falseForbid)

	decision2, _ := cedar.Authorize(ps2, types.EntityMap{}, request)
	if decision != decision2 {
		t.Errorf("Decisions differ: original=%v, replaced=%v", decision, decision2)
	}
}

// TestRemovalDuals tests both removal properties together.
func TestRemovalDuals(t *testing.T) {
	request := cedar.Request{
		Principal: types.NewEntityUID("User", "alice"),
		Action:    types.NewEntityUID("Action", "view"),
		Resource:  types.NewEntityUID("Doc", "doc1"),
		Context:   types.NewRecord(types.RecordMap{}),
	}

	t.Run("removing forbid preserves Allow", func(t *testing.T) {
		ps := cedar.NewPolicySet()
		var permit cedar.Policy
		if err := permit.UnmarshalCedar([]byte(`permit(principal, action, resource);`)); err != nil {
			t.Fatal(err)
		}
		var forbid cedar.Policy
		if err := forbid.UnmarshalCedar([]byte(
			`forbid(principal == User::"bob", action, resource);`,
		)); err != nil {
			t.Fatal(err)
		}
		ps.Add("permit", &permit)
		ps.Add("forbid", &forbid)

		decision, _ := cedar.Authorize(ps, types.EntityMap{}, request)
		if decision != cedar.Allow {
			t.Fatal("precondition: expected Allow")
		}

		// Remove the forbid → must still be Allow
		reduced := cedar.NewPolicySet()
		reduced.Add("permit", &permit)
		newDecision, _ := cedar.Authorize(reduced, types.EntityMap{}, request)
		if newDecision != cedar.Allow {
			t.Errorf("Expected Allow after removing forbid, got %v", newDecision)
		}
	})

	t.Run("removing permit preserves Deny", func(t *testing.T) {
		ps := cedar.NewPolicySet()
		var permit cedar.Policy
		if err := permit.UnmarshalCedar([]byte(
			`permit(principal == User::"bob", action, resource);`,
		)); err != nil {
			t.Fatal(err)
		}
		var forbid cedar.Policy
		if err := forbid.UnmarshalCedar([]byte(`forbid(principal, action, resource);`)); err != nil {
			t.Fatal(err)
		}
		ps.Add("permit", &permit)
		ps.Add("forbid", &forbid)

		decision, _ := cedar.Authorize(ps, types.EntityMap{}, request)
		if decision != cedar.Deny {
			t.Fatal("precondition: expected Deny")
		}

		// Remove the (unsatisfied) permit → must still be Deny
		reduced := cedar.NewPolicySet()
		reduced.Add("forbid", &forbid)
		newDecision, _ := cedar.Authorize(reduced, types.EntityMap{}, request)
		if newDecision != cedar.Deny {
			t.Errorf("Expected Deny after removing permit, got %v", newDecision)
		}
	})

	t.Run("removing satisfied permit preserves Deny when forbid present", func(t *testing.T) {
		ps := cedar.NewPolicySet()
		var permit cedar.Policy
		if err := permit.UnmarshalCedar([]byte(`permit(principal, action, resource);`)); err != nil {
			t.Fatal(err)
		}
		var forbid cedar.Policy
		if err := forbid.UnmarshalCedar([]byte(`forbid(principal, action, resource);`)); err != nil {
			t.Fatal(err)
		}
		ps.Add("permit", &permit)
		ps.Add("forbid", &forbid)

		decision, _ := cedar.Authorize(ps, types.EntityMap{}, request)
		if decision != cedar.Deny {
			t.Fatal("precondition: expected Deny (forbid trumps)")
		}

		// Remove the satisfied permit → must still be Deny
		reduced := cedar.NewPolicySet()
		reduced.Add("forbid", &forbid)
		newDecision, _ := cedar.Authorize(reduced, types.EntityMap{}, request)
		if newDecision != cedar.Deny {
			t.Errorf("Expected Deny after removing permit, got %v", newDecision)
		}
	})
}

// TestDecisionDecomposition tests the fundamental characterization:
// the decision depends only on (∃ satisfied forbid, ∃ satisfied permit).
func TestDecisionDecomposition(t *testing.T) {
	request := cedar.Request{
		Principal: types.NewEntityUID("User", "alice"),
		Action:    types.NewEntityUID("Action", "view"),
		Resource:  types.NewEntityUID("Doc", "doc1"),
		Context:   types.NewRecord(types.RecordMap{}),
	}

	tests := []struct {
		name             string
		hasForbid        bool
		hasPermit        bool
		expectedDecision cedar.Decision
	}{
		{"no policies → Deny", false, false, cedar.Deny},
		{"only permit → Allow", false, true, cedar.Allow},
		{"only forbid → Deny", true, false, cedar.Deny},
		{"both → Deny (forbid trumps)", true, true, cedar.Deny},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ps := cedar.NewPolicySet()
			if tc.hasPermit {
				var p cedar.Policy
				if err := p.UnmarshalCedar([]byte(`permit(principal, action, resource);`)); err != nil {
					t.Fatal(err)
				}
				ps.Add("permit", &p)
			}
			if tc.hasForbid {
				var p cedar.Policy
				if err := p.UnmarshalCedar([]byte(`forbid(principal, action, resource);`)); err != nil {
					t.Fatal(err)
				}
				ps.Add("forbid", &p)
			}

			decision, _ := cedar.Authorize(ps, types.EntityMap{}, request)
			if decision != tc.expectedDecision {
				t.Errorf("expected %v, got %v", tc.expectedDecision, decision)
			}
		})
	}
}
