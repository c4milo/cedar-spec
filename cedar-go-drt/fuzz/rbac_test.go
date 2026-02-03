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
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/typegen"
)

// FuzzRBAC tests role-based access control scenarios with role hierarchies.
// This compares cedar-go against Lean for RBAC-style policies where:
// - Users belong to groups/roles via entity hierarchy
// - Policies grant permissions to roles
// - Authorization checks role membership via 'in' operator
func FuzzRBAC(f *testing.F) {
	// Add seeds
	f.Add([]byte("rbac-seed-1"))
	f.Add([]byte("rbac-seed-2"))
	f.Add(make([]byte, 128))

	inputGen := typegen.TypeDirectedInputGenerator()
	config := comparison.DefaultConfig()

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 32 {
			return
		}

		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		// Generate RBAC-style input
		input, err := inputGen.Generate(data)
		if err != nil {
			return
		}

		if input.Policies == nil || len(input.Entities.AllUIDs) == 0 {
			return
		}

		// Create RBAC-style policies that use role hierarchies
		rbacPolicies := generateRBACPolicies(input)
		if rbacPolicies == nil {
			return
		}

		// Pick a request from generated requests
		if len(input.Requests) == 0 {
			return
		}
		req := input.Requests[0]

		// Run cedar-go authorization
		goDecision, goDiag := cedar.Authorize(rbacPolicies, input.Entities.Entities, req)

		// Run Lean authorization
		leanResp := runRBACLeanAuth(t, rbacPolicies, input.Entities.Entities, req)
		if leanResp == nil {
			return
		}

		// Compare results
		goResult := toAuthorizationResult(goDecision, goDiag)
		leanResult := toLeanAuthorizationResult(leanResp)

		diffs := comparison.CompareAuthorization(goResult, leanResult, config)
		if len(diffs) > 0 {
			t.Errorf("RBAC authorization divergence:\n%s\nRequest: %+v",
				comparison.FormatDifferences(diffs), req)
		}
	})
}

// runRBACLeanAuth runs Lean authorization for RBAC tests.
func runRBACLeanAuth(t *testing.T, policies *cedar.PolicySet, entities types.EntityMap, req cedar.Request) *lean.AuthorizationResponse {
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

// generateRBACPolicies creates policies that leverage role hierarchies.
// These policies use the 'in' operator to check group membership.
func generateRBACPolicies(input *typegen.TypeDirectedInput) *cedar.PolicySet {
	if len(input.Schema.ActionList) == 0 || len(input.Entities.PrincipalUIDs) == 0 {
		return nil
	}

	ps := cedar.NewPolicySet()
	policyIdx := 0

	policyIdx = addGroupMembershipPolicy(ps, input, policyIdx)
	policyIdx = addPrincipalActionPolicy(ps, input, policyIdx)
	addResourceRestrictionPolicy(ps, input, policyIdx)
	addGeneratedPolicies(ps, input)

	return ps
}

func addGroupMembershipPolicy(ps *cedar.PolicySet, input *typegen.TypeDirectedInput, policyIdx int) int {
	groupUID, found := findPrincipalGroup(input)
	if !found {
		return policyIdx
	}

	policyStr := fmt.Sprintf(`permit(principal in %s::"%s", action, resource);`, groupUID.Type, groupUID.ID)
	if addPolicyFromString(ps, policyStr, policyIdx) {
		return policyIdx + 1
	}
	return policyIdx
}

func findPrincipalGroup(input *typegen.TypeDirectedInput) (types.EntityUID, bool) {
	for _, uid := range input.Entities.PrincipalUIDs {
		entity, ok := input.Entities.Entities[uid]
		if !ok {
			continue
		}
		for parent := range entity.Parents.All() {
			return parent, true
		}
	}
	return types.EntityUID{}, false
}

func addPrincipalActionPolicy(ps *cedar.PolicySet, input *typegen.TypeDirectedInput, policyIdx int) int {
	if len(input.Schema.ActionList) == 0 || len(input.Entities.PrincipalUIDs) == 0 {
		return policyIdx
	}

	action := input.Schema.ActionList[0]
	principal := input.Entities.PrincipalUIDs[0]
	policyStr := fmt.Sprintf(`permit(principal == %s::"%s", action == Action::"%s", resource);`,
		principal.Type, principal.ID, action)

	if addPolicyFromString(ps, policyStr, policyIdx) {
		return policyIdx + 1
	}
	return policyIdx
}

func addResourceRestrictionPolicy(ps *cedar.PolicySet, input *typegen.TypeDirectedInput, policyIdx int) {
	if len(input.Entities.ResourceUIDs) == 0 {
		return
	}

	uid := input.Entities.ResourceUIDs[0]
	entity, ok := input.Entities.Entities[uid]
	if !ok {
		return
	}

	for parent := range entity.Parents.All() {
		policyStr := fmt.Sprintf(`forbid(principal, action, resource in %s::"%s");`, parent.Type, parent.ID)
		addPolicyFromString(ps, policyStr, policyIdx)
		break
	}
}

func addPolicyFromString(ps *cedar.PolicySet, policyStr string, policyIdx int) bool {
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(policyStr)); err != nil {
		return false
	}
	ps.Add(cedar.PolicyID(fmt.Sprintf("policy%d", policyIdx)), &policy)
	return true
}

func addGeneratedPolicies(ps *cedar.PolicySet, input *typegen.TypeDirectedInput) {
	for id, policy := range input.Policies.All() {
		ps.Add(id, policy)
	}
}

// TestRBACBasic is a basic unit test for RBAC authorization patterns.
func TestRBACBasic(t *testing.T) {
	// Create a role hierarchy: alice -> admins -> users
	entities := types.EntityMap{
		types.EntityUID{Type: "User", ID: "alice"}: types.Entity{
			Parents: types.NewEntityUIDSet(
				types.EntityUID{Type: "Group", ID: "admins"},
			),
		},
		types.EntityUID{Type: "Group", ID: "admins"}: types.Entity{
			Parents: types.NewEntityUIDSet(
				types.EntityUID{Type: "Group", ID: "users"},
			),
		},
		types.EntityUID{Type: "Group", ID: "users"}: types.Entity{},
		types.EntityUID{Type: "Doc", ID: "doc1"}:    types.Entity{},
	}

	// Policy: users group can read
	ps := cedar.NewPolicySet()
	var policy cedar.Policy
	err := policy.UnmarshalCedar([]byte(`permit(principal in Group::"users", action == Action::"read", resource);`))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	ps.Add("users-read", &policy)

	// Test: alice should be able to read (she's in admins, which is in users)
	req := cedar.Request{
		Principal: types.EntityUID{Type: "User", ID: "alice"},
		Action:    types.EntityUID{Type: "Action", ID: "read"},
		Resource:  types.EntityUID{Type: "Doc", ID: "doc1"},
		Context:   types.NewRecord(types.RecordMap{}),
	}

	decision, _ := cedar.Authorize(ps, entities, req)
	if decision != cedar.Allow {
		t.Errorf("Expected Allow for alice reading doc1 (via group membership), got %v", decision)
	}

	// Test: alice should not be able to write (no permit for write)
	reqWrite := cedar.Request{
		Principal: types.EntityUID{Type: "User", ID: "alice"},
		Action:    types.EntityUID{Type: "Action", ID: "write"},
		Resource:  types.EntityUID{Type: "Doc", ID: "doc1"},
		Context:   types.NewRecord(types.RecordMap{}),
	}

	decision, _ = cedar.Authorize(ps, entities, reqWrite)
	if decision != cedar.Deny {
		t.Errorf("Expected Deny for alice writing doc1, got %v", decision)
	}
}

// TestRBACForbidTrumpsPermit tests that forbid policies override permit in RBAC context.
func TestRBACForbidTrumpsPermit(t *testing.T) {
	entities := types.EntityMap{
		types.EntityUID{Type: "User", ID: "alice"}: types.Entity{
			Parents: types.NewEntityUIDSet(
				types.EntityUID{Type: "Group", ID: "editors"},
				types.EntityUID{Type: "Group", ID: "restricted"},
			),
		},
		types.EntityUID{Type: "Group", ID: "editors"}:    types.Entity{},
		types.EntityUID{Type: "Group", ID: "restricted"}: types.Entity{},
		types.EntityUID{Type: "Doc", ID: "secret"}:       types.Entity{},
	}

	ps := cedar.NewPolicySet()

	// Permit editors to edit
	var permitPolicy cedar.Policy
	err := permitPolicy.UnmarshalCedar([]byte(`permit(principal in Group::"editors", action == Action::"edit", resource);`))
	if err != nil {
		t.Fatalf("Failed to parse permit policy: %v", err)
	}
	ps.Add("editors-edit", &permitPolicy)

	// Forbid restricted users from editing secret docs
	var forbidPolicy cedar.Policy
	err = forbidPolicy.UnmarshalCedar([]byte(`forbid(principal in Group::"restricted", action == Action::"edit", resource == Doc::"secret");`))
	if err != nil {
		t.Fatalf("Failed to parse forbid policy: %v", err)
	}
	ps.Add("restricted-forbid", &forbidPolicy)

	// Alice is in both groups - forbid should win
	req := cedar.Request{
		Principal: types.EntityUID{Type: "User", ID: "alice"},
		Action:    types.EntityUID{Type: "Action", ID: "edit"},
		Resource:  types.EntityUID{Type: "Doc", ID: "secret"},
		Context:   types.NewRecord(types.RecordMap{}),
	}

	decision, _ := cedar.Authorize(ps, entities, req)
	if decision != cedar.Deny {
		t.Errorf("Expected Deny (forbid trumps permit), got %v", decision)
	}
}
