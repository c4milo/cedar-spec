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

package comparison_test

import (
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
)

// TestCedarGoAuthorization tests cedar-go authorization in isolation.
// These tests verify cedar-go works correctly without needing Lean.
func TestCedarGoAuthorization(t *testing.T) {
	tests := []struct {
		name     string
		policy   string
		request  cedar.Request
		entities types.EntityMap
		expected cedar.Decision
	}{
		{
			name:   "permit all",
			policy: "permit(principal, action, resource);",
			request: cedar.Request{
				Principal: types.NewEntityUID("User", "alice"),
				Action:    types.NewEntityUID("Action", "view"),
				Resource:  types.NewEntityUID("Document", "doc1"),
			},
			entities: types.EntityMap{},
			expected: cedar.Allow,
		},
		{
			name:   "forbid all",
			policy: "forbid(principal, action, resource);",
			request: cedar.Request{
				Principal: types.NewEntityUID("User", "alice"),
				Action:    types.NewEntityUID("Action", "view"),
				Resource:  types.NewEntityUID("Document", "doc1"),
			},
			entities: types.EntityMap{},
			expected: cedar.Deny,
		},
		{
			name:   "no matching policy denies",
			policy: `permit(principal == User::"bob", action, resource);`,
			request: cedar.Request{
				Principal: types.NewEntityUID("User", "alice"),
				Action:    types.NewEntityUID("Action", "view"),
				Resource:  types.NewEntityUID("Document", "doc1"),
			},
			entities: types.EntityMap{},
			expected: cedar.Deny,
		},
		{
			name:   "condition when true",
			policy: `permit(principal, action, resource) when { 1 == 1 };`,
			request: cedar.Request{
				Principal: types.NewEntityUID("User", "alice"),
				Action:    types.NewEntityUID("Action", "view"),
				Resource:  types.NewEntityUID("Document", "doc1"),
			},
			entities: types.EntityMap{},
			expected: cedar.Allow,
		},
		{
			name:   "condition when false",
			policy: `permit(principal, action, resource) when { 1 == 2 };`,
			request: cedar.Request{
				Principal: types.NewEntityUID("User", "alice"),
				Action:    types.NewEntityUID("Action", "view"),
				Resource:  types.NewEntityUID("Document", "doc1"),
			},
			entities: types.EntityMap{},
			expected: cedar.Deny,
		},
		{
			name:   "condition unless true",
			policy: `permit(principal, action, resource) unless { 1 == 1 };`,
			request: cedar.Request{
				Principal: types.NewEntityUID("User", "alice"),
				Action:    types.NewEntityUID("Action", "view"),
				Resource:  types.NewEntityUID("Document", "doc1"),
			},
			entities: types.EntityMap{},
			expected: cedar.Deny,
		},
		{
			name:   "condition unless false",
			policy: `permit(principal, action, resource) unless { 1 == 2 };`,
			request: cedar.Request{
				Principal: types.NewEntityUID("User", "alice"),
				Action:    types.NewEntityUID("Action", "view"),
				Resource:  types.NewEntityUID("Document", "doc1"),
			},
			entities: types.EntityMap{},
			expected: cedar.Allow,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policies := cedar.NewPolicySet()
			var policy cedar.Policy
			if err := policy.UnmarshalCedar([]byte(tc.policy)); err != nil {
				t.Fatalf("Failed to parse policy: %v", err)
			}
			policies.Add("test", &policy)

			decision, _ := cedar.Authorize(policies, tc.entities, tc.request)
			if decision != tc.expected {
				t.Errorf("Expected %v, got %v", tc.expected, decision)
			}
		})
	}
}

// TestCedarGoForbidTrumpsPermit tests that forbid policies override permit policies.
func TestCedarGoForbidTrumpsPermit(t *testing.T) {
	policies := cedar.NewPolicySet()

	var permit cedar.Policy
	if err := permit.UnmarshalCedar([]byte("permit(principal, action, resource);")); err != nil {
		t.Fatalf("Failed to parse permit policy: %v", err)
	}
	policies.Add("permit", &permit)

	var forbid cedar.Policy
	if err := forbid.UnmarshalCedar([]byte("forbid(principal, action, resource);")); err != nil {
		t.Fatalf("Failed to parse forbid policy: %v", err)
	}
	policies.Add("forbid", &forbid)

	request := cedar.Request{
		Principal: types.NewEntityUID("User", "alice"),
		Action:    types.NewEntityUID("Action", "view"),
		Resource:  types.NewEntityUID("Document", "doc1"),
	}

	decision, _ := cedar.Authorize(policies, types.EntityMap{}, request)
	if decision != cedar.Deny {
		t.Errorf("Expected Deny (forbid trumps permit), got %v", decision)
	}
}

// TestCedarGoPolicyParsing tests cedar-go policy parsing.
func TestCedarGoPolicyParsing(t *testing.T) {
	validPolicies := []string{
		"permit(principal, action, resource);",
		"forbid(principal, action, resource);",
		`permit(principal == User::"alice", action, resource);`,
		`permit(principal, action == Action::"view", resource);`,
		`permit(principal, action, resource == Document::"doc1");`,
		`permit(principal, action, resource) when { true };`,
		`permit(principal, action, resource) unless { false };`,
		`permit(principal in Group::"admins", action, resource);`,
	}

	for _, policyStr := range validPolicies {
		t.Run(policyStr, func(t *testing.T) {
			var policy cedar.Policy
			if err := policy.UnmarshalCedar([]byte(policyStr)); err != nil {
				t.Errorf("Expected valid policy, got error: %v", err)
			}
		})
	}
}

// TestCedarGoEntities tests cedar-go entity handling.
func TestCedarGoEntities(t *testing.T) {
	policy := `permit(principal, action, resource) when { principal.role == "admin" };`

	var p cedar.Policy
	if err := p.UnmarshalCedar([]byte(policy)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	policies := cedar.NewPolicySet()
	policies.Add("test", &p)

	// Entity with admin role
	entities := types.EntityMap{
		types.NewEntityUID("User", "alice"): {
			UID:     types.NewEntityUID("User", "alice"),
			Attributes:   types.NewRecord(types.RecordMap{"role": types.String("admin")}),
			Parents: types.NewEntityUIDSet(),
		},
	}

	request := cedar.Request{
		Principal: types.NewEntityUID("User", "alice"),
		Action:    types.NewEntityUID("Action", "view"),
		Resource:  types.NewEntityUID("Document", "doc1"),
	}

	decision, _ := cedar.Authorize(policies, entities, request)
	if decision != cedar.Allow {
		t.Errorf("Expected Allow for admin user, got %v", decision)
	}

	// Entity without admin role
	entities[types.NewEntityUID("User", "alice")] = types.Entity{
		UID:     types.NewEntityUID("User", "alice"),
		Attributes:   types.NewRecord(types.RecordMap{"role": types.String("user")}),
		Parents: types.NewEntityUIDSet(),
	}

	decision, _ = cedar.Authorize(policies, entities, request)
	if decision != cedar.Deny {
		t.Errorf("Expected Deny for non-admin user, got %v", decision)
	}
}
