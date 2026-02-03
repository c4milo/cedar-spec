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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/comparison"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/lean"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/proto"
)

// FuzzInput represents the structure of fuzz input data
type FuzzInput struct {
	Policies []string        `json:"policies"`
	Entities json.RawMessage `json:"entities"`
	Request  json.RawMessage `json:"request"`
}

// parseFuzzInput parses the fuzz input into its components.
// Returns nil values if parsing fails (indicating the input should be skipped).
func parseFuzzInput(data []byte) (*cedar.PolicySet, types.EntityMap, cedar.Request, error) {
	var input FuzzInput
	if err := json.Unmarshal(data, &input); err != nil {
		return nil, nil, cedar.Request{}, err
	}

	policies := cedar.NewPolicySet()
	for i, policyStr := range input.Policies {
		var policy cedar.Policy
		if err := policy.UnmarshalCedar([]byte(policyStr)); err != nil {
			return nil, nil, cedar.Request{}, err
		}
		policies.Add(cedar.PolicyID(fmt.Sprintf("policy%d", i)), &policy)
	}

	var entities types.EntityMap
	if err := json.Unmarshal(input.Entities, &entities); err != nil {
		return nil, nil, cedar.Request{}, err
	}

	var request cedar.Request
	if err := json.Unmarshal(input.Request, &request); err != nil {
		return nil, nil, cedar.Request{}, err
	}

	return policies, entities, request, nil
}

// runLeanAuth runs Lean authorization and returns the result.
func runLeanAuth(t *testing.T, policies *cedar.PolicySet, entities types.EntityMap, request cedar.Request) *lean.AuthorizationResponse {
	t.Helper()

	authReq := proto.PolicySetFromCedar(policies, entities, &request)
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

// FuzzAuthorization is the main fuzz target for authorization testing.
// It compares cedar-go authorization results against the Lean formalization.
// hasEmptyEntityType checks if any EntityUID has an empty type.
// Empty entity types are rejected by Rust Cedar at parse time, so we skip them
// to avoid known divergences between implementations.
func hasEmptyEntityType(entities types.EntityMap, request cedar.Request) bool {
	// Check request entities
	if request.Principal.Type == "" || request.Action.Type == "" || request.Resource.Type == "" {
		return true
	}
	// Check entity map
	for uid := range entities {
		if uid.Type == "" {
			return true
		}
	}
	return false
}

func FuzzAuthorization(f *testing.F) {
	addAuthorizationSeeds(f)

	config := comparison.DefaultConfig()

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		policies, entities, request, err := parseFuzzInput(data)
		if err != nil {
			return // Invalid input, skip
		}

		// Skip inputs with empty entity types - these are rejected by production
		// Rust Cedar and cause known divergences between cedar-go and Lean.
		if hasEmptyEntityType(entities, request) {
			return
		}

		goDecision, goDiag := cedar.Authorize(policies, entities, request)

		leanResp := runLeanAuth(t, policies, entities, request)
		if leanResp == nil {
			return // Lean error, skip
		}

		goResult := toAuthorizationResult(goDecision, goDiag)
		leanResult := toLeanAuthorizationResult(leanResp)

		diffs := comparison.CompareAuthorization(goResult, leanResult, config)
		if len(diffs) > 0 {
			t.Errorf("Authorization divergence detected:\n%s\nInput: %s",
				comparison.FormatDifferences(diffs), string(data))
		}
	})
}

func addAuthorizationSeeds(f *testing.F) {
	// Add basic hardcoded seeds
	f.Add([]byte(`{
		"policies": ["permit(principal, action, resource);"],
		"entities": [],
		"request": {
			"principal": {"type": "User", "id": "alice"},
			"action": {"type": "Action", "id": "view"},
			"resource": {"type": "Document", "id": "doc1"},
			"context": {}
		}
	}`))

	f.Add([]byte(`{
		"policies": ["forbid(principal, action, resource);"],
		"entities": [],
		"request": {
			"principal": {"type": "User", "id": "bob"},
			"action": {"type": "Action", "id": "edit"},
			"resource": {"type": "Document", "id": "doc2"},
			"context": {}
		}
	}`))

	f.Add([]byte(`{
		"policies": [
			"permit(principal, action, resource) when { principal.role == \"admin\" };"
		],
		"entities": [
			{
				"uid": {"type": "User", "id": "admin"},
				"attrs": {"role": "admin"},
				"parents": []
			}
		],
		"request": {
			"principal": {"type": "User", "id": "admin"},
			"action": {"type": "Action", "id": "delete"},
			"resource": {"type": "Document", "id": "doc3"},
			"context": {}
		}
	}`))

	// Load corpus from testdata
	loadCorpusSeeds(f, "testdata/fuzz/FuzzAuthorization")
}

// loadCorpusSeeds loads all corpus files from a directory and adds them as seeds.
func loadCorpusSeeds(f *testing.F, corpusDir string) {
	entries, err := os.ReadDir(corpusDir)
	if err != nil {
		// Corpus directory may not exist yet, which is fine
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		path := filepath.Join(corpusDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		f.Add(data)
	}
}

func toAuthorizationResult(decision cedar.Decision, diag types.Diagnostic) *comparison.AuthorizationResult {
	return &comparison.AuthorizationResult{
		Decision:            decisionToString(decision),
		DeterminingPolicies: extractPolicyIDs(diag.Reasons),
		ErroringPolicies:    extractErrorPolicyIDs(diag.Errors),
	}
}

func toLeanAuthorizationResult(resp *lean.AuthorizationResponse) *comparison.AuthorizationResult {
	return &comparison.AuthorizationResult{
		Decision:            resp.Decision,
		DeterminingPolicies: resp.DeterminingPolicies,
		ErroringPolicies:    resp.ErroringPolicies,
	}
}

func decisionToString(d cedar.Decision) string {
	if d {
		return "allow"
	}
	return "deny"
}

// extractPolicyIDs extracts policy IDs from cedar-go diagnostic reasons
func extractPolicyIDs(reasons []types.DiagnosticReason) []string {
	ids := make([]string, 0, len(reasons))
	for _, r := range reasons {
		ids = append(ids, string(r.PolicyID))
	}
	return ids
}

// extractErrorPolicyIDs extracts policy IDs from cedar-go diagnostic errors
func extractErrorPolicyIDs(errors []types.DiagnosticError) []string {
	ids := make([]string, 0, len(errors))
	for _, e := range errors {
		ids = append(ids, string(e.PolicyID))
	}
	return ids
}

// TestAuthorizationBasic tests basic authorization scenarios
func TestAuthorizationBasic(t *testing.T) {
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
