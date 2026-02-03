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

package corpus

import (
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/cedar-policy/cedar-go"

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/typegen"
)

// GenerateTypeDirectedCases generates random but well-typed test cases
// using the type-directed input generator. These cases provide better
// coverage than purely random fuzzing because they conform to valid
// Cedar schemas.
func GenerateTypeDirectedCases(count int, verbose bool) []TestCase {
	gen := typegen.TypeDirectedInputGenerator()
	var cases []TestCase

	for range count {
		// Generate random seed bytes
		seed := make([]byte, 256)
		if _, err := rand.Read(seed); err != nil {
			continue
		}

		input, err := gen.Generate(seed)
		if err != nil {
			continue
		}

		// Convert each request to a test case
		for _, req := range input.Requests {
			tc, err := typeDirectedInputToTestCase(input, req)
			if err != nil {
				continue
			}
			cases = append(cases, tc)
		}
	}

	if verbose {
		fmt.Printf("Generated %d type-directed test cases\n", len(cases))
	}
	return cases
}

// typeDirectedInputToTestCase converts a type-directed input to a corpus TestCase.
func typeDirectedInputToTestCase(input *typegen.TypeDirectedInput, req any) (TestCase, error) {
	// Marshal policies
	policiesBytes := input.Policies.MarshalCedar()

	// Marshal entities
	entitiesBytes, err := json.Marshal(input.Entities.Entities)
	if err != nil {
		return TestCase{}, err
	}

	// Convert cedar.Request to GoRequest format
	cedarReq, ok := req.(cedar.Request)
	if !ok {
		return TestCase{}, fmt.Errorf("expected cedar.Request, got %T", req)
	}

	goReq := GoRequest{
		Principal: EntityRef{
			Type: string(cedarReq.Principal.Type),
			ID:   string(cedarReq.Principal.ID),
		},
		Action: EntityRef{
			Type: string(cedarReq.Action.Type),
			ID:   string(cedarReq.Action.ID),
		},
		Resource: EntityRef{
			Type: string(cedarReq.Resource.Type),
			ID:   string(cedarReq.Resource.ID),
		},
		Context: json.RawMessage(`{}`),
	}

	// Marshal context if present
	if cedarReq.Context.Len() > 0 {
		ctxBytes, err := cedarReq.Context.MarshalJSON()
		if err == nil {
			goReq.Context = ctxBytes
		}
	}

	reqBytes, err := json.Marshal(goReq)
	if err != nil {
		return TestCase{}, err
	}

	return TestCase{
		Policies: []string{string(policiesBytes)},
		Entities: entitiesBytes,
		Request:  reqBytes,
	}, nil
}

// GenerateValidationCases generates type-directed validation test cases.
func GenerateValidationCases(count int, verbose bool) []ValidationTestCase {
	gen := typegen.TypeDirectedInputGenerator()
	var cases []ValidationTestCase

	for range count {
		seed := make([]byte, 256)
		if _, err := rand.Read(seed); err != nil {
			continue
		}

		input, err := gen.Generate(seed)
		if err != nil {
			continue
		}

		// Marshal policies
		policiesBytes := input.Policies.MarshalCedar()

		cases = append(cases, ValidationTestCase{
			Schema:   string(input.SchemaJSON),
			Policies: []string{string(policiesBytes)},
		})
	}

	if verbose {
		fmt.Printf("Generated %d type-directed validation test cases\n", len(cases))
	}
	return cases
}

// GenerateEdgeCases generates specific edge case test cases that cover
// boundary conditions and corner cases.
func GenerateEdgeCases() []TestCase {
	var cases []TestCase

	// Empty policy set
	cases = append(cases, TestCase{
		Policies: []string{},
		Entities: json.RawMessage(`[]`),
		Request: json.RawMessage(`{
			"principal": {"type": "User", "id": "alice"},
			"action": {"type": "Action", "id": "view"},
			"resource": {"type": "Resource", "id": "doc"},
			"context": {}
		}`),
	})

	// Forbid trumps permit
	cases = append(cases, TestCase{
		Policies: []string{
			`permit(principal, action, resource);`,
			`forbid(principal == User::"alice", action, resource);`,
		},
		Entities: json.RawMessage(`[]`),
		Request: json.RawMessage(`{
			"principal": {"type": "User", "id": "alice"},
			"action": {"type": "Action", "id": "view"},
			"resource": {"type": "Resource", "id": "doc"},
			"context": {}
		}`),
	})

	// Multiple matching policies
	cases = append(cases, TestCase{
		Policies: []string{
			`@id("p1") permit(principal, action, resource);`,
			`@id("p2") permit(principal == User::"alice", action, resource);`,
			`@id("p3") permit(principal, action == Action::"view", resource);`,
		},
		Entities: json.RawMessage(`[]`),
		Request: json.RawMessage(`{
			"principal": {"type": "User", "id": "alice"},
			"action": {"type": "Action", "id": "view"},
			"resource": {"type": "Resource", "id": "doc"},
			"context": {}
		}`),
	})

	// Entity hierarchy
	cases = append(cases, TestCase{
		Policies: []string{
			`permit(principal in Group::"admins", action, resource);`,
		},
		Entities: json.RawMessage(`[
			{"uid": {"type": "User", "id": "alice"}, "parents": [{"type": "Group", "id": "admins"}], "attrs": {}},
			{"uid": {"type": "Group", "id": "admins"}, "parents": [], "attrs": {}}
		]`),
		Request: json.RawMessage(`{
			"principal": {"type": "User", "id": "alice"},
			"action": {"type": "Action", "id": "view"},
			"resource": {"type": "Resource", "id": "doc"},
			"context": {}
		}`),
	})

	// Context attributes
	cases = append(cases, TestCase{
		Policies: []string{
			`permit(principal, action, resource) when { context.approved };`,
		},
		Entities: json.RawMessage(`[]`),
		Request: json.RawMessage(`{
			"principal": {"type": "User", "id": "alice"},
			"action": {"type": "Action", "id": "view"},
			"resource": {"type": "Resource", "id": "doc"},
			"context": {"approved": true}
		}`),
	})

	// Condition with attribute access
	cases = append(cases, TestCase{
		Policies: []string{
			`permit(principal, action, resource) when { principal.role == "admin" };`,
		},
		Entities: json.RawMessage(`[
			{"uid": {"type": "User", "id": "alice"}, "parents": [], "attrs": {"role": "admin"}}
		]`),
		Request: json.RawMessage(`{
			"principal": {"type": "User", "id": "alice"},
			"action": {"type": "Action", "id": "view"},
			"resource": {"type": "Resource", "id": "doc"},
			"context": {}
		}`),
	})

	// Resource in hierarchy
	cases = append(cases, TestCase{
		Policies: []string{
			`permit(principal, action, resource in Folder::"root");`,
		},
		Entities: json.RawMessage(`[
			{"uid": {"type": "File", "id": "doc1"}, "parents": [{"type": "Folder", "id": "root"}], "attrs": {}},
			{"uid": {"type": "Folder", "id": "root"}, "parents": [], "attrs": {}}
		]`),
		Request: json.RawMessage(`{
			"principal": {"type": "User", "id": "alice"},
			"action": {"type": "Action", "id": "view"},
			"resource": {"type": "File", "id": "doc1"},
			"context": {}
		}`),
	})

	// Action in set
	cases = append(cases, TestCase{
		Policies: []string{
			`permit(principal, action in [Action::"view", Action::"read"], resource);`,
		},
		Entities: json.RawMessage(`[]`),
		Request: json.RawMessage(`{
			"principal": {"type": "User", "id": "alice"},
			"action": {"type": "Action", "id": "view"},
			"resource": {"type": "Resource", "id": "doc"},
			"context": {}
		}`),
	})

	// Unless condition
	cases = append(cases, TestCase{
		Policies: []string{
			`permit(principal, action, resource) unless { context.blocked };`,
		},
		Entities: json.RawMessage(`[]`),
		Request: json.RawMessage(`{
			"principal": {"type": "User", "id": "alice"},
			"action": {"type": "Action", "id": "view"},
			"resource": {"type": "Resource", "id": "doc"},
			"context": {"blocked": false}
		}`),
	})

	// IP extension
	cases = append(cases, TestCase{
		Policies: []string{
			`permit(principal, action, resource) when { context.ip.isInRange(ip("10.0.0.0/8")) };`,
		},
		Entities: json.RawMessage(`[]`),
		Request: json.RawMessage(`{
			"principal": {"type": "User", "id": "alice"},
			"action": {"type": "Action", "id": "view"},
			"resource": {"type": "Resource", "id": "doc"},
			"context": {"ip": {"__extn": {"fn": "ip", "arg": "10.1.2.3"}}}
		}`),
	})

	// Decimal extension
	cases = append(cases, TestCase{
		Policies: []string{
			`permit(principal, action, resource) when { context.score > decimal("0.5") };`,
		},
		Entities: json.RawMessage(`[]`),
		Request: json.RawMessage(`{
			"principal": {"type": "User", "id": "alice"},
			"action": {"type": "Action", "id": "view"},
			"resource": {"type": "Resource", "id": "doc"},
			"context": {"score": {"__extn": {"fn": "decimal", "arg": "0.75"}}}
		}`),
	})

	// has operator
	cases = append(cases, TestCase{
		Policies: []string{
			`permit(principal, action, resource) when { principal has email && principal.email like "*@example.com" };`,
		},
		Entities: json.RawMessage(`[
			{"uid": {"type": "User", "id": "alice"}, "parents": [], "attrs": {"email": "alice@example.com"}}
		]`),
		Request: json.RawMessage(`{
			"principal": {"type": "User", "id": "alice"},
			"action": {"type": "Action", "id": "view"},
			"resource": {"type": "Resource", "id": "doc"},
			"context": {}
		}`),
	})

	// Set contains
	cases = append(cases, TestCase{
		Policies: []string{
			`permit(principal, action, resource) when { principal.tags.contains("vip") };`,
		},
		Entities: json.RawMessage(`[
			{"uid": {"type": "User", "id": "alice"}, "parents": [], "attrs": {"tags": ["vip", "premium"]}}
		]`),
		Request: json.RawMessage(`{
			"principal": {"type": "User", "id": "alice"},
			"action": {"type": "Action", "id": "view"},
			"resource": {"type": "Resource", "id": "doc"},
			"context": {}
		}`),
	})

	// Record access
	cases = append(cases, TestCase{
		Policies: []string{
			`permit(principal, action, resource) when { principal.profile["level"] > 5 };`,
		},
		Entities: json.RawMessage(`[
			{"uid": {"type": "User", "id": "alice"}, "parents": [], "attrs": {"profile": {"level": 10, "name": "Alice"}}}
		]`),
		Request: json.RawMessage(`{
			"principal": {"type": "User", "id": "alice"},
			"action": {"type": "Action", "id": "view"},
			"resource": {"type": "Resource", "id": "doc"},
			"context": {}
		}`),
	})

	// Deeply nested entities
	cases = append(cases, TestCase{
		Policies: []string{
			`permit(principal in Group::"level3", action, resource);`,
		},
		Entities: json.RawMessage(`[
			{"uid": {"type": "User", "id": "alice"}, "parents": [{"type": "Group", "id": "level1"}], "attrs": {}},
			{"uid": {"type": "Group", "id": "level1"}, "parents": [{"type": "Group", "id": "level2"}], "attrs": {}},
			{"uid": {"type": "Group", "id": "level2"}, "parents": [{"type": "Group", "id": "level3"}], "attrs": {}},
			{"uid": {"type": "Group", "id": "level3"}, "parents": [], "attrs": {}}
		]`),
		Request: json.RawMessage(`{
			"principal": {"type": "User", "id": "alice"},
			"action": {"type": "Action", "id": "view"},
			"resource": {"type": "Resource", "id": "doc"},
			"context": {}
		}`),
	})

	return cases
}
