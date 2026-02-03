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
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/typegen"
)

// FuzzEntitySlicing tests that authorization decisions are preserved when using
// a subset of entities that are "relevant" to a request.
//
// The key property: if we compute a slice of entities containing only the
// principal, resource, action, and their transitive ancestors, the authorization
// decision should be the same as with the full entity set.
//
// This is a simplified version of the Rust entity-slicing-drt target. Cedar-go
// doesn't have compute_entity_manifest yet, so we implement a basic slicing
// algorithm here.
func FuzzEntitySlicing(f *testing.F) {
	f.Add([]byte("entity-slicing-seed-1"))
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 128))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		input, ok := prepareEntitySlicingInput(data, inputGen)
		if !ok {
			return
		}

		for _, req := range input.Requests {
			verifyEntitySlicingForRequest(t, input, req)
		}
	})
}

func prepareEntitySlicingInput(data []byte, inputGen *typegen.InputGenerator) (*typegen.TypeDirectedInput, bool) {
	if len(data) < 32 {
		return nil, false
	}
	input, err := inputGen.GenerateForAuthorization(data)
	if err != nil {
		return nil, false
	}
	return input, true
}

func verifyEntitySlicingForRequest(t *testing.T, input *typegen.TypeDirectedInput, req cedar.Request) {
	fullDecision, fullDiag := cedar.Authorize(input.Policies, input.Entities.Entities, req)
	slice := computeEntitySlice(input.Entities.Entities, req)
	sliceDecision, sliceDiag := cedar.Authorize(input.Policies, slice, req)

	if fullDecision != sliceDecision {
		t.Errorf("Entity slicing changed authorization decision!\n"+
			"Full entities decision: %v\n"+
			"Sliced entities decision: %v\n"+
			"Request: %+v\n"+
			"Full entities count: %d\n"+
			"Sliced entities count: %d",
			fullDecision, sliceDecision, req,
			len(input.Entities.Entities), len(slice))
	}

	checkDeterminingPolicies(t, fullDecision, sliceDecision, fullDiag, sliceDiag)
}

func checkDeterminingPolicies(t *testing.T, fullDecision, sliceDecision cedar.Decision, fullDiag, sliceDiag types.Diagnostic) {
	if fullDecision == types.Allow && sliceDecision == types.Allow {
		if len(fullDiag.Reasons) != len(sliceDiag.Reasons) {
			t.Logf("Determining policy count differs: full=%d, slice=%d",
				len(fullDiag.Reasons), len(sliceDiag.Reasons))
		}
	}
}

// computeEntitySlice returns a subset of entities relevant to the given request.
// It includes the principal, action, resource, and all their ancestors.
func computeEntitySlice(entities types.EntityMap, req cedar.Request) types.EntityMap {
	slice := make(types.EntityMap)
	visited := make(map[types.EntityUID]bool)

	// Add entity and all its ancestors
	var addWithAncestors func(uid types.EntityUID)
	addWithAncestors = func(uid types.EntityUID) {
		if visited[uid] {
			return
		}
		visited[uid] = true

		entity, exists := entities[uid]
		if !exists {
			return
		}

		slice[uid] = entity

		// Add all parents
		for parent := range entity.Parents.All() {
			addWithAncestors(parent)
		}
	}

	// Add principal and its ancestors
	addWithAncestors(req.Principal)

	// Add action and its ancestors
	addWithAncestors(req.Action)

	// Add resource and its ancestors
	addWithAncestors(req.Resource)

	return slice
}

// FuzzEntitySlicingExtended tests entity slicing with attribute-based policies.
// This ensures that entities referenced in attributes are also included.
func FuzzEntitySlicingExtended(f *testing.F) {
	f.Add([]byte("entity-slicing-ext-seed-1"))
	f.Add(make([]byte, 64))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 32 {
			return
		}

		input, err := inputGen.GenerateForAuthorization(data)
		if err != nil {
			return
		}

		for _, req := range input.Requests {
			// Get authorization with full entities
			fullDecision, _ := cedar.Authorize(input.Policies, input.Entities.Entities, req)

			// Compute extended entity slice (includes attribute references)
			slice := computeExtendedEntitySlice(input.Entities.Entities, req)

			// Get authorization with sliced entities
			sliceDecision, _ := cedar.Authorize(input.Policies, slice, req)

			// Decisions must match
			if fullDecision != sliceDecision {
				t.Errorf("Extended entity slicing changed authorization decision!\n"+
					"Full: %v, Sliced: %v", fullDecision, sliceDecision)
			}
		}
	})
}

// computeExtendedEntitySlice computes a slice that also includes entities
// referenced in the attributes of included entities.
func computeExtendedEntitySlice(entities types.EntityMap, req cedar.Request) types.EntityMap {
	slice := make(types.EntityMap)
	visited := make(map[types.EntityUID]bool)
	queue := []types.EntityUID{req.Principal, req.Action, req.Resource}

	for len(queue) > 0 {
		uid := queue[0]
		queue = queue[1:]

		if visited[uid] {
			continue
		}
		visited[uid] = true

		entity, exists := entities[uid]
		if !exists {
			continue
		}

		slice[uid] = entity

		// Add parents to queue
		for parent := range entity.Parents.All() {
			if !visited[parent] {
				queue = append(queue, parent)
			}
		}

		// Add entity UIDs referenced in attributes
		for _, attrValue := range entity.Attributes.All() {
			collectEntityRefs(attrValue, &queue, visited)
		}
	}

	return slice
}

// collectEntityRefs recursively finds EntityUID values in a Cedar value.
func collectEntityRefs(v types.Value, queue *[]types.EntityUID, visited map[types.EntityUID]bool) {
	switch val := v.(type) {
	case types.EntityUID:
		if !visited[val] {
			*queue = append(*queue, val)
		}
	case types.Set:
		for elem := range val.All() {
			collectEntityRefs(elem, queue, visited)
		}
	case types.Record:
		for _, fieldVal := range val.All() {
			collectEntityRefs(fieldVal, queue, visited)
		}
	}
}

// TestEntitySlicingBasic tests basic entity slicing scenarios.
func TestEntitySlicingBasic(t *testing.T) {
	policyStr := `permit(principal, action, resource) when { principal in Group::"admins" };`

	policies, err := cedar.NewPolicySetFromBytes("test.cedar", []byte(policyStr))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	// Create entities with hierarchy
	alice := types.NewEntityUID("User", "alice")
	admins := types.NewEntityUID("Group", "admins")
	bob := types.NewEntityUID("User", "bob")
	users := types.NewEntityUID("Group", "users")
	action := types.NewEntityUID("Action", "view")
	doc := types.NewEntityUID("Doc", "readme")

	entities := types.EntityMap{
		alice: {
			UID:        alice,
			Parents:    types.NewEntityUIDSet(admins),
			Attributes: types.Record{},
		},
		admins: {
			UID:        admins,
			Parents:    types.NewEntityUIDSet(),
			Attributes: types.Record{},
		},
		bob: {
			UID:        bob,
			Parents:    types.NewEntityUIDSet(users),
			Attributes: types.Record{},
		},
		users: {
			UID:        users,
			Parents:    types.NewEntityUIDSet(),
			Attributes: types.Record{},
		},
	}

	// Test with Alice (in admins) - should be allowed
	aliceReq := cedar.Request{
		Principal: alice,
		Action:    action,
		Resource:  doc,
		Context:   types.Record{},
	}

	fullDecision, _ := cedar.Authorize(policies, entities, aliceReq)
	slice := computeEntitySlice(entities, aliceReq)
	sliceDecision, _ := cedar.Authorize(policies, slice, aliceReq)

	if fullDecision != sliceDecision {
		t.Errorf("Alice: full=%v, slice=%v", fullDecision, sliceDecision)
	}
	if fullDecision != types.Allow {
		t.Errorf("Alice should be allowed, got %v", fullDecision)
	}

	// Verify slice contains alice and admins, but not bob or users
	if _, ok := slice[alice]; !ok {
		t.Error("Slice should contain alice")
	}
	if _, ok := slice[admins]; !ok {
		t.Error("Slice should contain admins")
	}
	if _, ok := slice[bob]; ok {
		t.Error("Slice should not contain bob")
	}

	// Test with Bob (not in admins) - should be denied
	bobReq := cedar.Request{
		Principal: bob,
		Action:    action,
		Resource:  doc,
		Context:   types.Record{},
	}

	fullDecision, _ = cedar.Authorize(policies, entities, bobReq)
	slice = computeEntitySlice(entities, bobReq)
	sliceDecision, _ = cedar.Authorize(policies, slice, bobReq)

	if fullDecision != sliceDecision {
		t.Errorf("Bob: full=%v, slice=%v", fullDecision, sliceDecision)
	}
	if fullDecision != types.Deny {
		t.Errorf("Bob should be denied, got %v", fullDecision)
	}
}

// TestEntitySlicingWithAttributes tests slicing with attribute-based policies.
func TestEntitySlicingWithAttributes(t *testing.T) {
	policyStr := `permit(principal, action, resource) when { principal.manager == User::"boss" };`

	policies, err := cedar.NewPolicySetFromBytes("test.cedar", []byte(policyStr))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	alice := types.NewEntityUID("User", "alice")
	boss := types.NewEntityUID("User", "boss")
	action := types.NewEntityUID("Action", "view")
	doc := types.NewEntityUID("Doc", "readme")

	entities := types.EntityMap{
		alice: {
			UID:     alice,
			Parents: types.NewEntityUIDSet(),
			Attributes: types.NewRecord(types.RecordMap{
				"manager": boss,
			}),
		},
		boss: {
			UID:        boss,
			Parents:    types.NewEntityUIDSet(),
			Attributes: types.Record{},
		},
	}

	req := cedar.Request{
		Principal: alice,
		Action:    action,
		Resource:  doc,
		Context:   types.Record{},
	}

	fullDecision, _ := cedar.Authorize(policies, entities, req)

	// Basic slice won't include boss (not an ancestor)
	basicSlice := computeEntitySlice(entities, req)

	// Extended slice should include boss (referenced in attribute)
	extendedSlice := computeExtendedEntitySlice(entities, req)

	if _, ok := basicSlice[boss]; ok {
		t.Log("Basic slice unexpectedly contains boss")
	}

	if _, ok := extendedSlice[boss]; !ok {
		t.Error("Extended slice should contain boss (referenced in attribute)")
	}

	extendedDecision, _ := cedar.Authorize(policies, extendedSlice, req)
	if fullDecision != extendedDecision {
		t.Errorf("Extended slice decision differs: full=%v, extended=%v", fullDecision, extendedDecision)
	}
}
