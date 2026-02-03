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
	"context"
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/batch"

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/typegen"
)

type tpeTestContext struct {
	input   *typegen.TypeDirectedInput
	baseReq cedar.Request
}

type batchResults struct {
	allowed map[types.EntityUID]bool
	denied  map[types.EntityUID]bool
}

// FuzzTPEQueryPrincipal tests partial evaluation queries over principals.
// This verifies that batch evaluation with principal as a variable correctly
// identifies all principals that would be allowed.
//
// Property: For a given action, resource, and context, batch evaluation with
// principal as variable should return results consistent with individual
// authorization calls for each principal.
func FuzzTPEQueryPrincipal(f *testing.F) {
	f.Add([]byte("tpe-principal-seed-1"))
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 128))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		ctx, ok := prepareTPETestContext(data, inputGen)
		if !ok {
			return
		}
		testTPEQueryPrincipal(t, ctx)
	})
}

func prepareTPETestContext(data []byte, inputGen *typegen.InputGenerator) (*tpeTestContext, bool) {
	if len(data) < 32 {
		return nil, false
	}

	input, err := inputGen.GenerateForAuthorization(data)
	if err != nil || len(input.Requests) == 0 {
		return nil, false
	}

	return &tpeTestContext{
		input:   input,
		baseReq: input.Requests[0],
	}, true
}

func testTPEQueryPrincipal(t *testing.T, ctx *tpeTestContext) {
	principals := collectEntityUIDs(ctx.input.Entities.Entities)
	if len(principals) == 0 {
		return
	}

	batchReq := batch.Request{
		Principal: batch.Variable("principal"),
		Action:    ctx.baseReq.Action,
		Resource:  ctx.baseReq.Resource,
		Context:   ctx.baseReq.Context,
		Variables: batch.Variables{"principal": principals},
	}

	results := runBatchAuthorizePrincipal(ctx, batchReq)
	if results == nil {
		return
	}

	verifyPrincipalResults(t, ctx, results)
}

func collectEntityUIDs(entities types.EntityMap) []types.Value {
	var uids []types.Value
	for uid := range entities {
		uids = append(uids, uid)
	}
	return uids
}

func runBatchAuthorizePrincipal(ctx *tpeTestContext, batchReq batch.Request) *batchResults {
	results := &batchResults{
		allowed: make(map[types.EntityUID]bool),
		denied:  make(map[types.EntityUID]bool),
	}

	err := batch.Authorize(
		context.Background(),
		ctx.input.Policies,
		ctx.input.Entities.Entities,
		batchReq,
		func(result batch.Result) error {
			if result.Decision == types.Allow {
				results.allowed[result.Request.Principal] = true
			} else {
				results.denied[result.Request.Principal] = true
			}
			return nil
		},
	)
	if err != nil {
		return nil
	}
	return results
}

func verifyPrincipalResults(t *testing.T, ctx *tpeTestContext, results *batchResults) {
	for principal := range results.allowed {
		req := cedar.Request{
			Principal: principal,
			Action:    ctx.baseReq.Action,
			Resource:  ctx.baseReq.Resource,
			Context:   ctx.baseReq.Context,
		}
		decision, _ := cedar.Authorize(ctx.input.Policies, ctx.input.Entities.Entities, req)
		if decision != types.Allow {
			t.Errorf("Batch said Allow but Authorize said Deny for principal %v", principal)
		}
	}

	for principal := range results.denied {
		req := cedar.Request{
			Principal: principal,
			Action:    ctx.baseReq.Action,
			Resource:  ctx.baseReq.Resource,
			Context:   ctx.baseReq.Context,
		}
		decision, _ := cedar.Authorize(ctx.input.Policies, ctx.input.Entities.Entities, req)
		if decision != types.Deny {
			t.Errorf("Batch said Deny but Authorize said Allow for principal %v", principal)
		}
	}
}

// FuzzTPEQueryResource tests partial evaluation queries over resources.
// Similar to principal query but with resource as the variable.
func FuzzTPEQueryResource(f *testing.F) {
	f.Add([]byte("tpe-resource-seed-1"))
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 128))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		ctx, ok := prepareTPETestContext(data, inputGen)
		if !ok {
			return
		}
		testTPEQueryResource(t, ctx)
	})
}

func testTPEQueryResource(t *testing.T, ctx *tpeTestContext) {
	resources := collectEntityUIDs(ctx.input.Entities.Entities)
	if len(resources) == 0 {
		return
	}

	batchReq := batch.Request{
		Principal: ctx.baseReq.Principal,
		Action:    ctx.baseReq.Action,
		Resource:  batch.Variable("resource"),
		Context:   ctx.baseReq.Context,
		Variables: batch.Variables{"resource": resources},
	}

	results := runBatchAuthorizeResource(ctx, batchReq)
	if results == nil {
		return
	}

	verifyResourceResults(t, ctx, results)
}

func runBatchAuthorizeResource(ctx *tpeTestContext, batchReq batch.Request) *batchResults {
	results := &batchResults{
		allowed: make(map[types.EntityUID]bool),
		denied:  make(map[types.EntityUID]bool),
	}

	err := batch.Authorize(
		context.Background(),
		ctx.input.Policies,
		ctx.input.Entities.Entities,
		batchReq,
		func(result batch.Result) error {
			if result.Decision == types.Allow {
				results.allowed[result.Request.Resource] = true
			} else {
				results.denied[result.Request.Resource] = true
			}
			return nil
		},
	)
	if err != nil {
		return nil
	}
	return results
}

func verifyResourceResults(t *testing.T, ctx *tpeTestContext, results *batchResults) {
	for resource := range results.allowed {
		req := cedar.Request{
			Principal: ctx.baseReq.Principal,
			Action:    ctx.baseReq.Action,
			Resource:  resource,
			Context:   ctx.baseReq.Context,
		}
		decision, _ := cedar.Authorize(ctx.input.Policies, ctx.input.Entities.Entities, req)
		if decision != types.Allow {
			t.Errorf("Batch said Allow but IsAuthorized said Deny for resource %v", resource)
		}
	}

	for resource := range results.denied {
		req := cedar.Request{
			Principal: ctx.baseReq.Principal,
			Action:    ctx.baseReq.Action,
			Resource:  resource,
			Context:   ctx.baseReq.Context,
		}
		decision, _ := cedar.Authorize(ctx.input.Policies, ctx.input.Entities.Entities, req)
		if decision != types.Deny {
			t.Errorf("Batch said Deny but IsAuthorized said Allow for resource %v", resource)
		}
	}
}

// FuzzTPEQueryAction tests partial evaluation queries over actions.
// Tests that batch evaluation with action as variable is consistent.
func FuzzTPEQueryAction(f *testing.F) {
	f.Add([]byte("tpe-action-seed-1"))
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 128))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		ctx, ok := prepareTPETestContext(data, inputGen)
		if !ok {
			return
		}
		testTPEQueryAction(t, ctx)
	})
}

func testTPEQueryAction(t *testing.T, ctx *tpeTestContext) {
	actions := collectUniqueActions(ctx.input.Requests)
	if len(actions) == 0 {
		return
	}

	batchReq := batch.Request{
		Principal: ctx.baseReq.Principal,
		Action:    batch.Variable("action"),
		Resource:  ctx.baseReq.Resource,
		Context:   ctx.baseReq.Context,
		Variables: batch.Variables{"action": actions},
	}

	results := runBatchAuthorizeAction(ctx, batchReq)
	if results == nil {
		return
	}

	verifyActionResults(t, ctx, results)
}

func collectUniqueActions(requests []cedar.Request) []types.Value {
	actionSet := make(map[types.EntityUID]bool)
	for _, req := range requests {
		actionSet[req.Action] = true
	}

	var actions []types.Value
	for action := range actionSet {
		actions = append(actions, action)
	}
	return actions
}

func runBatchAuthorizeAction(ctx *tpeTestContext, batchReq batch.Request) *batchResults {
	results := &batchResults{
		allowed: make(map[types.EntityUID]bool),
		denied:  make(map[types.EntityUID]bool),
	}

	err := batch.Authorize(
		context.Background(),
		ctx.input.Policies,
		ctx.input.Entities.Entities,
		batchReq,
		func(result batch.Result) error {
			if result.Decision == types.Allow {
				results.allowed[result.Request.Action] = true
			} else {
				results.denied[result.Request.Action] = true
			}
			return nil
		},
	)
	if err != nil {
		return nil
	}
	return results
}

func verifyActionResults(t *testing.T, ctx *tpeTestContext, results *batchResults) {
	for action := range results.allowed {
		req := cedar.Request{
			Principal: ctx.baseReq.Principal,
			Action:    action,
			Resource:  ctx.baseReq.Resource,
			Context:   ctx.baseReq.Context,
		}
		decision, _ := cedar.Authorize(ctx.input.Policies, ctx.input.Entities.Entities, req)
		if decision != types.Allow {
			t.Errorf("Batch said Allow but IsAuthorized said Deny for action %v", action)
		}
	}

	for action := range results.denied {
		req := cedar.Request{
			Principal: ctx.baseReq.Principal,
			Action:    action,
			Resource:  ctx.baseReq.Resource,
			Context:   ctx.baseReq.Context,
		}
		decision, _ := cedar.Authorize(ctx.input.Policies, ctx.input.Entities.Entities, req)
		if decision != types.Deny {
			t.Errorf("Batch said Deny but IsAuthorized said Allow for action %v", action)
		}
	}
}

// TestTPEQueryPrincipalBasic tests basic TPE principal query scenarios.
func TestTPEQueryPrincipalBasic(t *testing.T) {
	policyStr := `permit(principal == User::"alice", action, resource);`

	policies, err := cedar.NewPolicySetFromBytes("test.cedar", []byte(policyStr))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	entities := make(types.EntityMap)

	// Create some test principals
	alice := types.NewEntityUID("User", "alice")
	bob := types.NewEntityUID("User", "bob")
	action := types.NewEntityUID("Action", "view")
	resource := types.NewEntityUID("Doc", "readme")

	principals := []types.Value{alice, bob}

	batchReq := batch.Request{
		Principal: batch.Variable("principal"),
		Action:    action,
		Resource:  resource,
		Context:   types.Record{},
		Variables: batch.Variables{
			"principal": principals,
		},
	}

	var results []batch.Result
	err = batch.Authorize(
		context.Background(),
		policies,
		entities,
		batchReq,
		func(result batch.Result) error {
			results = append(results, result)
			return nil
		},
	)
	if err != nil {
		t.Fatalf("Batch authorization failed: %v", err)
	}

	// Should have 2 results
	if len(results) != 2 {
		t.Fatalf("Expected 2 results, got %d", len(results))
	}

	// Alice should be allowed, Bob should be denied
	for _, result := range results {
		switch result.Request.Principal {
		case alice:
			if result.Decision != types.Allow {
				t.Errorf("Alice should be allowed, got %v", result.Decision)
			}
		case bob:
			if result.Decision != types.Deny {
				t.Errorf("Bob should be denied, got %v", result.Decision)
			}
		}
	}
}

// TestTPEQueryResourceBasic tests basic TPE resource query scenarios.
func TestTPEQueryResourceBasic(t *testing.T) {
	policyStr := `permit(principal, action, resource == Doc::"secret");`

	policies, err := cedar.NewPolicySetFromBytes("test.cedar", []byte(policyStr))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	entities := make(types.EntityMap)

	principal := types.NewEntityUID("User", "alice")
	action := types.NewEntityUID("Action", "view")
	secret := types.NewEntityUID("Doc", "secret")
	public := types.NewEntityUID("Doc", "public")

	resources := []types.Value{secret, public}

	batchReq := batch.Request{
		Principal: principal,
		Action:    action,
		Resource:  batch.Variable("resource"),
		Context:   types.Record{},
		Variables: batch.Variables{
			"resource": resources,
		},
	}

	var results []batch.Result
	err = batch.Authorize(
		context.Background(),
		policies,
		entities,
		batchReq,
		func(result batch.Result) error {
			results = append(results, result)
			return nil
		},
	)
	if err != nil {
		t.Fatalf("Batch authorization failed: %v", err)
	}

	// Should have 2 results
	if len(results) != 2 {
		t.Fatalf("Expected 2 results, got %d", len(results))
	}

	// secret should be allowed, public should be denied
	for _, result := range results {
		switch result.Request.Resource {
		case secret:
			if result.Decision != types.Allow {
				t.Errorf("secret should be allowed, got %v", result.Decision)
			}
		case public:
			if result.Decision != types.Deny {
				t.Errorf("public should be denied, got %v", result.Decision)
			}
		}
	}
}
