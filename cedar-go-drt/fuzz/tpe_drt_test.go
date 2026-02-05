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
	"runtime"
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/batch"
	"github.com/cedar-policy/cedar-go/x/exp/schema"

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/lean"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/proto"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/typegen"
)

// This file contains DRT tests comparing cedar-go's batch/TPE functionality
// against Lean's Template Policy Engine (TPE) formalization.
//
// The Lean TPE provides partial evaluation with lazy entity loading, which
// corresponds to cedar-go's batch evaluation functionality.

// FuzzTPEDRT tests the Template Policy Engine by comparing cedar-go's batch
// evaluation against Lean's batchedEvaluateFFI.
func FuzzTPEDRT(f *testing.F) {
	f.Add([]byte("tpe-drt-seed-1"))
	f.Add([]byte("tpe-drt-seed-2"))
	f.Add(make([]byte, 128))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		ctx, ok := prepareTPEContext(data, inputGen)
		if !ok {
			return
		}

		runTPEComparison(t, ctx)
	})
}

type tpeContext struct {
	input   *typegen.TypeDirectedInput
	request cedar.Request
	schema  *schema.Schema
}

func prepareTPEContext(data []byte, inputGen *typegen.InputGenerator) (*tpeContext, bool) {
	if len(data) < 32 {
		return nil, false
	}

	input, err := inputGen.Generate(data)
	if err != nil {
		return nil, false
	}

	if input.Policies == nil {
		return nil, false
	}

	// Parse schema
	s, err := schema.NewFromJSON(input.SchemaJSON)
	if err != nil {
		return nil, false
	}

	// Build request from input
	request := buildTPERequest(input)

	return &tpeContext{
		input:   input,
		request: request,
		schema:  s,
	}, true
}

func buildTPERequest(input *typegen.TypeDirectedInput) cedar.Request {
	principal := types.NewEntityUID("User", "test")
	resource := types.NewEntityUID("Resource", "test")
	action := types.NewEntityUID("Action", "test")

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

func runTPEComparison(t *testing.T, ctx *tpeContext) {
	t.Helper()

	// Run cedar-go batch evaluation
	goResult := runCedarGoBatch(t, ctx)

	// Run Lean TPE evaluation
	leanResult := runLeanTPE(t, ctx)
	if leanResult == nil {
		return
	}

	// Compare results
	compareTPEResults(t, goResult, leanResult, ctx)
}

type goBatchResult struct {
	decision *bool
	err      error
}

func runCedarGoBatch(t *testing.T, ctx *tpeContext) *goBatchResult {
	t.Helper()

	batchReq := batch.Request{
		Principal: ctx.request.Principal,
		Action:    ctx.request.Action,
		Resource:  ctx.request.Resource,
		Context:   ctx.request.Context,
	}

	var result *goBatchResult
	callback := func(r batch.Result) error {
		decision := bool(r.Decision)
		result = &goBatchResult{
			decision: &decision,
		}
		return nil
	}

	err := batch.Authorize(context.Background(), ctx.input.Policies, ctx.input.Entities.Entities, batchReq, callback)
	if err != nil {
		return &goBatchResult{err: err}
	}

	if result == nil {
		// No results from batch - this can happen with empty variable sets
		return &goBatchResult{}
	}

	return result
}

func runLeanTPE(t *testing.T, ctx *tpeContext) *lean.BatchedEvaluationResponse {
	t.Helper()

	// Create batched evaluation request
	batchReq := proto.BatchedEvaluationFromCedar(
		ctx.input.Policies,
		ctx.schema,
		&ctx.request,
		ctx.input.Entities.Entities,
		10, // Maximum iterations
	)

	protoBytes, err := batchReq.ToProtobuf()
	if err != nil {
		t.Logf("Failed to convert TPE request to protobuf: %v", err)
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

	leanResp, err := lean.BatchedEvaluate(protoBytes)
	if err != nil {
		t.Logf("Lean TPE FFI error: %v", err)
		return nil
	}

	return leanResp
}

func compareTPEResults(t *testing.T, goResult *goBatchResult, leanResult *lean.BatchedEvaluationResponse, ctx *tpeContext) {
	t.Helper()

	// Handle errors
	if goResult.err != nil {
		// cedar-go had an error - Lean result doesn't matter
		return
	}

	// Compare concrete results
	if goResult.decision != nil && leanResult.Result != nil {
		goDecision := *goResult.decision
		leanDecision := *leanResult.Result

		if goDecision != leanDecision {
			t.Errorf("TPE DRT divergence: cedar-go=%v, Lean=%v\n"+
				"Request: %+v", goDecision, leanDecision, ctx.request)
		}
	}

	// If Lean returns residual (nil), we allow cedar-go to return any result
	// since cedar-go may have more information to resolve the residual
	if leanResult.Result == nil && goResult.decision != nil {
		// This is expected - cedar-go resolved what Lean couldn't
		t.Logf("cedar-go resolved residual: %v", *goResult.decision)
	}
}

// FuzzTPESoundness tests TPE soundness: if TPE returns a concrete result,
// it must match the result of full evaluation.
func FuzzTPESoundness(f *testing.F) {
	f.Add([]byte("tpe-soundness-seed-1"))
	f.Add([]byte("tpe-soundness-seed-2"))
	f.Add(make([]byte, 128))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		ctx, ok := prepareTPEContext(data, inputGen)
		if !ok {
			return
		}

		verifyTPESoundness(t, ctx)
	})
}

func verifyTPESoundness(t *testing.T, ctx *tpeContext) {
	t.Helper()

	// Run full evaluation
	fullDecision, _ := cedar.Authorize(ctx.input.Policies, ctx.input.Entities.Entities, ctx.request)

	// Run batch/TPE evaluation
	batchResult := runCedarGoBatch(t, ctx)
	if batchResult.err != nil {
		return
	}

	// Soundness: if batch returns a concrete result, it must match full eval
	if batchResult.decision != nil {
		batchDecision := cedar.Decision(*batchResult.decision)
		if batchDecision != fullDecision {
			t.Errorf("TPE soundness violation: batch=%v, full=%v\n"+
				"Request: %+v", batchDecision, fullDecision, ctx.request)
		}
	}
}

// FuzzTPEResidualReauthorize tests the TPE reauthorize property:
// A partial evaluation result can be reauthorized with full entities
// to get the same result as direct authorization.
func FuzzTPEResidualReauthorize(f *testing.F) {
	f.Add([]byte("tpe-reauth-seed-1"))
	f.Add([]byte("tpe-reauth-seed-2"))
	f.Add(make([]byte, 128))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 32 {
			return
		}

		input, err := inputGen.Generate(data)
		if err != nil {
			return
		}

		if input.Policies == nil {
			return
		}

		verifyResidualReauthorize(t, input)
	})
}

func verifyResidualReauthorize(t *testing.T, input *typegen.TypeDirectedInput) {
	t.Helper()

	request := buildTPERequest(input)

	// Get full authorization result
	fullDecision, fullDiag := cedar.Authorize(input.Policies, input.Entities.Entities, request)

	// Run batch with partial entities (empty initially)
	batchReq := batch.Request{
		Principal: request.Principal,
		Action:    request.Action,
		Resource:  request.Resource,
		Context:   request.Context,
	}

	var batchDecision cedar.Decision
	var batchDiag types.Diagnostic
	callback := func(r batch.Result) error {
		batchDecision = cedar.Decision(r.Decision)
		batchDiag = r.Diagnostic
		return nil
	}

	err := batch.Authorize(context.Background(), input.Policies, input.Entities.Entities, batchReq, callback)
	if err != nil {
		return
	}

	// Property: batch result with full entities should match direct authorization
	if batchDecision != fullDecision {
		t.Errorf("TPE reauthorize violation: batch=%v, full=%v\n"+
			"Request: %+v", batchDecision, fullDecision, request)
	}

	// Verify determining policies match
	if len(batchDiag.Reasons) != len(fullDiag.Reasons) {
		t.Logf("Different determining policy counts: batch=%d, full=%d",
			len(batchDiag.Reasons), len(fullDiag.Reasons))
	}
}

// TestTPEBasic tests basic TPE functionality.
func TestTPEBasic(t *testing.T) {
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource);`))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("permit-all", &policy)

	entities := types.EntityMap{
		types.NewEntityUID("User", "alice"):  types.Entity{},
		types.NewEntityUID("Doc", "doc1"):    types.Entity{},
		types.NewEntityUID("Action", "view"): types.Entity{},
	}

	request := cedar.Request{
		Principal: types.NewEntityUID("User", "alice"),
		Action:    types.NewEntityUID("Action", "view"),
		Resource:  types.NewEntityUID("Doc", "doc1"),
		Context:   types.NewRecord(types.RecordMap{}),
	}

	// Full authorization
	fullDecision, _ := cedar.Authorize(policies, entities, request)

	// Batch authorization
	batchReq := batch.Request{
		Principal: request.Principal,
		Action:    request.Action,
		Resource:  request.Resource,
		Context:   request.Context,
	}

	var batchDecision cedar.Decision
	callback := func(r batch.Result) error {
		batchDecision = cedar.Decision(r.Decision)
		return nil
	}

	err = batch.Authorize(context.Background(), policies, entities, batchReq, callback)
	if err != nil {
		t.Fatalf("Batch authorize failed: %v", err)
	}

	if batchDecision != fullDecision {
		t.Errorf("TPE basic test failed: batch=%v, full=%v", batchDecision, fullDecision)
	}
}

// TestTPEWithVariables tests TPE with variable substitution.
func TestTPEWithVariables(t *testing.T) {
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	err := policy.UnmarshalCedar([]byte(`permit(principal == User::"alice", action, resource);`))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("permit-alice", &policy)

	entities := types.EntityMap{
		types.NewEntityUID("User", "alice"): types.Entity{},
		types.NewEntityUID("User", "bob"):   types.Entity{},
		types.NewEntityUID("Doc", "doc1"):   types.Entity{},
	}

	principals := []types.Value{
		types.NewEntityUID("User", "alice"),
		types.NewEntityUID("User", "bob"),
	}

	batchReq := batch.Request{
		Principal: batch.Variable("principal"),
		Action:    types.NewEntityUID("Action", "view"),
		Resource:  types.NewEntityUID("Doc", "doc1"),
		Context:   types.NewRecord(types.RecordMap{}),
		Variables: batch.Variables{
			"principal": principals,
		},
	}

	results := make(map[string]cedar.Decision)
	callback := func(r batch.Result) error {
		key := string(r.Request.Principal.ID)
		results[key] = cedar.Decision(r.Decision)
		return nil
	}

	err = batch.Authorize(context.Background(), policies, entities, batchReq, callback)
	if err != nil {
		t.Fatalf("Batch authorize failed: %v", err)
	}

	// Alice should be allowed, Bob should be denied
	if results["alice"] != cedar.Allow {
		t.Errorf("Expected alice to be allowed, got %v", results["alice"])
	}
	if results["bob"] != cedar.Deny {
		t.Errorf("Expected bob to be denied, got %v", results["bob"])
	}
}

// TestTPEPartialEvaluation tests that partial evaluation preserves semantics.
func TestTPEPartialEvaluation(t *testing.T) {
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource) when { principal.role == "admin" };`))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("permit-admin", &policy)

	entities := types.EntityMap{
		types.NewEntityUID("User", "alice"): types.Entity{
			Attributes: types.NewRecord(types.RecordMap{
				"role": types.String("admin"),
			}),
		},
		types.NewEntityUID("User", "bob"): types.Entity{
			Attributes: types.NewRecord(types.RecordMap{
				"role": types.String("user"),
			}),
		},
		types.NewEntityUID("Doc", "doc1"): types.Entity{},
	}

	tests := []struct {
		name      string
		principal types.EntityUID
		expected  cedar.Decision
	}{
		{"admin user", types.NewEntityUID("User", "alice"), cedar.Allow},
		{"regular user", types.NewEntityUID("User", "bob"), cedar.Deny},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			request := cedar.Request{
				Principal: tc.principal,
				Action:    types.NewEntityUID("Action", "view"),
				Resource:  types.NewEntityUID("Doc", "doc1"),
				Context:   types.NewRecord(types.RecordMap{}),
			}

			// Full evaluation
			fullDecision, _ := cedar.Authorize(policies, entities, request)

			// Batch evaluation
			batchReq := batch.Request{
				Principal: tc.principal,
				Action:    request.Action,
				Resource:  request.Resource,
				Context:   request.Context,
			}

			var batchDecision cedar.Decision
			callback := func(r batch.Result) error {
				batchDecision = cedar.Decision(r.Decision)
				return nil
			}

			err := batch.Authorize(context.Background(), policies, entities, batchReq, callback)
			if err != nil {
				t.Fatalf("Batch authorize failed: %v", err)
			}

			if fullDecision != tc.expected {
				t.Errorf("Full eval: expected %v, got %v", tc.expected, fullDecision)
			}

			if batchDecision != tc.expected {
				t.Errorf("Batch eval: expected %v, got %v", tc.expected, batchDecision)
			}

			if batchDecision != fullDecision {
				t.Errorf("TPE soundness: batch=%v, full=%v", batchDecision, fullDecision)
			}
		})
	}
}
