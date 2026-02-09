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

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/comparison"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/typegen"
)

// multiVarResult holds a concrete batch result for multi-variable queries.
type multiVarResult struct {
	principal types.EntityUID
	action    types.EntityUID
	resource  types.EntityUID
	context   types.Record
	decision  types.Decision
}

// FuzzTPEQueryMultiVariable tests batch evaluation with principal, action, and
// resource all as variables simultaneously. Each concrete (P, A, R, C) tuple
// produced by the batch API is verified against lean.IsAuthorized.
func FuzzTPEQueryMultiVariable(f *testing.F) {
	f.Add([]byte("tpe-multi-seed-1"))
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 128))

	inputGen := typegen.TypeDirectedInputGenerator()
	config := comparison.ComparisonConfig{
		ErrorMode:             comparison.ErrorComparisonModeIgnore,
		IgnoreDecisionOnError: true,
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		ctx, ok := prepareTPETestContext(data, inputGen)
		if !ok {
			return
		}
		testTPEQueryMultiVariable(t, ctx, config)
	})
}

func testTPEQueryMultiVariable(t *testing.T, ctx *tpeTestContext, config comparison.ComparisonConfig) {
	principals := limitSlice(collectEntityUIDs(ctx.input.Entities.Entities), 3)
	actions := limitSlice(collectUniqueActions(ctx.input.Requests), 3)
	resources := limitSlice(collectEntityUIDs(ctx.input.Entities.Entities), 3)

	if len(principals) == 0 || len(actions) == 0 || len(resources) == 0 {
		return
	}

	batchReq := batch.Request{
		Principal: batch.Variable("principal"),
		Action:    batch.Variable("action"),
		Resource:  batch.Variable("resource"),
		Context:   ctx.baseReq.Context,
		Variables: batch.Variables{
			"principal": principals,
			"action":    actions,
			"resource":  resources,
		},
	}

	results := runBatchAuthorizeMultiVar(ctx, batchReq)
	if results == nil {
		return
	}

	verifyMultiVarResultsWithLean(t, ctx, results, config)
}

func runBatchAuthorizeMultiVar(ctx *tpeTestContext, batchReq batch.Request) []multiVarResult {
	var results []multiVarResult

	err := batch.Authorize(
		context.Background(),
		ctx.input.Policies,
		ctx.input.Entities.Entities,
		batchReq,
		func(result batch.Result) error {
			results = append(results, multiVarResult{
				principal: result.Request.Principal,
				action:    result.Request.Action,
				resource:  result.Request.Resource,
				context:   result.Request.Context,
				decision:  result.Decision,
			})
			return nil
		},
	)
	if err != nil {
		return nil
	}
	return results
}

func verifyMultiVarResultsWithLean(t *testing.T, ctx *tpeTestContext, results []multiVarResult, config comparison.ComparisonConfig) {
	for _, r := range results {
		req := cedar.Request{
			Principal: r.principal,
			Action:    r.action,
			Resource:  r.resource,
			Context:   r.context,
		}

		leanResp := runBatchLeanAuth(t, ctx.input.Policies, ctx.input.Entities.Entities, req)
		if leanResp == nil {
			continue
		}

		goDecision, goDiag := cedar.Authorize(ctx.input.Policies, ctx.input.Entities.Entities, req)
		goResult := toAuthorizationResult(goDecision, goDiag)
		leanResult := toLeanAuthorizationResult(leanResp)

		diffs := comparison.CompareAuthorization(goResult, leanResult, config)
		if len(diffs) > 0 {
			t.Errorf("MultiVar batch vs Lean mismatch for P=%v A=%v R=%v:\n%s\nBatch decision: %v, Lean decision: %s",
				r.principal, r.action, r.resource,
				comparison.FormatDifferences(diffs), r.decision, leanResp.Decision)
		}

		// Also verify batch decision matches cedar-go individual decision
		if cedar.Decision(r.decision) != goDecision {
			t.Errorf("MultiVar batch vs individual mismatch for P=%v A=%v R=%v: batch=%v individual=%v",
				r.principal, r.action, r.resource, r.decision, goDecision)
		}
	}
}

// FuzzTPEQueryContext tests batch evaluation with the entire context as a
// variable. Distinct contexts are collected from the generated requests.
// Each concrete result is verified against lean.IsAuthorized.
func FuzzTPEQueryContext(f *testing.F) {
	f.Add([]byte("tpe-context-seed-1"))
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 128))

	inputGen := typegen.TypeDirectedInputGenerator()
	config := comparison.ComparisonConfig{
		ErrorMode:             comparison.ErrorComparisonModeIgnore,
		IgnoreDecisionOnError: true,
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		ctx, ok := prepareTPETestContext(data, inputGen)
		if !ok {
			return
		}
		testTPEQueryContext(t, ctx, config)
	})
}

func testTPEQueryContext(t *testing.T, ctx *tpeTestContext, config comparison.ComparisonConfig) {
	contexts := collectDistinctContexts(ctx.input.Requests)
	if len(contexts) == 0 {
		return
	}

	batchReq := batch.Request{
		Principal: ctx.baseReq.Principal,
		Action:    ctx.baseReq.Action,
		Resource:  ctx.baseReq.Resource,
		Context:   batch.Variable("context"),
		Variables: batch.Variables{"context": contexts},
	}

	results := runBatchAuthorizeContext(ctx, batchReq)
	if results == nil {
		return
	}

	verifyContextResultsWithLean(t, ctx, results, config)
}

// contextResult holds a concrete batch result for context-variable queries.
type contextResult struct {
	context  types.Record
	decision types.Decision
}

func collectDistinctContexts(requests []cedar.Request) []types.Value {
	// Use string serialization for deduplication since Record is not comparable.
	seen := make(map[string]bool)
	var contexts []types.Value

	for _, req := range requests {
		key := req.Context.String()
		if !seen[key] {
			seen[key] = true
			contexts = append(contexts, req.Context)
		}
	}

	return limitSlice(contexts, 5)
}

func runBatchAuthorizeContext(ctx *tpeTestContext, batchReq batch.Request) []contextResult {
	var results []contextResult

	err := batch.Authorize(
		context.Background(),
		ctx.input.Policies,
		ctx.input.Entities.Entities,
		batchReq,
		func(result batch.Result) error {
			results = append(results, contextResult{
				context:  result.Request.Context,
				decision: result.Decision,
			})
			return nil
		},
	)
	if err != nil {
		return nil
	}
	return results
}

func verifyContextResultsWithLean(t *testing.T, ctx *tpeTestContext, results []contextResult, config comparison.ComparisonConfig) {
	for _, r := range results {
		req := cedar.Request{
			Principal: ctx.baseReq.Principal,
			Action:    ctx.baseReq.Action,
			Resource:  ctx.baseReq.Resource,
			Context:   r.context,
		}

		leanResp := runBatchLeanAuth(t, ctx.input.Policies, ctx.input.Entities.Entities, req)
		if leanResp == nil {
			continue
		}

		goDecision, goDiag := cedar.Authorize(ctx.input.Policies, ctx.input.Entities.Entities, req)
		goResult := toAuthorizationResult(goDecision, goDiag)
		leanResult := toLeanAuthorizationResult(leanResp)

		diffs := comparison.CompareAuthorization(goResult, leanResult, config)
		if len(diffs) > 0 {
			t.Errorf("Context batch vs Lean mismatch for context=%v:\n%s\nBatch decision: %v, Lean decision: %s",
				r.context, comparison.FormatDifferences(diffs), r.decision, leanResp.Decision)
		}

		if cedar.Decision(r.decision) != goDecision {
			t.Errorf("Context batch vs individual mismatch for context=%v: batch=%v individual=%v",
				r.context, r.decision, goDecision)
		}
	}
}

// FuzzTPEQueryContextField tests batch evaluation with a single context
// attribute replaced by a variable. Multiple Long values are substituted
// for the chosen attribute. Each concrete result is verified against
// lean.IsAuthorized.
func FuzzTPEQueryContextField(f *testing.F) {
	f.Add([]byte("tpe-ctxfield-seed-1"))
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 128))

	inputGen := typegen.TypeDirectedInputGenerator()
	config := comparison.ComparisonConfig{
		ErrorMode:             comparison.ErrorComparisonModeIgnore,
		IgnoreDecisionOnError: true,
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		ctx, ok := prepareTPETestContext(data, inputGen)
		if !ok {
			return
		}
		testTPEQueryContextField(t, ctx, config)
	})
}

// ctxFieldResult holds a concrete batch result for context-field-variable queries.
type ctxFieldResult struct {
	context  types.Record
	decision types.Decision
}

func testTPEQueryContextField(t *testing.T, ctx *tpeTestContext, config comparison.ComparisonConfig) {
	// Pick the first attribute from the base request's context.
	attrName := firstRecordKey(ctx.baseReq.Context)
	if attrName == "" {
		return
	}

	// Build substitute values: a range of Long values.
	substitutes := []types.Value{
		types.Long(-1),
		types.Long(0),
		types.Long(1),
		types.Long(42),
		types.Long(9999),
	}

	// Build a context record where the chosen attribute is a batch variable.
	ctxWithVar := replaceRecordField(ctx.baseReq.Context, attrName)

	batchReq := batch.Request{
		Principal: ctx.baseReq.Principal,
		Action:    ctx.baseReq.Action,
		Resource:  ctx.baseReq.Resource,
		Context:   ctxWithVar,
		Variables: batch.Variables{"ctxvar": substitutes},
	}

	results := runBatchAuthorizeContextField(ctx, batchReq)
	if results == nil {
		return
	}

	verifyContextFieldResultsWithLean(t, ctx, results, config)
}

// firstRecordKey returns the first key from a Record, or "" if empty.
func firstRecordKey(r types.Record) string {
	for key := range r.All() {
		return string(key)
	}
	return ""
}

// replaceRecordField returns a new Record with the named field replaced
// by batch.Variable("ctxvar") and all other fields copied.
func replaceRecordField(r types.Record, fieldName string) types.Record {
	rm := types.RecordMap{}
	for key, val := range r.All() {
		if string(key) == fieldName {
			rm[key] = batch.Variable("ctxvar")
		} else {
			rm[key] = val
		}
	}
	return types.NewRecord(rm)
}

func runBatchAuthorizeContextField(ctx *tpeTestContext, batchReq batch.Request) []ctxFieldResult {
	var results []ctxFieldResult

	err := batch.Authorize(
		context.Background(),
		ctx.input.Policies,
		ctx.input.Entities.Entities,
		batchReq,
		func(result batch.Result) error {
			results = append(results, ctxFieldResult{
				context:  result.Request.Context,
				decision: result.Decision,
			})
			return nil
		},
	)
	if err != nil {
		return nil
	}
	return results
}

func verifyContextFieldResultsWithLean(t *testing.T, ctx *tpeTestContext, results []ctxFieldResult, config comparison.ComparisonConfig) {
	for _, r := range results {
		req := cedar.Request{
			Principal: ctx.baseReq.Principal,
			Action:    ctx.baseReq.Action,
			Resource:  ctx.baseReq.Resource,
			Context:   r.context,
		}

		leanResp := runBatchLeanAuth(t, ctx.input.Policies, ctx.input.Entities.Entities, req)
		if leanResp == nil {
			continue
		}

		goDecision, goDiag := cedar.Authorize(ctx.input.Policies, ctx.input.Entities.Entities, req)
		goResult := toAuthorizationResult(goDecision, goDiag)
		leanResult := toLeanAuthorizationResult(leanResp)

		diffs := comparison.CompareAuthorization(goResult, leanResult, config)
		if len(diffs) > 0 {
			t.Errorf("ContextField batch vs Lean mismatch for context=%v:\n%s\nBatch decision: %v, Lean decision: %s",
				r.context, comparison.FormatDifferences(diffs), r.decision, leanResp.Decision)
		}

		if cedar.Decision(r.decision) != goDecision {
			t.Errorf("ContextField batch vs individual mismatch for context=%v: batch=%v individual=%v",
				r.context, r.decision, goDecision)
		}
	}
}

// TestTPEQueryMultiVariableBasic tests basic multi-variable batch query scenarios.
func TestTPEQueryMultiVariableBasic(t *testing.T) {
	policyStr := `permit(principal == User::"alice", action == Action::"view", resource == Doc::"readme");`

	policies, err := cedar.NewPolicySetFromBytes("test.cedar", []byte(policyStr))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	entities := make(types.EntityMap)

	alice := types.NewEntityUID("User", "alice")
	bob := types.NewEntityUID("User", "bob")
	view := types.NewEntityUID("Action", "view")
	edit := types.NewEntityUID("Action", "edit")
	readme := types.NewEntityUID("Doc", "readme")
	secret := types.NewEntityUID("Doc", "secret")

	batchReq := batch.Request{
		Principal: batch.Variable("principal"),
		Action:    batch.Variable("action"),
		Resource:  batch.Variable("resource"),
		Context:   types.Record{},
		Variables: batch.Variables{
			"principal": []types.Value{alice, bob},
			"action":    []types.Value{view, edit},
			"resource":  []types.Value{readme, secret},
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

	// Should have 2*2*2 = 8 results
	if len(results) != 8 {
		t.Fatalf("Expected 8 results, got %d", len(results))
	}

	// Only (alice, view, readme) should be allowed
	for _, result := range results {
		isAliceViewReadme := result.Request.Principal == alice &&
			result.Request.Action == view &&
			result.Request.Resource == readme
		if isAliceViewReadme {
			if result.Decision != types.Allow {
				t.Errorf("Expected Allow for (alice, view, readme), got %v", result.Decision)
			}
		} else {
			if result.Decision != types.Deny {
				t.Errorf("Expected Deny for (%v, %v, %v), got %v",
					result.Request.Principal, result.Request.Action, result.Request.Resource, result.Decision)
			}
		}
	}
}

// TestTPEQueryContextBasic tests basic context-variable batch query scenarios.
func TestTPEQueryContextBasic(t *testing.T) {
	policyStr := `permit(principal, action, resource) when { context.level > 5 };`

	policies, err := cedar.NewPolicySetFromBytes("test.cedar", []byte(policyStr))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	entities := make(types.EntityMap)
	principal := types.NewEntityUID("User", "alice")
	action := types.NewEntityUID("Action", "view")
	resource := types.NewEntityUID("Doc", "readme")

	highCtx := types.NewRecord(types.RecordMap{"level": types.Long(10)})
	lowCtx := types.NewRecord(types.RecordMap{"level": types.Long(3)})

	batchReq := batch.Request{
		Principal: principal,
		Action:    action,
		Resource:  resource,
		Context:   batch.Variable("context"),
		Variables: batch.Variables{
			"context": []types.Value{highCtx, lowCtx},
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

	if len(results) != 2 {
		t.Fatalf("Expected 2 results, got %d", len(results))
	}

	for _, result := range results {
		// Verify against individual evaluation
		req := cedar.Request{
			Principal: principal,
			Action:    action,
			Resource:  resource,
			Context:   result.Request.Context,
		}
		individual, _ := cedar.Authorize(policies, entities, req)
		if cedar.Decision(result.Decision) != individual {
			t.Errorf("Batch vs individual mismatch for context=%v: batch=%v individual=%v",
				result.Request.Context, result.Decision, individual)
		}
	}
}

// TestTPEQueryContextFieldBasic tests basic context-field-variable batch query scenarios.
func TestTPEQueryContextFieldBasic(t *testing.T) {
	policyStr := `permit(principal, action, resource) when { context.level > 5 };`

	policies, err := cedar.NewPolicySetFromBytes("test.cedar", []byte(policyStr))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	entities := make(types.EntityMap)
	principal := types.NewEntityUID("User", "alice")
	action := types.NewEntityUID("Action", "view")
	resource := types.NewEntityUID("Doc", "readme")

	batchReq := batch.Request{
		Principal: principal,
		Action:    action,
		Resource:  resource,
		Context: types.NewRecord(types.RecordMap{
			"level": batch.Variable("ctxvar"),
		}),
		Variables: batch.Variables{
			"ctxvar": []types.Value{types.Long(1), types.Long(10)},
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

	if len(results) != 2 {
		t.Fatalf("Expected 2 results, got %d", len(results))
	}

	for _, result := range results {
		req := cedar.Request{
			Principal: principal,
			Action:    action,
			Resource:  resource,
			Context:   result.Request.Context,
		}
		individual, _ := cedar.Authorize(policies, entities, req)
		if cedar.Decision(result.Decision) != individual {
			t.Errorf("Batch vs individual mismatch for context=%v: batch=%v individual=%v",
				result.Request.Context, result.Decision, individual)
		}
	}
}
