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

// batchTestContext holds the data needed for batch evaluation testing.
type batchTestContext struct {
	input      *typegen.TypeDirectedInput
	principals []types.EntityUID
	resources  []types.EntityUID
	action     types.EntityUID
}

// FuzzBatchedEvaluation tests batch evaluation against individual evaluations.
// This is a property-based test that verifies batch evaluation produces the
// same results as evaluating each request individually.
func FuzzBatchedEvaluation(f *testing.F) {
	f.Add([]byte("batch-seed-1"))
	f.Add([]byte("batch-seed-2"))
	f.Add(make([]byte, 128))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		ctx, ok := prepareBatchTestContext(data, inputGen)
		if !ok {
			return
		}
		runBatchComparisonTest(t, ctx)
	})
}

func prepareBatchTestContext(data []byte, inputGen *typegen.InputGenerator) (*batchTestContext, bool) {
	if len(data) < 32 {
		return nil, false
	}

	input, err := inputGen.Generate(data)
	if err != nil {
		return nil, false
	}

	if input.Policies == nil || len(input.Entities.AllUIDs) == 0 {
		return nil, false
	}

	principals := limitSlice(input.Entities.PrincipalUIDs, 3)
	resources := limitSlice(input.Entities.ResourceUIDs, 3)

	if len(principals) == 0 || len(resources) == 0 {
		return nil, false
	}

	if len(input.Schema.ActionList) == 0 {
		return nil, false
	}

	actionName := input.Schema.ActionList[0]
	action := types.EntityUID{Type: "Action", ID: types.String(actionName)}

	return &batchTestContext{
		input:      input,
		principals: principals,
		resources:  resources,
		action:     action,
	}, true
}

func runBatchComparisonTest(t *testing.T, ctx *batchTestContext) {
	batchResults, err := runBatchEvaluation(ctx)
	if err != nil {
		return // Some errors are expected for invalid inputs
	}

	compareWithIndividualResults(t, ctx, batchResults)
}

func runBatchEvaluation(ctx *batchTestContext) (map[string]cedar.Decision, error) {
	principalValues := make([]types.Value, len(ctx.principals))
	for i, p := range ctx.principals {
		principalValues[i] = p
	}

	resourceValues := make([]types.Value, len(ctx.resources))
	for i, r := range ctx.resources {
		resourceValues[i] = r
	}

	batchReq := batch.Request{
		Principal: batch.Variable("principal"),
		Action:    ctx.action,
		Resource:  batch.Variable("resource"),
		Context:   types.NewRecord(types.RecordMap{}),
		Variables: batch.Variables{
			"principal": principalValues,
			"resource":  resourceValues,
		},
	}

	batchResults := make(map[string]cedar.Decision)
	callback := func(r batch.Result) error {
		key := requestKey(r.Request.Principal, r.Request.Resource)
		batchResults[key] = cedar.Decision(r.Decision)
		return nil
	}

	err := batch.Authorize(context.Background(), ctx.input.Policies, ctx.input.Entities.Entities, batchReq, callback)
	return batchResults, err
}

func compareWithIndividualResults(t *testing.T, ctx *batchTestContext, batchResults map[string]cedar.Decision) {
	for _, principal := range ctx.principals {
		for _, resource := range ctx.resources {
			compareOneResult(t, ctx, batchResults, principal, resource)
		}
	}
}

func compareOneResult(t *testing.T, ctx *batchTestContext, batchResults map[string]cedar.Decision, principal, resource types.EntityUID) {
	req := cedar.Request{
		Principal: principal,
		Action:    ctx.action,
		Resource:  resource,
		Context:   types.NewRecord(types.RecordMap{}),
	}

	individualDecision, _ := cedar.Authorize(ctx.input.Policies, ctx.input.Entities.Entities, req)

	key := requestKey(principal, resource)
	batchDecision, ok := batchResults[key]

	if !ok {
		t.Errorf("Missing batch result for %s", key)
		return
	}

	if batchDecision != individualDecision {
		t.Errorf("Batch/individual mismatch for %s: batch=%v individual=%v",
			key, batchDecision, individualDecision)
	}
}

func requestKey(principal, resource types.EntityUID) string {
	return string(principal.Type) + "::" + string(principal.ID) + "|" +
		string(resource.Type) + "::" + string(resource.ID)
}

func limitSlice[T any](s []T, max int) []T {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

// TestBatchEvaluationBasic is a basic unit test for batch evaluation.
func TestBatchEvaluationBasic(t *testing.T) {
	ps := cedar.NewPolicySet()
	var policy cedar.Policy
	err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource);`))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	ps.Add("policy0", &policy)

	entities := types.EntityMap{
		types.EntityUID{Type: "User", ID: "alice"}: types.Entity{},
		types.EntityUID{Type: "Doc", ID: "doc1"}:   types.Entity{},
	}

	batchReq := batch.Request{
		Principal: batch.Variable("principal"),
		Action:    types.EntityUID{Type: "Action", ID: "view"},
		Resource:  batch.Variable("resource"),
		Context:   types.NewRecord(types.RecordMap{}),
		Variables: batch.Variables{
			"principal": []types.Value{types.EntityUID{Type: "User", ID: "alice"}},
			"resource":  []types.Value{types.EntityUID{Type: "Doc", ID: "doc1"}},
		},
	}

	var results []batch.Result
	callback := func(r batch.Result) error {
		results = append(results, r)
		return nil
	}

	err = batch.Authorize(context.Background(), ps, entities, batchReq, callback)
	if err != nil {
		t.Fatalf("Batch authorize failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	if results[0].Decision != types.Allow {
		t.Errorf("Expected Allow, got %v", results[0].Decision)
	}
}
