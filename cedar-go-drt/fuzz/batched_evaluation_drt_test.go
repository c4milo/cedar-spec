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
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/lean"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/proto"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/typegen"
)

type batchResultData struct {
	decision   types.Decision
	diagnostic types.Diagnostic
	request    types.Request
}

type batchDRTContext struct {
	input      *typegen.TypeDirectedInput
	principals []types.EntityUID
	resources  []types.EntityUID
	action     types.EntityUID
	config     comparison.ComparisonConfig
}

// FuzzBatchedEvaluationDRT tests batch evaluation against Lean for each individual request.
// This verifies that batch evaluation produces the same results as the Lean formalization
// for every request in the batch.
func FuzzBatchedEvaluationDRT(f *testing.F) {
	f.Add([]byte("batch-drt-seed-1"))
	f.Add([]byte("batch-drt-seed-2"))
	f.Add(make([]byte, 128))

	inputGen := typegen.TypeDirectedInputGenerator()
	config := comparison.ComparisonConfig{
		ErrorMode:             comparison.ErrorComparisonModeIgnore,
		IgnoreDecisionOnError: true,
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		ctx, ok := prepareBatchDRTContext(data, inputGen, config)
		if !ok {
			return
		}

		batchResults, err := runBatchDRTEvaluation(ctx)
		if err != nil {
			return
		}

		compareBatchResultsWithLean(t, ctx, batchResults)
	})
}

func prepareBatchDRTContext(data []byte, inputGen *typegen.InputGenerator, config comparison.ComparisonConfig) (*batchDRTContext, bool) {
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

	return &batchDRTContext{
		input:      input,
		principals: principals,
		resources:  resources,
		action:     action,
		config:     config,
	}, true
}

func runBatchDRTEvaluation(ctx *batchDRTContext) (map[string]batchResultData, error) {
	principalValues := uidSliceToValues(ctx.principals)
	resourceValues := uidSliceToValues(ctx.resources)

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

	batchResults := make(map[string]batchResultData)
	callback := func(r batch.Result) error {
		key := requestKey(r.Request.Principal, r.Request.Resource)
		batchResults[key] = batchResultData{
			decision:   r.Decision,
			diagnostic: r.Diagnostic,
			request:    r.Request,
		}
		return nil
	}

	err := batch.Authorize(context.Background(), ctx.input.Policies, ctx.input.Entities.Entities, batchReq, callback)
	return batchResults, err
}

func uidSliceToValues(uids []types.EntityUID) []types.Value {
	values := make([]types.Value, len(uids))
	for i, uid := range uids {
		values[i] = uid
	}
	return values
}

func compareBatchResultsWithLean(t *testing.T, ctx *batchDRTContext, batchResults map[string]batchResultData) {
	for key, result := range batchResults {
		compareSingleBatchResult(t, ctx, key, result)
	}
}

func compareSingleBatchResult(t *testing.T, ctx *batchDRTContext, key string, result batchResultData) {
	req := cedar.Request{
		Principal: result.request.Principal,
		Action:    result.request.Action,
		Resource:  result.request.Resource,
		Context:   result.request.Context,
	}

	leanResp := runBatchLeanAuth(t, ctx.input.Policies, ctx.input.Entities.Entities, req)
	if leanResp == nil {
		return
	}

	goResult := toAuthorizationResult(cedar.Decision(result.decision), result.diagnostic)
	leanResult := toLeanAuthorizationResult(leanResp)

	diffs := comparison.CompareAuthorization(goResult, leanResult, ctx.config)
	if len(diffs) > 0 {
		t.Errorf("Batch DRT mismatch for %s:\n%s\nBatch decision: %v, Lean decision: %s",
			key, comparison.FormatDifferences(diffs), result.decision, leanResp.Decision)
	}
}

func runBatchLeanAuth(t *testing.T, policies *cedar.PolicySet, entities types.EntityMap, req cedar.Request) *lean.AuthorizationResponse {
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
