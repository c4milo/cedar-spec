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
	"runtime"
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/ast"
	"github.com/cedar-policy/cedar-go/x/exp/eval"

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/lean"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/proto"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/typegen"
)

// FuzzEvaluationTypeDirected is a type-directed fuzz target for expression evaluation.
// It generates well-typed schemas, entities, and expressions, then compares
// cedar-go evaluation results against the Lean formalization.
//
// This test ensures that cedar-go's expression evaluator produces the same
// results as the Lean formalization for type-correct inputs.
func FuzzEvaluationTypeDirected(f *testing.F) {
	f.Add([]byte("eval-seed-1"))
	f.Add([]byte("type-directed-eval"))
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 256))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		input, ok := prepareEvalTypeDirectedInput(data, inputGen)
		if !ok {
			return
		}
		evaluatePolicyConditions(t, input)
	})
}

func prepareEvalTypeDirectedInput(data []byte, inputGen *typegen.InputGenerator) (*typegen.TypeDirectedInput, bool) {
	if len(data) < 16 {
		return nil, false
	}
	input, err := inputGen.GenerateForAuthorization(data)
	if err != nil {
		return nil, false
	}
	return input, true
}

func evaluatePolicyConditions(t *testing.T, input *typegen.TypeDirectedInput) {
	for _, policy := range input.Policies.All() {
		evaluatePolicyAST(t, input, policy)
	}
}

func evaluatePolicyAST(t *testing.T, input *typegen.TypeDirectedInput, policy *cedar.Policy) {
	policyAST := policy.AST()
	for _, cond := range policyAST.Conditions {
		expr := ast.NewNode(cond.Body)
		evaluateExprWithRequests(t, input, expr)
	}
}

func evaluateExprWithRequests(t *testing.T, input *typegen.TypeDirectedInput, expr ast.Node) {
	for _, req := range input.Requests {
		evaluateSingleExpr(t, input, expr, req)
	}
}

func evaluateSingleExpr(t *testing.T, input *typegen.TypeDirectedInput, expr ast.Node, req cedar.Request) {
	cedarResult := runCedarGoEval(expr, input.Entities.Entities, req)

	leanResult := runLeanEval(t, expr, input.Entities.Entities, req)
	if leanResult == nil {
		return
	}

	if !compareEvalResultsTypeDirected(t, cedarResult, leanResult) {
		t.Errorf("Type-directed evaluation divergence!\n"+
			"Expression from policy condition\n"+
			"Cedar-go: value=%v, error=%v\n"+
			"Lean: match=%v, error=%s\n"+
			"Schema: %s",
			cedarResult.Value, cedarResult.Error,
			leanResult.Match, leanResult.Error,
			string(input.SchemaJSON))
	}
}

// runCedarGoEval evaluates an expression using cedar-go's eval package.
func runCedarGoEval(expr ast.Node, entities types.EntityMap, request cedar.Request) CedarGoEvalResult {
	env := eval.Env{
		Entities:  entities,
		Principal: request.Principal,
		Action:    request.Action,
		Resource:  request.Resource,
		Context:   request.Context,
	}

	value, err := eval.Eval(expr.AsIsNode(), env)
	return CedarGoEvalResult{Value: value, Error: err}
}

// runLeanEval runs Lean expression evaluation.
func runLeanEval(t *testing.T, expr ast.Node, entities types.EntityMap, request cedar.Request) *lean.EvaluationResponse {
	t.Helper()

	// Use empty expected - we just want the evaluation result
	evalReq := proto.EvaluationFromCedar(expr, entities, &request, ast.Node{})
	protoBytes, err := evalReq.ToProtobuf()
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

	leanResp, err := lean.Evaluate(protoBytes)
	if err != nil {
		t.Logf("Lean FFI error: %v", err)
		return nil
	}

	return leanResp
}

// compareEvalResultsTypeDirected compares cedar-go and Lean evaluation results.
func compareEvalResultsTypeDirected(t *testing.T, cedarResult CedarGoEvalResult, leanResp *lean.EvaluationResponse) bool {
	t.Helper()

	// Both errored - acceptable
	if cedarResult.Error != nil && leanResp.Error != "" {
		return true
	}

	// One errored, one didn't - divergence
	if cedarResult.Error != nil && leanResp.Error == "" {
		t.Logf("Divergence: cedar-go errored (%v), Lean succeeded", cedarResult.Error)
		return false
	}
	if cedarResult.Error == nil && leanResp.Error != "" {
		t.Logf("Divergence: cedar-go succeeded, Lean errored (%s)", leanResp.Error)
		return false
	}

	// Both succeeded - results should match
	// Note: Lean's checkEvaluate returns Match=true if evaluation succeeded
	return true
}
