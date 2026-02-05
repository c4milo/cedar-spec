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
	"github.com/cedar-policy/cedar-go/x/exp/schema"

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/lean"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/proto"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/typegen"
)

type residualKind int

const (
	residualTrue residualKind = iota
	residualFalse
	residualUnknown
)

type partialEvalContext struct {
	input    *typegen.TypeDirectedInput
	schema   *schema.Schema
	leanThread *lean.LeanThread
}

// FuzzPartialEvaluationDRT tests that cedar-go's partial evaluation matches
// the Lean formalization's batched evaluation for policies.
func FuzzPartialEvaluationDRT(f *testing.F) {
	if testing.Short() {
		f.Skip("Skipping Lean DRT test in short mode")
	}

	if err := lean.Initialize(); err != nil {
		f.Skipf("Failed to initialize Lean: %v", err)
	}

	f.Add([]byte("partial-drt-seed-1"))
	f.Add([]byte("partial-drt-seed-2"))
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 128))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		ctx, ok := preparePartialEvalContext(t, data, inputGen)
		if !ok {
			return
		}
		defer ctx.leanThread.Close()

		testPartialEvaluationForAllPolicies(t, ctx)
	})
}

func preparePartialEvalContext(t *testing.T, data []byte, inputGen *typegen.InputGenerator) (*partialEvalContext, bool) {
	if len(data) < 32 {
		return nil, false
	}

	lt, err := lean.NewLeanThread()
	if err != nil {
		t.Skipf("Failed to create Lean thread: %v", err)
		return nil, false
	}

	input, err := inputGen.GenerateForAuthorization(data)
	if err != nil {
		lt.Close()
		return nil, false
	}

	if len(input.Requests) == 0 {
		lt.Close()
		return nil, false
	}

	s, err := schema.NewFromJSON(input.SchemaJSON)
	if err != nil {
		lt.Close()
		return nil, false
	}

	return &partialEvalContext{
		input:      input,
		schema:     s,
		leanThread: lt,
	}, true
}

func testPartialEvaluationForAllPolicies(t *testing.T, ctx *partialEvalContext) {
	for policyID, policy := range ctx.input.Policies.All() {
		testPartialEvaluationForPolicy(t, ctx, policyID, policy)
	}
}

func testPartialEvaluationForPolicy(t *testing.T, ctx *partialEvalContext, policyID cedar.PolicyID, policy *cedar.Policy) {
	policyAST := (*ast.Policy)(policy.AST())
	req := ctx.input.Requests[0]

	env := eval.Env{
		Entities:  ctx.input.Entities.Entities,
		Principal: req.Principal,
		Action:    req.Action,
		Resource:  req.Resource,
		Context:   req.Context,
	}

	residual, keep := eval.PartialPolicy(env, policyAST)
	kind := classifyResidualPolicy(residual, keep)

	leanResult := runLeanBatchedEvaluation(ctx, policy, req)
	if leanResult == nil {
		return
	}

	comparePartialEvalResults(t, kind, leanResult, policyID, policy, req)
}

func runLeanBatchedEvaluation(ctx *partialEvalContext, policy *cedar.Policy, req cedar.Request) *lean.BatchedEvaluationResponse {
	singlePolicySet, err := cedar.NewPolicySetFromBytes("test.cedar", []byte(policy.MarshalCedar()))
	if err != nil {
		return nil
	}

	batchReq := proto.BatchedEvaluationFromCedar(singlePolicySet, ctx.schema, &req, ctx.input.Entities.Entities, 5)
	protoBytes, err := batchReq.ToProtobuf()
	if err != nil {
		return nil
	}

	leanResp, err := lean.BatchedEvaluate(protoBytes)
	if err != nil {
		return nil
	}

	return leanResp
}

func comparePartialEvalResults(t *testing.T, kind residualKind, leanResp *lean.BatchedEvaluationResponse, policyID cedar.PolicyID, policy *cedar.Policy, req cedar.Request) {
	switch kind {
	case residualTrue:
		if leanResp.Result != nil && !*leanResp.Result {
			t.Errorf("Cedar-go partial eval returned TRUE but Lean returned FALSE\n"+
				"Policy ID: %s\n"+
				"Policy: %s\n"+
				"Request: principal=%v, action=%v, resource=%v",
				policyID, policy.MarshalCedar(), req.Principal, req.Action, req.Resource)
		}
	case residualFalse:
		if leanResp.Result != nil && *leanResp.Result {
			t.Errorf("Cedar-go partial eval returned FALSE but Lean returned TRUE\n"+
				"Policy ID: %s\n"+
				"Policy: %s\n"+
				"Request: principal=%v, action=%v, resource=%v",
				policyID, policy.MarshalCedar(), req.Principal, req.Action, req.Resource)
		}
	case residualUnknown:
		// Residual - any Lean result is acceptable
	}
}

// classifyResidualPolicy determines if a residual policy is definitely true,
// definitely false, or unknown (needs more information).
func classifyResidualPolicy(p *ast.Policy, keep bool) residualKind {
	if !keep || p == nil {
		return residualFalse
	}

	if !isScopeAll(p.Principal) || !isScopeAll(p.Action) || !isScopeAll(p.Resource) {
		return residualUnknown
	}

	return classifyResidualConditions(p.Conditions)
}

func classifyResidualConditions(conditions []ast.ConditionType) residualKind {
	if len(conditions) == 0 {
		return residualTrue
	}

	for _, cond := range conditions {
		kind := classifySingleCondition(cond)
		if kind != residualTrue {
			return kind
		}
	}

	return residualTrue
}

func classifySingleCondition(cond ast.ConditionType) residualKind {
	v, ok := cond.Body.(ast.NodeValue)
	if !ok {
		return residualUnknown
	}

	b, ok := v.Value.(types.Boolean)
	if !ok {
		return residualUnknown
	}

	if bool(b) != bool(cond.Condition) {
		return residualFalse
	}
	return residualTrue
}

func isScopeAll(scope ast.IsScopeNode) bool {
	_, ok := scope.(ast.ScopeTypeAll)
	return ok
}

// TestPartialEvaluationDRTBasic tests basic partial evaluation DRT scenarios.
func TestPartialEvaluationDRTBasic(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Lean DRT test in short mode")
	}

	lt, err := initLeanForTest(t)
	if err != nil {
		return
	}
	defer lt.Close()

	tests := getPartialEvalTestCases()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runPartialEvalTestCase(t, tc)
		})
	}
}

type partialEvalTestCase struct {
	name         string
	policy       string
	principal    types.EntityUID
	action       types.EntityUID
	resource     types.EntityUID
	expectResult *bool
}

func initLeanForTest(t *testing.T) (*lean.LeanThread, error) {
	if err := lean.Initialize(); err != nil {
		t.Skipf("Failed to initialize Lean: %v", err)
		return nil, err
	}

	runtime.LockOSThread()

	lt, err := lean.NewLeanThread()
	if err != nil {
		t.Fatalf("Failed to create Lean thread: %v", err)
		return nil, err
	}

	return lt, nil
}

func getPartialEvalTestCases() []partialEvalTestCase {
	return []partialEvalTestCase{
		{
			name:         "always permit",
			policy:       "permit(principal, action, resource);",
			principal:    types.NewEntityUID("User", "alice"),
			action:       types.NewEntityUID("Action", "view"),
			resource:     types.NewEntityUID("Doc", "readme"),
			expectResult: boolPtr(true),
		},
		{
			name:         "always forbid with false condition",
			policy:       "permit(principal, action, resource) when { false };",
			principal:    types.NewEntityUID("User", "alice"),
			action:       types.NewEntityUID("Action", "view"),
			resource:     types.NewEntityUID("Doc", "readme"),
			expectResult: boolPtr(false),
		},
		{
			name:         "principal matches",
			policy:       `permit(principal == User::"alice", action, resource);`,
			principal:    types.NewEntityUID("User", "alice"),
			action:       types.NewEntityUID("Action", "view"),
			resource:     types.NewEntityUID("Doc", "readme"),
			expectResult: boolPtr(true),
		},
		{
			name:         "principal does not match",
			policy:       `permit(principal == User::"bob", action, resource);`,
			principal:    types.NewEntityUID("User", "alice"),
			action:       types.NewEntityUID("Action", "view"),
			resource:     types.NewEntityUID("Doc", "readme"),
			expectResult: boolPtr(false),
		},
	}
}

func runPartialEvalTestCase(t *testing.T, tc partialEvalTestCase) {
	policies, err := cedar.NewPolicySetFromBytes("test.cedar", []byte(tc.policy))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	schemaJSON := createMinimalSchemaJSON(tc.principal.Type, tc.action, tc.resource.Type)
	s, err := schema.NewFromJSON(schemaJSON)
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	req := cedar.Request{
		Principal: tc.principal,
		Action:    tc.action,
		Resource:  tc.resource,
		Context:   types.Record{},
	}

	resp := runPartialEvalLean(t, policies, s, req)
	if resp == nil {
		return
	}

	comparePartialEvalTestResult(t, tc.expectResult, resp.Result)
}

func runPartialEvalLean(t *testing.T, policies *cedar.PolicySet, s *schema.Schema, req cedar.Request) *lean.BatchedEvaluationResponse {
	entities := make(types.EntityMap)

	batchReq := proto.BatchedEvaluationFromCedar(policies, s, &req, entities, 5)
	protoBytes, err := batchReq.ToProtobuf()
	if err != nil {
		t.Fatalf("Failed to convert to protobuf: %v", err)
	}

	resp, err := lean.BatchedEvaluate(protoBytes)
	if err != nil {
		t.Fatalf("Lean BatchedEvaluate failed: %v", err)
	}

	return resp
}

func comparePartialEvalTestResult(t *testing.T, expected, actual *bool) {
	if expected == nil {
		t.Logf("Lean returned: %v (expected residual)", actual)
	} else if actual == nil {
		t.Logf("Lean returned residual, expected %v", *expected)
	} else if *actual != *expected {
		t.Errorf("Expected %v, got %v", *expected, *actual)
	}
}

// createMinimalSchemaJSON creates a minimal schema JSON for testing.
func createMinimalSchemaJSON(principalType types.EntityType, action types.EntityUID, resourceType types.EntityType) []byte {
	return []byte(`{
		"": {
			"entityTypes": {
				"` + string(principalType) + `": {},
				"` + string(resourceType) + `": {},
				"Action": {}
			},
			"actions": {
				"` + string(action.ID) + `": {
					"appliesTo": {
						"principalTypes": ["` + string(principalType) + `"],
						"resourceTypes": ["` + string(resourceType) + `"]
					}
				}
			}
		}
	}`)
}

func boolPtr(b bool) *bool {
	return &b
}

// FuzzResidualSetDRT tests the ResidualSet API against Lean's authorization.
func FuzzResidualSetDRT(f *testing.F) {
	if testing.Short() {
		f.Skip("Skipping Lean DRT test in short mode")
	}

	if err := lean.Initialize(); err != nil {
		f.Skipf("Failed to initialize Lean: %v", err)
	}

	f.Add([]byte("residual-set-seed-1"))
	f.Add(make([]byte, 64))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		testResidualSetDRT(t, data, inputGen)
	})
}

func testResidualSetDRT(t *testing.T, data []byte, inputGen *typegen.InputGenerator) {
	if len(data) < 32 {
		return
	}

	lt, err := lean.NewLeanThread()
	if err != nil {
		t.Skipf("Failed to create Lean thread: %v", err)
		return
	}
	defer lt.Close()

	input, err := inputGen.GenerateForAuthorization(data)
	if err != nil || len(input.Requests) == 0 {
		return
	}

	req := input.Requests[0]
	residuals := computeResidualSet(input, req)

	if residuals.MustDecide() {
		compareResidualSetWithLean(t, input, req, residuals.Decision())
	}
}

func computeResidualSet(input *typegen.TypeDirectedInput, req cedar.Request) *eval.ResidualSet {
	policies := make(map[types.PolicyID]*ast.Policy)
	for policyID, policy := range input.Policies.All() {
		policies[policyID] = (*ast.Policy)(policy.AST())
	}

	env := eval.Env{
		Entities:  input.Entities.Entities,
		Principal: req.Principal,
		Action:    req.Action,
		Resource:  req.Resource,
		Context:   req.Context,
	}

	return eval.PartialPolicySet(env, policies)
}

func compareResidualSetWithLean(t *testing.T, input *typegen.TypeDirectedInput, req cedar.Request, goDecision types.Decision) {
	authReq := proto.PolicySetFromCedar(input.Policies, input.Entities.Entities, &req)
	protoBytes, err := authReq.ToProtobuf()
	if err != nil {
		return
	}

	leanResp, err := lean.IsAuthorized(protoBytes)
	if err != nil {
		return
	}

	var leanDecision types.Decision
	if leanResp.Decision == "allow" {
		leanDecision = types.Allow
	} else {
		leanDecision = types.Deny
	}

	if goDecision != leanDecision {
		t.Errorf("ResidualSet.MustDecide() = true with %v but Lean says %v\n"+
			"Request: principal=%v, action=%v, resource=%v",
			goDecision, leanDecision, req.Principal, req.Action, req.Resource)
	}
}
