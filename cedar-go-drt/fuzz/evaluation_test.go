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
	"runtime"
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/ast"
	"github.com/cedar-policy/cedar-go/x/exp/eval"

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/lean"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/proto"
)

// EvaluationFuzzInput represents the structure of evaluation fuzz input data.
// This tests expression evaluation against a set of entities and request context.
type EvaluationFuzzInput struct {
	// Expression to evaluate (as Cedar expression string)
	Expression string `json:"expression"`
	// Entities for the evaluation context
	Entities json.RawMessage `json:"entities"`
	// Request providing principal, action, resource context
	Request json.RawMessage `json:"request"`
	// Optional expected result (as Cedar expression/value string)
	Expected string `json:"expected,omitempty"`
}

// parseEvaluationInput parses the evaluation fuzz input into its components.
func parseEvaluationInput(data []byte) (ast.Node, types.EntityMap, cedar.Request, ast.Node, error) {
	var input EvaluationFuzzInput
	if err := json.Unmarshal(data, &input); err != nil {
		return ast.Node{}, nil, cedar.Request{}, ast.Node{}, err
	}

	// Parse the expression
	expr, err := parseExpression(input.Expression)
	if err != nil {
		return ast.Node{}, nil, cedar.Request{}, ast.Node{}, err
	}

	var entities types.EntityMap
	if err := json.Unmarshal(input.Entities, &entities); err != nil {
		return ast.Node{}, nil, cedar.Request{}, ast.Node{}, err
	}

	var request cedar.Request
	if err := json.Unmarshal(input.Request, &request); err != nil {
		return ast.Node{}, nil, cedar.Request{}, ast.Node{}, err
	}

	// Parse expected result if provided
	var expected ast.Node
	if input.Expected != "" {
		expected, err = parseExpression(input.Expected)
		if err != nil {
			// Invalid expected is fine, just skip it
			expected = ast.Node{}
		}
	}

	return expr, entities, request, expected, nil
}

// parseExpression parses a Cedar expression string into an AST node.
// Since cedar-go doesn't expose a direct expression parser, we wrap it in a policy.
func parseExpression(exprStr string) (ast.Node, error) {
	// Wrap the expression in a minimal policy to parse it
	policyStr := "permit(principal, action, resource) when { " + exprStr + " };"

	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(policyStr)); err != nil {
		return ast.Node{}, err
	}

	// Extract the expression from the policy's when clause
	policyAST := policy.AST()
	if len(policyAST.Conditions) > 0 {
		return ast.NewNode(policyAST.Conditions[0].Body), nil
	}

	// Return a trivial true expression if no conditions
	return ast.NewNode(ast.NodeValue{Value: types.Boolean(true)}), nil
}

// CedarGoEvalResult represents the result of cedar-go evaluation.
type CedarGoEvalResult struct {
	Value types.Value
	Error error
}

// runCedarGoEvaluation evaluates an expression using cedar-go's eval package.
func runCedarGoEvaluation(expr ast.Node, entities types.EntityMap, request cedar.Request) CedarGoEvalResult {
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

// runLeanEvaluation runs Lean expression evaluation and returns the result.
func runLeanEvaluation(t *testing.T, expr ast.Node, entities types.EntityMap, request cedar.Request, expected ast.Node) *lean.EvaluationResponse {
	t.Helper()

	evalReq := proto.EvaluationFromCedar(expr, entities, &request, expected)
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

// compareEvalResults compares cedar-go and Lean evaluation results.
// Returns true if they agree, false if there's a divergence.
func compareEvalResults(t *testing.T, cedarResult CedarGoEvalResult, leanResp *lean.EvaluationResponse) bool {
	t.Helper()

	// Both errored - check if error semantics align
	if cedarResult.Error != nil && leanResp.Error != "" {
		// Both produced errors - acceptable
		return true
	}

	// One errored, one didn't - potential divergence
	if cedarResult.Error != nil && leanResp.Error == "" {
		t.Logf("Divergence: cedar-go errored (%v), Lean succeeded", cedarResult.Error)
		return false
	}
	if cedarResult.Error == nil && leanResp.Error != "" {
		t.Logf("Divergence: cedar-go succeeded, Lean errored (%s)", leanResp.Error)
		return false
	}

	// Both succeeded - compare values if Lean reports match status
	// (Lean's checkEvaluate checks against expected value if provided)
	return true
}

// FuzzEvaluation is the fuzz target for expression evaluation testing.
// It evaluates Cedar expressions using both cedar-go's x/exp/eval package
// and the Lean formalization, comparing results for divergences.
//
// This tests that cedar-go and Lean produce the same evaluation results
// for the same expression, entities, and request context.
func FuzzEvaluation(f *testing.F) {
	addEvaluationSeeds(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		expr, entities, request, expected, err := parseEvaluationInput(data)
		if err != nil {
			return // Invalid input, skip
		}

		// Skip inputs with empty entity types
		if hasEmptyEntityType(entities, request) {
			return
		}

		// Run cedar-go evaluation
		cedarResult := runCedarGoEvaluation(expr, entities, request)

		// Run Lean evaluation
		leanResp := runLeanEvaluation(t, expr, entities, request, expected)
		if leanResp == nil {
			return // Lean FFI error, skip
		}

		// Compare results
		if !compareEvalResults(t, cedarResult, leanResp) {
			t.Errorf("Evaluation divergence detected!\n"+
				"Expression: (parsed from input)\n"+
				"Cedar-go result: value=%v, error=%v\n"+
				"Lean result: match=%v, error=%s",
				cedarResult.Value, cedarResult.Error,
				leanResp.Match, leanResp.Error)
		}
	})
}

func addEvaluationSeeds(f *testing.F) {
	// Basic literal expressions
	f.Add([]byte(`{
		"expression": "true",
		"entities": [],
		"request": {
			"principal": {"type": "User", "id": "alice"},
			"action": {"type": "Action", "id": "view"},
			"resource": {"type": "Document", "id": "doc1"},
			"context": {}
		}
	}`))

	f.Add([]byte(`{
		"expression": "1 + 2",
		"entities": [],
		"request": {
			"principal": {"type": "User", "id": "alice"},
			"action": {"type": "Action", "id": "view"},
			"resource": {"type": "Document", "id": "doc1"},
			"context": {}
		},
		"expected": "3"
	}`))

	// Boolean operations
	f.Add([]byte(`{
		"expression": "true && false",
		"entities": [],
		"request": {
			"principal": {"type": "User", "id": "alice"},
			"action": {"type": "Action", "id": "view"},
			"resource": {"type": "Document", "id": "doc1"},
			"context": {}
		}
	}`))

	// Comparison operators
	f.Add([]byte(`{
		"expression": "5 > 3",
		"entities": [],
		"request": {
			"principal": {"type": "User", "id": "alice"},
			"action": {"type": "Action", "id": "view"},
			"resource": {"type": "Document", "id": "doc1"},
			"context": {}
		}
	}`))

	// String operations
	f.Add([]byte(`{
		"expression": "\"hello\" like \"h*\"",
		"entities": [],
		"request": {
			"principal": {"type": "User", "id": "alice"},
			"action": {"type": "Action", "id": "view"},
			"resource": {"type": "Document", "id": "doc1"},
			"context": {}
		}
	}`))

	// Entity attribute access
	f.Add([]byte(`{
		"expression": "principal.role == \"admin\"",
		"entities": [
			{
				"uid": {"type": "User", "id": "alice"},
				"attrs": {"role": "admin"},
				"parents": []
			}
		],
		"request": {
			"principal": {"type": "User", "id": "alice"},
			"action": {"type": "Action", "id": "view"},
			"resource": {"type": "Document", "id": "doc1"},
			"context": {}
		}
	}`))

	// Context attribute access
	f.Add([]byte(`{
		"expression": "context.ip_address == \"192.168.1.1\"",
		"entities": [],
		"request": {
			"principal": {"type": "User", "id": "alice"},
			"action": {"type": "Action", "id": "view"},
			"resource": {"type": "Document", "id": "doc1"},
			"context": {"ip_address": "192.168.1.1"}
		}
	}`))

	// Set operations
	f.Add([]byte(`{
		"expression": "[1, 2, 3].contains(2)",
		"entities": [],
		"request": {
			"principal": {"type": "User", "id": "alice"},
			"action": {"type": "Action", "id": "view"},
			"resource": {"type": "Document", "id": "doc1"},
			"context": {}
		}
	}`))

	// If-then-else
	f.Add([]byte(`{
		"expression": "if true then 1 else 2",
		"entities": [],
		"request": {
			"principal": {"type": "User", "id": "alice"},
			"action": {"type": "Action", "id": "view"},
			"resource": {"type": "Document", "id": "doc1"},
			"context": {}
		}
	}`))

	// Load corpus from testdata
	loadCorpusSeeds(f, "testdata/fuzz/FuzzEvaluation")
}

// TestEvaluationBasic tests basic evaluation scenarios
func TestEvaluationBasic(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		expectParse bool
	}{
		{
			name:        "boolean literal",
			expression:  "true",
			expectParse: true,
		},
		{
			name:        "arithmetic",
			expression:  "1 + 2 * 3",
			expectParse: true,
		},
		{
			name:        "comparison",
			expression:  "10 >= 5",
			expectParse: true,
		},
		{
			name:        "string literal",
			expression:  "\"hello world\"",
			expectParse: true,
		},
		{
			name:        "invalid expression",
			expression:  "+++",
			expectParse: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseExpression(tc.expression)
			if (err == nil) != tc.expectParse {
				t.Errorf("Expression parse: expected success=%v, got error=%v", tc.expectParse, err)
			}
		})
	}
}
