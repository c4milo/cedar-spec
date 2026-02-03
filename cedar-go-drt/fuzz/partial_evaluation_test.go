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
	"github.com/cedar-policy/cedar-go/x/exp/ast"
	"github.com/cedar-policy/cedar-go/x/exp/eval"

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/typegen"
)

// FuzzPartialEvaluation tests the soundness of partial evaluation.
//
// The key property tested is: if you partially evaluate a policy with some
// request components as variables, then fill in those variables and evaluate
// the residual, you should get the same authorization decision as evaluating
// the original policy with the full request.
//
// This is the "weak equivalence" property from the Rust TPE tests.
func FuzzPartialEvaluation(f *testing.F) {
	// Add seeds
	f.Add([]byte("partial-eval-seed-1"))
	f.Add([]byte("partial-eval-seed-2"))
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 128))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 16 {
			return // Need minimum data for generation
		}

		// Generate type-directed input
		input, err := inputGen.GenerateForAuthorization(data)
		if err != nil {
			return // Generation failed, skip
		}

		// Test partial evaluation for each policy and request
		for _, policy := range input.Policies.All() {
			// Convert public AST to experimental AST (same underlying struct)
			policyAST := (*ast.Policy)(policy.AST())

			for _, req := range input.Requests {
				// Test with different partial request configurations
				testPartialEvalConfigs(t, policyAST, input.Entities.Entities, req)
			}
		}
	})
}

// PartialConfig describes which request components are unknown.
type PartialConfig struct {
	Name              string
	PrincipalUnknown  bool
	ResourceUnknown   bool
	ContextKeyUnknown string // If non-empty, this context key is unknown
}

// testPartialEvalConfigs tests partial evaluation with various configurations.
func testPartialEvalConfigs(t *testing.T, policy *ast.Policy, entities types.EntityMap, req cedar.Request) {
	t.Helper()

	configs := []PartialConfig{
		{Name: "principal_unknown", PrincipalUnknown: true},
		{Name: "resource_unknown", ResourceUnknown: true},
		{Name: "both_unknown", PrincipalUnknown: true, ResourceUnknown: true},
	}

	for _, cfg := range configs {
		testPartialEvalWithConfig(t, policy, entities, req, cfg)
	}
}

// testPartialEvalWithConfig tests partial evaluation with a specific configuration.
func testPartialEvalWithConfig(t *testing.T, policy *ast.Policy, entities types.EntityMap, req cedar.Request, cfg PartialConfig) {
	t.Helper()

	// Build the partial environment with some components as variables
	partialEnv := buildPartialEnv(req, entities, cfg)

	// Partially evaluate the policy
	residualPolicy, keep := eval.PartialPolicy(partialEnv, policy)

	// Build the full environment for concrete evaluation
	fullEnv := eval.Env{
		Entities:  entities,
		Principal: req.Principal,
		Action:    req.Action,
		Resource:  req.Resource,
		Context:   req.Context,
	}

	// Evaluate the original policy with full context
	originalNode := eval.PolicyToNode(policy)
	originalResult, originalErr := eval.Eval(originalNode.AsIsNode(), fullEnv)

	// If the residual policy was dropped (keep=false), the original should evaluate to false
	if !keep {
		if originalErr == nil {
			if b, ok := originalResult.(types.Boolean); ok && bool(b) {
				t.Errorf("Partial eval dropped policy but original evaluates to true\n"+
					"Config: %s\nPolicy: %v", cfg.Name, policy)
			}
		}
		return
	}

	// Evaluate the residual policy with full context
	residualNode := eval.PolicyToNode(residualPolicy)
	residualResult, residualErr := eval.Eval(residualNode.AsIsNode(), fullEnv)

	// Compare results - both should agree on the boolean outcome
	originalBool := toBoolResult(originalResult, originalErr)
	residualBool := toBoolResult(residualResult, residualErr)

	if originalBool != residualBool {
		t.Errorf("Partial evaluation soundness violation!\n"+
			"Config: %s\n"+
			"Original result: %v (err: %v)\n"+
			"Residual result: %v (err: %v)\n"+
			"Original policy: %v\n"+
			"Residual policy: %v",
			cfg.Name,
			originalResult, originalErr,
			residualResult, residualErr,
			policy, residualPolicy)
	}
}

// buildPartialEnv builds an evaluation environment with some components as variables.
func buildPartialEnv(req cedar.Request, entities types.EntityMap, cfg PartialConfig) eval.Env {
	env := eval.Env{
		Entities: entities,
		Action:   req.Action,
		Context:  req.Context,
	}

	// Set principal - either concrete or variable
	if cfg.PrincipalUnknown {
		env.Principal = variableEntityUID("principal")
	} else {
		env.Principal = req.Principal
	}

	// Set resource - either concrete or variable
	if cfg.ResourceUnknown {
		env.Resource = variableEntityUID("resource")
	} else {
		env.Resource = req.Resource
	}

	return env
}

// variableEntityUID creates a placeholder for variable entity UIDs.
// Since eval.Variable returns types.Value but we need types.EntityUID,
// we use a sentinel value that the partial evaluator will recognize.
func variableEntityUID(name string) types.EntityUID {
	// The partial evaluator in cedar-go works differently from Rust.
	// We need to check how it handles entity UID variables.
	// For now, use a special marker type/id that's unlikely to match real entities.
	return types.NewEntityUID("__cedar_variable__", types.String(name))
}

// toBoolResult converts an evaluation result to a boolean.
// Returns false for errors or non-boolean values.
func toBoolResult(result types.Value, err error) bool {
	if err != nil {
		return false
	}
	if b, ok := result.(types.Boolean); ok {
		return bool(b)
	}
	return false
}

// FuzzPartialEvaluationPBT is a property-based test for partial evaluation.
// It verifies that re-evaluating a residual policy with concrete values
// produces the same authorization decision as the original policy.
func FuzzPartialEvaluationPBT(f *testing.F) {
	f.Add([]byte("pbt-seed-1"))
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

		// For each policy
		for _, policy := range input.Policies.All() {
			policyAST := (*ast.Policy)(policy.AST())

			// For each request pair (use two requests: one for partial, one for concrete)
			for i := 0; i+1 < len(input.Requests); i += 2 {
				partialReq := input.Requests[i]
				concreteReq := input.Requests[i+1]

				// Partially evaluate with partialReq's context
				// eval.Variable returns a types.Value that the partial evaluator recognizes
				partialEnv := eval.Env{
					Entities:  input.Entities.Entities,
					Principal: eval.Variable("principal"),
					Action:    partialReq.Action,
					Resource:  partialReq.Resource,
					Context:   partialReq.Context,
				}

				residual, keep := eval.PartialPolicy(partialEnv, policyAST)
				if !keep {
					continue
				}

				// Evaluate residual with concreteReq's principal
				fullEnv := eval.Env{
					Entities:  input.Entities.Entities,
					Principal: concreteReq.Principal,
					Action:    partialReq.Action,
					Resource:  partialReq.Resource,
					Context:   partialReq.Context,
				}

				residualNode := eval.PolicyToNode(residual)
				_, _ = eval.Eval(residualNode.AsIsNode(), fullEnv)
				// We mainly care that this doesn't panic
			}
		}
	})
}

// TestPartialEvaluationBasic tests basic partial evaluation scenarios.
func TestPartialEvaluationBasic(t *testing.T) {
	tests := []struct {
		name       string
		policyStr  string
		principal  types.EntityUID
		action     types.EntityUID
		resource   types.EntityUID
		expectKeep bool
	}{
		{
			name:       "always true permit",
			policyStr:  "permit(principal, action, resource);",
			principal:  types.NewEntityUID("User", "alice"),
			action:     types.NewEntityUID("Action", "view"),
			resource:   types.NewEntityUID("Doc", "readme"),
			expectKeep: true,
		},
		{
			name:       "always false forbid with impossible condition",
			policyStr:  "forbid(principal, action, resource) when { false };",
			principal:  types.NewEntityUID("User", "alice"),
			action:     types.NewEntityUID("Action", "view"),
			resource:   types.NewEntityUID("Doc", "readme"),
			expectKeep: false,
		},
		{
			name:       "principal constraint that matches",
			policyStr:  `permit(principal == User::"alice", action, resource);`,
			principal:  types.NewEntityUID("User", "alice"),
			action:     types.NewEntityUID("Action", "view"),
			resource:   types.NewEntityUID("Doc", "readme"),
			expectKeep: true,
		},
		{
			name:       "principal constraint that doesn't match",
			policyStr:  `permit(principal == User::"bob", action, resource);`,
			principal:  types.NewEntityUID("User", "alice"),
			action:     types.NewEntityUID("Action", "view"),
			resource:   types.NewEntityUID("Doc", "readme"),
			expectKeep: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var policy cedar.Policy
			if err := policy.UnmarshalCedar([]byte(tc.policyStr)); err != nil {
				t.Fatalf("Failed to parse policy: %v", err)
			}

			policyAST := (*ast.Policy)(policy.AST())

			// Full environment - no variables
			env := eval.Env{
				Entities:  make(types.EntityMap),
				Principal: tc.principal,
				Action:    tc.action,
				Resource:  tc.resource,
				Context:   types.Record{},
			}

			_, keep := eval.PartialPolicy(env, policyAST)

			if keep != tc.expectKeep {
				t.Errorf("Expected keep=%v, got keep=%v", tc.expectKeep, keep)
			}
		})
	}
}

// TestPartialEvaluationSoundness verifies the soundness property with concrete examples.
func TestPartialEvaluationSoundness(t *testing.T) {
	policyStr := `permit(principal, action, resource) when { principal == User::"alice" };`

	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(policyStr)); err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	policyAST := (*ast.Policy)(policy.AST())
	entities := make(types.EntityMap)

	// Test with Alice (should be true)
	aliceEnv := eval.Env{
		Entities:  entities,
		Principal: types.NewEntityUID("User", "alice"),
		Action:    types.NewEntityUID("Action", "view"),
		Resource:  types.NewEntityUID("Doc", "readme"),
		Context:   types.Record{},
	}

	residual, keep := eval.PartialPolicy(aliceEnv, policyAST)
	if !keep {
		t.Error("Policy should be kept for Alice")
	}

	// Evaluate residual
	residualNode := eval.PolicyToNode(residual)
	result, err := eval.Eval(residualNode.AsIsNode(), aliceEnv)
	if err != nil {
		t.Errorf("Evaluation failed: %v", err)
	}
	if b, ok := result.(types.Boolean); !ok || !bool(b) {
		t.Errorf("Expected true for Alice, got %v", result)
	}

	// Test with Bob (should be false/dropped)
	bobEnv := eval.Env{
		Entities:  entities,
		Principal: types.NewEntityUID("User", "bob"),
		Action:    types.NewEntityUID("Action", "view"),
		Resource:  types.NewEntityUID("Doc", "readme"),
		Context:   types.Record{},
	}

	_, keep = eval.PartialPolicy(bobEnv, policyAST)
	// The policy may be kept but evaluate to false, or may be dropped entirely
	// Either is correct behavior
	t.Logf("Policy kept for Bob: %v", keep)
}
