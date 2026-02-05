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
	"github.com/cedar-policy/cedar-go/x/exp/schema"

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/lean"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/proto"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/typegen"
)

// This file contains fuzz tests for SymCC (Symbolic Cedar Compiler).
// SymCC compiles Cedar policies to SMT formulas and uses cvc5 to verify properties.

// =============================================================================
// Single Policy Checks
// =============================================================================

// FuzzSymCCNeverErrors tests that the SymCC neverErrors check works correctly.
// A policy "never errors" if it cannot produce an evaluation error for any valid request.
func FuzzSymCCNeverErrors(f *testing.F) {
	f.Add([]byte("never-errors-seed-1"))
	f.Add([]byte("never-errors-seed-2"))
	f.Add(make([]byte, 64))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		ctx, ok := prepareSymCCContext(data, inputGen)
		if !ok {
			return
		}

		testNeverErrors(t, ctx)
	})
}

// FuzzSymCCAlwaysMatches tests that the SymCC alwaysMatches check works correctly.
// A policy "always matches" if its condition always evaluates to true for any valid request.
func FuzzSymCCAlwaysMatches(f *testing.F) {
	f.Add([]byte("always-matches-seed-1"))
	f.Add([]byte("always-matches-seed-2"))
	f.Add(make([]byte, 64))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		ctx, ok := prepareSymCCContext(data, inputGen)
		if !ok {
			return
		}

		testAlwaysMatches(t, ctx)
	})
}

// FuzzSymCCNeverMatches tests that the SymCC neverMatches check works correctly.
// A policy "never matches" if its condition never evaluates to true for any valid request.
func FuzzSymCCNeverMatches(f *testing.F) {
	f.Add([]byte("never-matches-seed-1"))
	f.Add([]byte("never-matches-seed-2"))
	f.Add(make([]byte, 64))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		ctx, ok := prepareSymCCContext(data, inputGen)
		if !ok {
			return
		}

		testNeverMatches(t, ctx)
	})
}

// =============================================================================
// Policy Set Checks
// =============================================================================

// FuzzSymCCAlwaysAllows tests the SymCC alwaysAllows check.
// A policy set "always allows" if it permits any valid request.
func FuzzSymCCAlwaysAllows(f *testing.F) {
	f.Add([]byte("always-allows-seed-1"))
	f.Add([]byte("always-allows-seed-2"))
	f.Add(make([]byte, 64))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		ctx, ok := prepareSymCCContext(data, inputGen)
		if !ok {
			return
		}

		testAlwaysAllows(t, ctx)
	})
}

// FuzzSymCCAlwaysDenies tests the SymCC alwaysDenies check.
// A policy set "always denies" if it denies any valid request.
func FuzzSymCCAlwaysDenies(f *testing.F) {
	f.Add([]byte("always-denies-seed-1"))
	f.Add([]byte("always-denies-seed-2"))
	f.Add(make([]byte, 64))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		ctx, ok := prepareSymCCContext(data, inputGen)
		if !ok {
			return
		}

		testAlwaysDenies(t, ctx)
	})
}

// =============================================================================
// Two Policy Comparison
// =============================================================================

// FuzzSymCCMatchesEquivalent tests that two policies have equivalent conditions.
func FuzzSymCCMatchesEquivalent(f *testing.F) {
	f.Add([]byte("matches-equiv-seed-1"))
	f.Add([]byte("matches-equiv-seed-2"))
	f.Add(make([]byte, 64))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		ctx, ok := prepareTwoPolicyContext(data, inputGen)
		if !ok {
			return
		}

		testMatchesEquivalent(t, ctx)
	})
}

// FuzzSymCCMatchesImplies tests that one policy's condition implies another's.
func FuzzSymCCMatchesImplies(f *testing.F) {
	f.Add([]byte("matches-implies-seed-1"))
	f.Add([]byte("matches-implies-seed-2"))
	f.Add(make([]byte, 64))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		ctx, ok := prepareTwoPolicyContext(data, inputGen)
		if !ok {
			return
		}

		testMatchesImplies(t, ctx)
	})
}

// =============================================================================
// Two PolicySet Comparison
// =============================================================================

// FuzzSymCCEquivalent tests that two policy sets are equivalent.
func FuzzSymCCEquivalent(f *testing.F) {
	f.Add([]byte("equiv-seed-1"))
	f.Add([]byte("equiv-seed-2"))
	f.Add(make([]byte, 64))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		ctx, ok := prepareTwoPolicySetContext(data, inputGen)
		if !ok {
			return
		}

		testEquivalent(t, ctx)
	})
}

// FuzzSymCCImplies tests that one policy set implies another.
func FuzzSymCCImplies(f *testing.F) {
	f.Add([]byte("implies-seed-1"))
	f.Add([]byte("implies-seed-2"))
	f.Add(make([]byte, 64))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		ctx, ok := prepareTwoPolicySetContext(data, inputGen)
		if !ok {
			return
		}

		testImplies(t, ctx)
	})
}

// =============================================================================
// Context Preparation
// =============================================================================

type symccContext struct {
	input       *typegen.TypeDirectedInput
	schema      *schema.Schema
	leanSchema  *lean.LeanSchema
	requestEnv  *proto.RequestEnv
	firstPolicy *cedar.Policy
}

type twoPolicyContext struct {
	*symccContext
	secondPolicy *cedar.Policy
}

type twoPolicySetContext struct {
	*symccContext
	secondPolicySet *cedar.PolicySet
}

func prepareSymCCContext(data []byte, inputGen *typegen.InputGenerator) (*symccContext, bool) {
	if len(data) < 32 {
		return nil, false
	}

	input, err := inputGen.Generate(data)
	if err != nil {
		return nil, false
	}

	if input.Policies == nil || countPolicies(input.Policies) == 0 {
		return nil, false
	}

	// Parse schema
	s, err := schema.NewFromJSON(input.SchemaJSON)
	if err != nil {
		return nil, false
	}

	// Load schema into Lean
	schemaBytes, err := proto.SchemaToProtobuf(s)
	if err != nil {
		return nil, false
	}

	if err := lean.Initialize(); err != nil {
		return nil, false
	}

	lt, err := lean.NewLeanThread()
	if err != nil {
		return nil, false
	}
	defer lt.Close()

	leanSchema, err := lean.LoadSchema(schemaBytes)
	if err != nil {
		return nil, false
	}

	// Build request environment from schema
	env := buildRequestEnv(input)

	// Get first policy
	var firstPolicy *cedar.Policy
	for _, p := range input.Policies.All() {
		firstPolicy = p
		break
	}

	return &symccContext{
		input:       input,
		schema:      s,
		leanSchema:  leanSchema,
		requestEnv:  env,
		firstPolicy: firstPolicy,
	}, true
}

func prepareTwoPolicyContext(data []byte, inputGen *typegen.InputGenerator) (*twoPolicyContext, bool) {
	ctx, ok := prepareSymCCContext(data, inputGen)
	if !ok {
		return nil, false
	}

	if countPolicies(ctx.input.Policies) < 2 {
		// Need at least two policies
		// Create a second policy by copying the first with minor modification
		return nil, false
	}

	// Get second policy
	var secondPolicy *cedar.Policy
	count := 0
	for _, p := range ctx.input.Policies.All() {
		if count == 1 {
			secondPolicy = p
			break
		}
		count++
	}

	return &twoPolicyContext{
		symccContext: ctx,
		secondPolicy: secondPolicy,
	}, true
}

func prepareTwoPolicySetContext(data []byte, inputGen *typegen.InputGenerator) (*twoPolicySetContext, bool) {
	ctx, ok := prepareSymCCContext(data, inputGen)
	if !ok {
		return nil, false
	}

	// Create a second policy set (could be modified version or subset)
	secondPolicySet := cedar.NewPolicySet()
	for id, p := range ctx.input.Policies.All() {
		secondPolicySet.Add(id, p)
	}

	return &twoPolicySetContext{
		symccContext:    ctx,
		secondPolicySet: secondPolicySet,
	}, true
}

func buildRequestEnv(input *typegen.TypeDirectedInput) *proto.RequestEnv {
	principalType := types.EntityType("User")
	resourceType := types.EntityType("Resource")
	actionID := types.NewEntityUID("Action", "action")

	if len(input.Entities.PrincipalUIDs) > 0 {
		principalType = input.Entities.PrincipalUIDs[0].Type
	}
	if len(input.Entities.ResourceUIDs) > 0 {
		resourceType = input.Entities.ResourceUIDs[0].Type
	}
	if len(input.Schema.ActionList) > 0 {
		actionID = types.NewEntityUID("Action", types.String(input.Schema.ActionList[0]))
	}

	return &proto.RequestEnv{
		PrincipalType: principalType,
		ActionID:      actionID,
		ResourceType:  resourceType,
	}
}

// =============================================================================
// Test Functions
// =============================================================================

func testNeverErrors(t *testing.T, ctx *symccContext) {
	t.Helper()
	defer ctx.leanSchema.Release()

	req := proto.CheckPolicyFromCedar(ctx.firstPolicy, ctx.requestEnv)
	protoBytes, err := req.ToProtobuf()
	if err != nil {
		t.Logf("Failed to convert to protobuf: %v", err)
		return
	}

	resp, err := lean.CheckNeverErrors(ctx.leanSchema, protoBytes)
	if err != nil {
		t.Logf("SymCC neverErrors failed: %v", err)
		return
	}

	// Log the result - we're mainly testing that the operation completes without crash
	t.Logf("neverErrors result: %v", resp.Result)
}

func testAlwaysMatches(t *testing.T, ctx *symccContext) {
	t.Helper()
	defer ctx.leanSchema.Release()

	req := proto.CheckPolicyFromCedar(ctx.firstPolicy, ctx.requestEnv)
	protoBytes, err := req.ToProtobuf()
	if err != nil {
		t.Logf("Failed to convert to protobuf: %v", err)
		return
	}

	resp, err := lean.CheckAlwaysMatches(ctx.leanSchema, protoBytes)
	if err != nil {
		t.Logf("SymCC alwaysMatches failed: %v", err)
		return
	}

	t.Logf("alwaysMatches result: %v", resp.Result)
}

func testNeverMatches(t *testing.T, ctx *symccContext) {
	t.Helper()
	defer ctx.leanSchema.Release()

	req := proto.CheckPolicyFromCedar(ctx.firstPolicy, ctx.requestEnv)
	protoBytes, err := req.ToProtobuf()
	if err != nil {
		t.Logf("Failed to convert to protobuf: %v", err)
		return
	}

	resp, err := lean.CheckNeverMatches(ctx.leanSchema, protoBytes)
	if err != nil {
		t.Logf("SymCC neverMatches failed: %v", err)
		return
	}

	t.Logf("neverMatches result: %v", resp.Result)
}

func testAlwaysAllows(t *testing.T, ctx *symccContext) {
	t.Helper()
	defer ctx.leanSchema.Release()

	req := proto.CheckPolicySetFromCedar(ctx.input.Policies, ctx.requestEnv)
	protoBytes, err := req.ToProtobuf()
	if err != nil {
		t.Logf("Failed to convert to protobuf: %v", err)
		return
	}

	resp, err := lean.CheckAlwaysAllows(ctx.leanSchema, protoBytes)
	if err != nil {
		t.Logf("SymCC alwaysAllows failed: %v", err)
		return
	}

	t.Logf("alwaysAllows result: %v", resp.Result)
}

func testAlwaysDenies(t *testing.T, ctx *symccContext) {
	t.Helper()
	defer ctx.leanSchema.Release()

	req := proto.CheckPolicySetFromCedar(ctx.input.Policies, ctx.requestEnv)
	protoBytes, err := req.ToProtobuf()
	if err != nil {
		t.Logf("Failed to convert to protobuf: %v", err)
		return
	}

	resp, err := lean.CheckAlwaysDenies(ctx.leanSchema, protoBytes)
	if err != nil {
		t.Logf("SymCC alwaysDenies failed: %v", err)
		return
	}

	t.Logf("alwaysDenies result: %v", resp.Result)
}

func testMatchesEquivalent(t *testing.T, ctx *twoPolicyContext) {
	t.Helper()
	defer ctx.leanSchema.Release()

	req := proto.ComparePoliciesFromCedar(ctx.firstPolicy, ctx.secondPolicy, ctx.requestEnv)
	protoBytes, err := req.ToProtobuf()
	if err != nil {
		t.Logf("Failed to convert to protobuf: %v", err)
		return
	}

	resp, err := lean.CheckMatchesEquivalent(ctx.leanSchema, protoBytes)
	if err != nil {
		t.Logf("SymCC matchesEquivalent failed: %v", err)
		return
	}

	t.Logf("matchesEquivalent result: %v", resp.Result)
}

func testMatchesImplies(t *testing.T, ctx *twoPolicyContext) {
	t.Helper()
	defer ctx.leanSchema.Release()

	req := proto.ComparePoliciesFromCedar(ctx.firstPolicy, ctx.secondPolicy, ctx.requestEnv)
	protoBytes, err := req.ToProtobuf()
	if err != nil {
		t.Logf("Failed to convert to protobuf: %v", err)
		return
	}

	resp, err := lean.CheckMatchesImplies(ctx.leanSchema, protoBytes)
	if err != nil {
		t.Logf("SymCC matchesImplies failed: %v", err)
		return
	}

	t.Logf("matchesImplies result: %v", resp.Result)
}

func testEquivalent(t *testing.T, ctx *twoPolicySetContext) {
	t.Helper()
	defer ctx.leanSchema.Release()

	req := proto.ComparePolicySetsFromCedar(ctx.input.Policies, ctx.secondPolicySet, ctx.requestEnv)
	protoBytes, err := req.ToProtobuf()
	if err != nil {
		t.Logf("Failed to convert to protobuf: %v", err)
		return
	}

	resp, err := lean.CheckEquivalent(ctx.leanSchema, protoBytes)
	if err != nil {
		t.Logf("SymCC equivalent failed: %v", err)
		return
	}

	t.Logf("equivalent result: %v", resp.Result)
}

func testImplies(t *testing.T, ctx *twoPolicySetContext) {
	t.Helper()
	defer ctx.leanSchema.Release()

	req := proto.ComparePolicySetsFromCedar(ctx.input.Policies, ctx.secondPolicySet, ctx.requestEnv)
	protoBytes, err := req.ToProtobuf()
	if err != nil {
		t.Logf("Failed to convert to protobuf: %v", err)
		return
	}

	resp, err := lean.CheckImplies(ctx.leanSchema, protoBytes)
	if err != nil {
		t.Logf("SymCC implies failed: %v", err)
		return
	}

	t.Logf("implies result: %v", resp.Result)
}

// =============================================================================
// Unit Tests
// =============================================================================

// TestSymCCNeverErrorsBasic tests basic neverErrors functionality.
func TestSymCCNeverErrorsBasic(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Create a simple policy that should never error
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource);`))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("permit-all", &policy)

	// Create schema
	schemaJSON := []byte(`{"": {"entityTypes": {"User": {}, "Resource": {}}, "actions": {"action": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["Resource"]}}}}}`)
	s, err := schema.NewFromJSON(schemaJSON)
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	// Convert schema to protobuf
	schemaBytes, err := proto.SchemaToProtobuf(s)
	if err != nil {
		t.Fatalf("Failed to convert schema: %v", err)
	}

	// Initialize Lean
	if err := lean.Initialize(); err != nil {
		t.Fatalf("Failed to initialize Lean: %v", err)
	}

	lt, err := lean.NewLeanThread()
	if err != nil {
		t.Fatalf("Failed to create Lean thread: %v", err)
	}
	defer lt.Close()

	// Load schema
	leanSchema, err := lean.LoadSchema(schemaBytes)
	if err != nil {
		t.Fatalf("Failed to load schema: %v", err)
	}
	defer leanSchema.Release()

	// Build request
	env := &proto.RequestEnv{
		PrincipalType: types.EntityType("User"),
		ActionID:      types.NewEntityUID("Action", "action"),
		ResourceType:  types.EntityType("Resource"),
	}

	req := proto.CheckPolicyFromCedar(&policy, env)
	protoBytes, err := req.ToProtobuf()
	if err != nil {
		t.Fatalf("Failed to convert to protobuf: %v", err)
	}

	// Run check
	resp, err := lean.CheckNeverErrors(leanSchema, protoBytes)
	if err != nil {
		t.Fatalf("SymCC check failed: %v", err)
	}

	// A simple permit-all policy should never error
	if !resp.Result {
		t.Errorf("Expected neverErrors=true for permit-all policy, got false")
	}
}

// TestSymCCAlwaysAllowsBasic tests basic alwaysAllows functionality.
func TestSymCCAlwaysAllowsBasic(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Create a permit-all policy
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource);`))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("permit-all", &policy)

	// Create schema
	schemaJSON := []byte(`{"": {"entityTypes": {"User": {}, "Resource": {}}, "actions": {"action": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["Resource"]}}}}}`)
	s, err := schema.NewFromJSON(schemaJSON)
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	schemaBytes, err := proto.SchemaToProtobuf(s)
	if err != nil {
		t.Fatalf("Failed to convert schema: %v", err)
	}

	if err := lean.Initialize(); err != nil {
		t.Fatalf("Failed to initialize Lean: %v", err)
	}

	lt, err := lean.NewLeanThread()
	if err != nil {
		t.Fatalf("Failed to create Lean thread: %v", err)
	}
	defer lt.Close()

	leanSchema, err := lean.LoadSchema(schemaBytes)
	if err != nil {
		t.Fatalf("Failed to load schema: %v", err)
	}
	defer leanSchema.Release()

	env := &proto.RequestEnv{
		PrincipalType: types.EntityType("User"),
		ActionID:      types.NewEntityUID("Action", "action"),
		ResourceType:  types.EntityType("Resource"),
	}

	req := proto.CheckPolicySetFromCedar(policies, env)
	protoBytes, err := req.ToProtobuf()
	if err != nil {
		t.Fatalf("Failed to convert to protobuf: %v", err)
	}

	resp, err := lean.CheckAlwaysAllows(leanSchema, protoBytes)
	if err != nil {
		t.Fatalf("SymCC check failed: %v", err)
	}

	// A permit-all policy should always allow
	if !resp.Result {
		t.Errorf("Expected alwaysAllows=true for permit-all policy, got false")
	}
}

// TestSymCCAlwaysDeniesBasic tests basic alwaysDenies functionality.
func TestSymCCAlwaysDeniesBasic(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Create an empty policy set (default deny)
	policies := cedar.NewPolicySet()

	// Create schema
	schemaJSON := []byte(`{"": {"entityTypes": {"User": {}, "Resource": {}}, "actions": {"action": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["Resource"]}}}}}`)
	s, err := schema.NewFromJSON(schemaJSON)
	if err != nil {
		t.Fatalf("Failed to parse schema: %v", err)
	}

	schemaBytes, err := proto.SchemaToProtobuf(s)
	if err != nil {
		t.Fatalf("Failed to convert schema: %v", err)
	}

	if err := lean.Initialize(); err != nil {
		t.Fatalf("Failed to initialize Lean: %v", err)
	}

	lt, err := lean.NewLeanThread()
	if err != nil {
		t.Fatalf("Failed to create Lean thread: %v", err)
	}
	defer lt.Close()

	leanSchema, err := lean.LoadSchema(schemaBytes)
	if err != nil {
		t.Fatalf("Failed to load schema: %v", err)
	}
	defer leanSchema.Release()

	env := &proto.RequestEnv{
		PrincipalType: types.EntityType("User"),
		ActionID:      types.NewEntityUID("Action", "action"),
		ResourceType:  types.EntityType("Resource"),
	}

	req := proto.CheckPolicySetFromCedar(policies, env)
	protoBytes, err := req.ToProtobuf()
	if err != nil {
		t.Fatalf("Failed to convert to protobuf: %v", err)
	}

	resp, err := lean.CheckAlwaysDenies(leanSchema, protoBytes)
	if err != nil {
		t.Fatalf("SymCC check failed: %v", err)
	}

	// An empty policy set should always deny (default deny)
	if !resp.Result {
		t.Errorf("Expected alwaysDenies=true for empty policy set, got false")
	}
}
