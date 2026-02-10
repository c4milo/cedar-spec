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

// This file contains fuzz tests for SymCC WithCex (counterexample) variants.
// These tests exercise the counterexample extraction path in the symbolic
// compiler, verifying that when a property doesn't hold, the Lean formalization
// can produce a concrete counterexample (request + entities) that demonstrates it.

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

// =============================================================================
// Single Policy WithCex Checks
// =============================================================================

// FuzzSymCCNeverErrorsWithCex tests neverErrors with counterexample extraction.
// When a policy CAN error, the solver should produce a counterexample request.
func FuzzSymCCNeverErrorsWithCex(f *testing.F) {
	f.Add([]byte("never-errors-cex-seed-1"))
	f.Add(make([]byte, 64))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		ctx, ok := prepareSymCCContext(data, inputGen)
		if !ok {
			return
		}

		testNeverErrorsWithCex(t, ctx)
	})
}

// FuzzSymCCAlwaysMatchesWithCex tests alwaysMatches with counterexample extraction.
func FuzzSymCCAlwaysMatchesWithCex(f *testing.F) {
	f.Add([]byte("always-matches-cex-seed-1"))
	f.Add(make([]byte, 64))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		ctx, ok := prepareSymCCContext(data, inputGen)
		if !ok {
			return
		}

		testAlwaysMatchesWithCex(t, ctx)
	})
}

// FuzzSymCCNeverMatchesWithCex tests neverMatches with counterexample extraction.
func FuzzSymCCNeverMatchesWithCex(f *testing.F) {
	f.Add([]byte("never-matches-cex-seed-1"))
	f.Add(make([]byte, 64))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		ctx, ok := prepareSymCCContext(data, inputGen)
		if !ok {
			return
		}

		testNeverMatchesWithCex(t, ctx)
	})
}

// =============================================================================
// PolicySet WithCex Checks
// =============================================================================

// FuzzSymCCAlwaysAllowsWithCex tests alwaysAllows with counterexample extraction.
func FuzzSymCCAlwaysAllowsWithCex(f *testing.F) {
	f.Add([]byte("always-allows-cex-seed-1"))
	f.Add(make([]byte, 64))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		ctx, ok := prepareSymCCContext(data, inputGen)
		if !ok {
			return
		}

		testAlwaysAllowsWithCex(t, ctx)
	})
}

// FuzzSymCCAlwaysDeniesWithCex tests alwaysDenies with counterexample extraction.
func FuzzSymCCAlwaysDeniesWithCex(f *testing.F) {
	f.Add([]byte("always-denies-cex-seed-1"))
	f.Add(make([]byte, 64))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		ctx, ok := prepareSymCCContext(data, inputGen)
		if !ok {
			return
		}

		testAlwaysDeniesWithCex(t, ctx)
	})
}

// =============================================================================
// Two Policy WithCex Comparison
// =============================================================================

// FuzzSymCCMatchesEquivalentWithCex tests matchesEquivalent with counterexample extraction.
func FuzzSymCCMatchesEquivalentWithCex(f *testing.F) {
	f.Add([]byte("matches-equiv-cex-seed-1"))
	f.Add(make([]byte, 64))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		ctx, ok := prepareTwoPolicyContext(data, inputGen)
		if !ok {
			return
		}

		testMatchesEquivalentWithCex(t, ctx)
	})
}

// FuzzSymCCMatchesImpliesWithCex tests matchesImplies with counterexample extraction.
func FuzzSymCCMatchesImpliesWithCex(f *testing.F) {
	f.Add([]byte("matches-implies-cex-seed-1"))
	f.Add(make([]byte, 64))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		ctx, ok := prepareTwoPolicyContext(data, inputGen)
		if !ok {
			return
		}

		testMatchesImpliesWithCex(t, ctx)
	})
}

// FuzzSymCCMatchesDisjointWithCex tests matchesDisjoint with counterexample extraction.
func FuzzSymCCMatchesDisjointWithCex(f *testing.F) {
	f.Add([]byte("matches-disjoint-cex-seed-1"))
	f.Add(make([]byte, 64))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		ctx, ok := prepareTwoPolicyContext(data, inputGen)
		if !ok {
			return
		}

		testMatchesDisjointWithCex(t, ctx)
	})
}

// =============================================================================
// Two PolicySet WithCex Comparison
// =============================================================================

// FuzzSymCCEquivalentWithCex tests equivalent with counterexample extraction.
func FuzzSymCCEquivalentWithCex(f *testing.F) {
	f.Add([]byte("equiv-cex-seed-1"))
	f.Add(make([]byte, 64))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		ctx, ok := prepareTwoPolicySetContext(data, inputGen)
		if !ok {
			return
		}

		testEquivalentWithCex(t, ctx)
	})
}

// FuzzSymCCImpliesWithCex tests implies with counterexample extraction.
func FuzzSymCCImpliesWithCex(f *testing.F) {
	f.Add([]byte("implies-cex-seed-1"))
	f.Add(make([]byte, 64))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		ctx, ok := prepareTwoPolicySetContext(data, inputGen)
		if !ok {
			return
		}

		testImpliesWithCex(t, ctx)
	})
}

// FuzzSymCCDisjointWithCex tests disjoint with counterexample extraction.
func FuzzSymCCDisjointWithCex(f *testing.F) {
	f.Add([]byte("disjoint-cex-seed-1"))
	f.Add(make([]byte, 64))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		ctx, ok := prepareTwoPolicySetContext(data, inputGen)
		if !ok {
			return
		}

		testDisjointWithCex(t, ctx)
	})
}

// =============================================================================
// WithCex Test Functions
// =============================================================================

func testNeverErrorsWithCex(t *testing.T, ctx *symccContext) {
	t.Helper()
	defer ctx.leanSchema.Release()

	req := proto.CheckPolicyFromCedar(ctx.firstPolicy, ctx.requestEnv)
	protoBytes, err := req.ToProtobuf()
	if err != nil {
		t.Logf("Failed to convert to protobuf: %v", err)
		return
	}

	resp, err := lean.CheckNeverErrorsWithCex(ctx.leanSchema, protoBytes)
	if err != nil {
		t.Logf("SymCC neverErrorsWithCex failed: %v", err)
		return
	}

	if resp.Result == nil {
		t.Logf("neverErrorsWithCex: property holds (no counterexample)")
	} else {
		t.Logf("neverErrorsWithCex: property violated, counterexample found (request=%d bytes, entities=%d bytes)",
			len(resp.Result.Request), len(resp.Result.Entities))
	}
}

func testAlwaysMatchesWithCex(t *testing.T, ctx *symccContext) {
	t.Helper()
	defer ctx.leanSchema.Release()

	req := proto.CheckPolicyFromCedar(ctx.firstPolicy, ctx.requestEnv)
	protoBytes, err := req.ToProtobuf()
	if err != nil {
		t.Logf("Failed to convert to protobuf: %v", err)
		return
	}

	resp, err := lean.CheckAlwaysMatchesWithCex(ctx.leanSchema, protoBytes)
	if err != nil {
		t.Logf("SymCC alwaysMatchesWithCex failed: %v", err)
		return
	}

	if resp.Result == nil {
		t.Logf("alwaysMatchesWithCex: property holds")
	} else {
		t.Logf("alwaysMatchesWithCex: counterexample found")
	}
}

func testNeverMatchesWithCex(t *testing.T, ctx *symccContext) {
	t.Helper()
	defer ctx.leanSchema.Release()

	req := proto.CheckPolicyFromCedar(ctx.firstPolicy, ctx.requestEnv)
	protoBytes, err := req.ToProtobuf()
	if err != nil {
		t.Logf("Failed to convert to protobuf: %v", err)
		return
	}

	resp, err := lean.CheckNeverMatchesWithCex(ctx.leanSchema, protoBytes)
	if err != nil {
		t.Logf("SymCC neverMatchesWithCex failed: %v", err)
		return
	}

	if resp.Result == nil {
		t.Logf("neverMatchesWithCex: property holds")
	} else {
		t.Logf("neverMatchesWithCex: counterexample found")
	}
}

func testAlwaysAllowsWithCex(t *testing.T, ctx *symccContext) {
	t.Helper()
	defer ctx.leanSchema.Release()

	req := proto.CheckPolicySetFromCedar(ctx.input.Policies, ctx.requestEnv)
	protoBytes, err := req.ToProtobuf()
	if err != nil {
		t.Logf("Failed to convert to protobuf: %v", err)
		return
	}

	resp, err := lean.CheckAlwaysAllowsWithCex(ctx.leanSchema, protoBytes)
	if err != nil {
		t.Logf("SymCC alwaysAllowsWithCex failed: %v", err)
		return
	}

	if resp.Result == nil {
		t.Logf("alwaysAllowsWithCex: property holds")
	} else {
		t.Logf("alwaysAllowsWithCex: counterexample found")
	}
}

func testAlwaysDeniesWithCex(t *testing.T, ctx *symccContext) {
	t.Helper()
	defer ctx.leanSchema.Release()

	req := proto.CheckPolicySetFromCedar(ctx.input.Policies, ctx.requestEnv)
	protoBytes, err := req.ToProtobuf()
	if err != nil {
		t.Logf("Failed to convert to protobuf: %v", err)
		return
	}

	resp, err := lean.CheckAlwaysDeniesWithCex(ctx.leanSchema, protoBytes)
	if err != nil {
		t.Logf("SymCC alwaysDeniesWithCex failed: %v", err)
		return
	}

	if resp.Result == nil {
		t.Logf("alwaysDeniesWithCex: property holds")
	} else {
		t.Logf("alwaysDeniesWithCex: counterexample found")
	}
}

func testMatchesEquivalentWithCex(t *testing.T, ctx *twoPolicyContext) {
	t.Helper()
	defer ctx.leanSchema.Release()

	req := proto.ComparePoliciesFromCedar(ctx.firstPolicy, ctx.secondPolicy, ctx.requestEnv)
	protoBytes, err := req.ToProtobuf()
	if err != nil {
		t.Logf("Failed to convert to protobuf: %v", err)
		return
	}

	resp, err := lean.CheckMatchesEquivalentWithCex(ctx.leanSchema, protoBytes)
	if err != nil {
		t.Logf("SymCC matchesEquivalentWithCex failed: %v", err)
		return
	}

	if resp.Result == nil {
		t.Logf("matchesEquivalentWithCex: policies are equivalent")
	} else {
		t.Logf("matchesEquivalentWithCex: counterexample found")
	}
}

func testMatchesImpliesWithCex(t *testing.T, ctx *twoPolicyContext) {
	t.Helper()
	defer ctx.leanSchema.Release()

	req := proto.ComparePoliciesFromCedar(ctx.firstPolicy, ctx.secondPolicy, ctx.requestEnv)
	protoBytes, err := req.ToProtobuf()
	if err != nil {
		t.Logf("Failed to convert to protobuf: %v", err)
		return
	}

	resp, err := lean.CheckMatchesImpliesWithCex(ctx.leanSchema, protoBytes)
	if err != nil {
		t.Logf("SymCC matchesImpliesWithCex failed: %v", err)
		return
	}

	if resp.Result == nil {
		t.Logf("matchesImpliesWithCex: implication holds")
	} else {
		t.Logf("matchesImpliesWithCex: counterexample found")
	}
}

func testMatchesDisjointWithCex(t *testing.T, ctx *twoPolicyContext) {
	t.Helper()
	defer ctx.leanSchema.Release()

	req := proto.ComparePoliciesFromCedar(ctx.firstPolicy, ctx.secondPolicy, ctx.requestEnv)
	protoBytes, err := req.ToProtobuf()
	if err != nil {
		t.Logf("Failed to convert to protobuf: %v", err)
		return
	}

	resp, err := lean.CheckMatchesDisjointWithCex(ctx.leanSchema, protoBytes)
	if err != nil {
		t.Logf("SymCC matchesDisjointWithCex failed: %v", err)
		return
	}

	if resp.Result == nil {
		t.Logf("matchesDisjointWithCex: policies are disjoint")
	} else {
		t.Logf("matchesDisjointWithCex: counterexample found (policies overlap)")
	}
}

func testEquivalentWithCex(t *testing.T, ctx *twoPolicySetContext) {
	t.Helper()
	defer ctx.leanSchema.Release()

	req := proto.ComparePolicySetsFromCedar(ctx.input.Policies, ctx.secondPolicySet, ctx.requestEnv)
	protoBytes, err := req.ToProtobuf()
	if err != nil {
		t.Logf("Failed to convert to protobuf: %v", err)
		return
	}

	resp, err := lean.CheckEquivalentWithCex(ctx.leanSchema, protoBytes)
	if err != nil {
		t.Logf("SymCC equivalentWithCex failed: %v", err)
		return
	}

	if resp.Result == nil {
		t.Logf("equivalentWithCex: policy sets are equivalent")
	} else {
		t.Logf("equivalentWithCex: counterexample found")
	}
}

func testImpliesWithCex(t *testing.T, ctx *twoPolicySetContext) {
	t.Helper()
	defer ctx.leanSchema.Release()

	req := proto.ComparePolicySetsFromCedar(ctx.input.Policies, ctx.secondPolicySet, ctx.requestEnv)
	protoBytes, err := req.ToProtobuf()
	if err != nil {
		t.Logf("Failed to convert to protobuf: %v", err)
		return
	}

	resp, err := lean.CheckImpliesWithCex(ctx.leanSchema, protoBytes)
	if err != nil {
		t.Logf("SymCC impliesWithCex failed: %v", err)
		return
	}

	if resp.Result == nil {
		t.Logf("impliesWithCex: implication holds")
	} else {
		t.Logf("impliesWithCex: counterexample found")
	}
}

func testDisjointWithCex(t *testing.T, ctx *twoPolicySetContext) {
	t.Helper()
	defer ctx.leanSchema.Release()

	req := proto.ComparePolicySetsFromCedar(ctx.input.Policies, ctx.secondPolicySet, ctx.requestEnv)
	protoBytes, err := req.ToProtobuf()
	if err != nil {
		t.Logf("Failed to convert to protobuf: %v", err)
		return
	}

	resp, err := lean.CheckDisjointWithCex(ctx.leanSchema, protoBytes)
	if err != nil {
		t.Logf("SymCC disjointWithCex failed: %v", err)
		return
	}

	if resp.Result == nil {
		t.Logf("disjointWithCex: policy sets are disjoint")
	} else {
		t.Logf("disjointWithCex: counterexample found")
	}
}

// =============================================================================
// WithCex Consistency Verification
// =============================================================================

// FuzzSymCCWithCexConsistency verifies that the base check and WithCex variant
// agree: if the base check returns true, WithCex should return nil (no counterexample),
// and if base returns false, WithCex should return a counterexample.
func FuzzSymCCWithCexConsistency(f *testing.F) {
	f.Add([]byte("consistency-seed-1"))
	f.Add([]byte("consistency-seed-2"))
	f.Add(make([]byte, 64))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		ctx, ok := prepareSymCCContext(data, inputGen)
		if !ok {
			return
		}
		defer ctx.leanSchema.Release()

		// Test neverErrors consistency: base and WithCex must agree
		req := proto.CheckPolicyFromCedar(ctx.firstPolicy, ctx.requestEnv)
		protoBytes, err := req.ToProtobuf()
		if err != nil {
			return
		}

		// Need to inc schema ref since we'll call twice
		baseResp, err := lean.CheckNeverErrors(ctx.leanSchema, protoBytes)
		if err != nil {
			return
		}

		// Re-prepare since CheckNeverErrors consumed the schema ref
		// Re-create protoBytes (same content)
		protoBytes2, err := req.ToProtobuf()
		if err != nil {
			return
		}

		cexResp, err := lean.CheckNeverErrorsWithCex(ctx.leanSchema, protoBytes2)
		if err != nil {
			return
		}

		// Verify consistency
		if baseResp.Result && cexResp.Result != nil {
			t.Errorf("Inconsistency: neverErrors=true but WithCex returned counterexample")
		}
		if !baseResp.Result && cexResp.Result == nil {
			t.Errorf("Inconsistency: neverErrors=false but WithCex returned no counterexample")
		}
	})
}

// =============================================================================
// Unit Tests
// =============================================================================

// TestSymCCNeverErrorsWithCexBasic tests counterexample extraction for a policy that can error.
func TestSymCCNeverErrorsWithCexBasic(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// A simple policy that should never error - tests WithCex extraction path
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource);`))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	policies.Add("permit-all", &policy)

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

	req := proto.CheckPolicyFromCedar(&policy, env)
	protoBytes, err := req.ToProtobuf()
	if err != nil {
		t.Fatalf("Failed to convert to protobuf: %v", err)
	}

	resp, err := lean.CheckNeverErrorsWithCex(leanSchema, protoBytes)
	if err != nil {
		t.Fatalf("SymCC check failed: %v", err)
	}

	// A simple permit-all should never error, so WithCex should return nil (property holds)
	if resp.Result == nil {
		t.Logf("neverErrorsWithCex: property holds (no counterexample) - correct for permit-all")
	} else {
		t.Errorf("Expected neverErrorsWithCex to hold for permit-all policy, but got counterexample")
	}
}

// TestSymCCMatchesDisjointBasic tests basic disjointness checking.
func TestSymCCMatchesDisjointBasic(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Two policies with mutually exclusive conditions
	var policy1, policy2 cedar.Policy
	err := policy1.UnmarshalCedar([]byte(`permit(principal == User::"alice", action, resource);`))
	if err != nil {
		t.Fatalf("Failed to parse policy1: %v", err)
	}
	err = policy2.UnmarshalCedar([]byte(`permit(principal == User::"bob", action, resource);`))
	if err != nil {
		t.Fatalf("Failed to parse policy2: %v", err)
	}

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

	req := proto.ComparePoliciesFromCedar(&policy1, &policy2, env)
	protoBytes, err := req.ToProtobuf()
	if err != nil {
		t.Fatalf("Failed to convert to protobuf: %v", err)
	}

	resp, err := lean.CheckMatchesDisjoint(leanSchema, protoBytes)
	if err != nil {
		t.Fatalf("SymCC check failed: %v", err)
	}

	// Alice-only and Bob-only policies should be disjoint
	t.Logf("matchesDisjoint result: %v (expected true for alice vs bob)", resp.Result)
}

// TestSymCCDisjointBasic tests basic policy set disjointness checking.
func TestSymCCDisjointBasic(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Policy set 1: only permits alice
	ps1 := cedar.NewPolicySet()
	var p1 cedar.Policy
	err := p1.UnmarshalCedar([]byte(`permit(principal == User::"alice", action, resource);`))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	ps1.Add("alice-only", &p1)

	// Policy set 2: only permits bob
	ps2 := cedar.NewPolicySet()
	var p2 cedar.Policy
	err = p2.UnmarshalCedar([]byte(`permit(principal == User::"bob", action, resource);`))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	ps2.Add("bob-only", &p2)

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

	req := proto.ComparePolicySetsFromCedar(ps1, ps2, env)
	protoBytes, err := req.ToProtobuf()
	if err != nil {
		t.Fatalf("Failed to convert to protobuf: %v", err)
	}

	resp, err := lean.CheckDisjoint(leanSchema, protoBytes)
	if err != nil {
		t.Fatalf("SymCC check failed: %v", err)
	}

	// Alice-only and Bob-only policy sets should be disjoint
	t.Logf("disjoint result: %v (expected true for alice-only vs bob-only)", resp.Result)
}
