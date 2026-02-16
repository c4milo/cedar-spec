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

// DRT variants of authorization theorems that verify cedar-go agrees with
// the Lean formalization on every authorization call. The theorem properties
// are mathematically proven in Lean (Cedar/Thm/Authorization.lean), so if
// cedar-go matches Lean, it satisfies them too.

import (
	"runtime"
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/comparison"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/lean"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/proto"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/typegen"
)

// authorizeWithLean runs authorization through both cedar-go and Lean,
// compares the results, and returns the cedar-go result.
func authorizeWithLean(t *testing.T, policies *cedar.PolicySet, entities types.EntityMap, req cedar.Request, config comparison.ComparisonConfig) (cedar.Decision, types.Diagnostic) {
	t.Helper()

	decision, diag := cedar.Authorize(policies, entities, req)

	authReq := proto.PolicySetFromCedar(policies, entities, &req)
	protoBytes, err := authReq.ToProtobuf()
	if err != nil {
		return decision, diag
	}

	if err := lean.Initialize(); err != nil {
		t.Fatalf("Lean init failed: %v", err)
	}

	lt, err := lean.NewLeanThread()
	if err != nil {
		t.Fatalf("Lean thread failed: %v", err)
	}
	defer lt.Close()

	leanResp, err := lean.IsAuthorized(protoBytes)
	if err != nil {
		return decision, diag
	}

	goResult := toAuthorizationResult(decision, diag)
	leanResult := toLeanAuthorizationResult(leanResp)
	diffs := comparison.CompareAuthorization(goResult, leanResult, config)
	if len(diffs) > 0 {
		t.Errorf("DRT divergence: %s", comparison.FormatDifferences(diffs))
	}

	return decision, diag
}

// FuzzErrorIrrelevanceDRT verifies error_irrelevance against both cedar-go and Lean.
func FuzzErrorIrrelevanceDRT(f *testing.F) {
	f.Add([]byte("error-irrel-drt-seed-1"))
	f.Add(make([]byte, 64))

	config := comparison.DefaultConfig()
	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 16 {
			return
		}

		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		input, err := inputGen.Generate(data)
		if err != nil {
			return
		}

		request := buildRequest(input)
		decision, diag := authorizeWithLean(t, input.Policies, input.Entities.Entities, request, config)

		if len(diag.Errors) == 0 {
			return
		}

		erroring := make(map[types.PolicyID]bool)
		for _, diagErr := range diag.Errors {
			erroring[diagErr.PolicyID] = true
		}

		replacedPolicies := cedar.NewPolicySet()
		for id, p := range input.Policies.All() {
			if erroring[id] {
				var replacement cedar.Policy
				if p.Effect() == cedar.Permit {
					if err := replacement.UnmarshalCedar([]byte(`permit(principal, action, resource) when { false };`)); err != nil {
						return
					}
				} else {
					if err := replacement.UnmarshalCedar([]byte(`forbid(principal, action, resource) when { false };`)); err != nil {
						return
					}
				}
				replacedPolicies.Add(id, &replacement)
			} else {
				replacedPolicies.Add(id, p)
			}
		}

		newDecision, _ := authorizeWithLean(t, replacedPolicies, input.Entities.Entities, request, config)

		if decision != newDecision {
			t.Errorf("error_irrelevance violated (DRT):\n"+
				"Original decision=%v, after replacing %d erroring policies: %v\n"+
				"Request: %+v", decision, len(diag.Errors), newDecision, request)
		}
	})
}

// FuzzRemovingForbidPreservesAllowDRT verifies removing_forbid_preserves_allow against Lean.
func FuzzRemovingForbidPreservesAllowDRT(f *testing.F) {
	f.Add([]byte("rm-forbid-drt-seed-1"))
	f.Add(make([]byte, 64))

	config := comparison.DefaultConfig()
	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 16 {
			return
		}

		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		input, err := inputGen.Generate(data)
		if err != nil {
			return
		}

		request := buildRequest(input)
		decision, _ := authorizeWithLean(t, input.Policies, input.Entities.Entities, request, config)

		if decision != cedar.Allow {
			return
		}

		for id, p := range input.Policies.All() {
			if p.Effect() != cedar.Forbid {
				continue
			}

			reduced := cedar.NewPolicySet()
			for id2, p2 := range input.Policies.All() {
				if id2 != id {
					reduced.Add(id2, p2)
				}
			}

			newDecision, _ := authorizeWithLean(t, reduced, input.Entities.Entities, request, config)
			if newDecision != cedar.Allow {
				t.Errorf("removing_forbid_preserves_allow violated (DRT):\n"+
					"Removing forbid %q flipped Allow to %v\nRequest: %+v", id, newDecision, request)
			}
		}
	})
}

// FuzzRemovingPermitPreservesDenyDRT verifies removing_permit_preserves_deny against Lean.
func FuzzRemovingPermitPreservesDenyDRT(f *testing.F) {
	f.Add([]byte("rm-permit-drt-seed-1"))
	f.Add(make([]byte, 64))

	config := comparison.DefaultConfig()
	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 16 {
			return
		}

		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		input, err := inputGen.Generate(data)
		if err != nil {
			return
		}

		request := buildRequest(input)
		decision, _ := authorizeWithLean(t, input.Policies, input.Entities.Entities, request, config)

		if decision != cedar.Deny {
			return
		}

		for id, p := range input.Policies.All() {
			if p.Effect() != cedar.Permit {
				continue
			}

			reduced := cedar.NewPolicySet()
			for id2, p2 := range input.Policies.All() {
				if id2 != id {
					reduced.Add(id2, p2)
				}
			}

			newDecision, _ := authorizeWithLean(t, reduced, input.Entities.Entities, request, config)
			if newDecision != cedar.Deny {
				t.Errorf("removing_permit_preserves_deny violated (DRT):\n"+
					"Removing permit %q flipped Deny to %v\nRequest: %+v", id, newDecision, request)
			}
		}
	})
}

// FuzzDecisionDecompositionDRT verifies decision_decomposition against Lean.
func FuzzDecisionDecompositionDRT(f *testing.F) {
	f.Add([]byte("decomp-drt-seed-1"))
	f.Add(make([]byte, 64))

	config := comparison.DefaultConfig()
	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 16 {
			return
		}

		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		input, err := inputGen.Generate(data)
		if err != nil {
			return
		}

		request := buildRequest(input)
		decision, diag := authorizeWithLean(t, input.Policies, input.Entities.Entities, request, config)

		hasSatisfiedForbid := (decision == cedar.Deny && len(diag.Reasons) > 0)

		var hasSatisfiedPermit bool
		if decision == cedar.Allow {
			hasSatisfiedPermit = true
		} else {
			permitOnly := cedar.NewPolicySet()
			for id, p := range input.Policies.All() {
				if p.Effect() == cedar.Permit {
					permitOnly.Add(id, p)
				}
			}
			permitDecision, _ := authorizeWithLean(t, permitOnly, input.Entities.Entities, request, config)
			hasSatisfiedPermit = (permitDecision == cedar.Allow)
		}

		canonical := cedar.NewPolicySet()
		if hasSatisfiedForbid {
			var forbidAll cedar.Policy
			if err := forbidAll.UnmarshalCedar([]byte(`forbid(principal, action, resource);`)); err != nil {
				return
			}
			canonical.Add("canonical-forbid", &forbidAll)
		}
		if hasSatisfiedPermit {
			var permitAll cedar.Policy
			if err := permitAll.UnmarshalCedar([]byte(`permit(principal, action, resource);`)); err != nil {
				return
			}
			canonical.Add("canonical-permit", &permitAll)
		}

		canonicalDecision, _ := authorizeWithLean(t, canonical, input.Entities.Entities, request, config)

		if decision != canonicalDecision {
			t.Errorf("decision_decomposition violated (DRT):\n"+
				"Original=%v, canonical=%v\n"+
				"hasSatisfiedForbid=%v, hasSatisfiedPermit=%v\nRequest: %+v",
				decision, canonicalDecision, hasSatisfiedForbid, hasSatisfiedPermit, request)
		}
	})
}
