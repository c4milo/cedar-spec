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

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/comparison"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/lean"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/proto"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/typegen"
)

// FuzzAuthorizationTypeDirected is a type-directed fuzz target for authorization.
// It generates well-typed schemas, entities, policies, and requests.
func FuzzAuthorizationTypeDirected(f *testing.F) {
	// Add seeds
	f.Add([]byte("seed1"))
	f.Add([]byte("type-directed-test-input"))
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 256))

	config := comparison.DefaultConfig()
	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 16 {
			return // Need minimum data for generation
		}

		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		// Generate type-directed input
		input, err := inputGen.GenerateForAuthorization(data)
		if err != nil {
			return // Generation failed, skip
		}

		// Run cedar-go authorization for each request
		for _, req := range input.Requests {
			goDecision, goDiag := cedar.Authorize(input.Policies, input.Entities.Entities, req)

			// Run Lean authorization
			leanResp := runTypeDirectedLeanAuthorization(t, input, req)
			if leanResp == nil {
				continue // Lean error, skip this request
			}

			// Compare results
			goResult := toAuthorizationResult(goDecision, goDiag)
			leanResult := toLeanAuthorizationResult(leanResp)

			diffs := comparison.CompareAuthorization(goResult, leanResult, config)
			if len(diffs) > 0 {
				t.Errorf("Type-directed authorization divergence:\n%s\nSchema: %s\nRequest: %+v",
					comparison.FormatDifferences(diffs), string(input.SchemaJSON), req)
			}
		}
	})
}

func runTypeDirectedLeanAuthorization(t *testing.T, input *typegen.TypeDirectedInput, req cedar.Request) *lean.AuthorizationResponse {
	t.Helper()

	authReq := proto.PolicySetFromCedar(input.Policies, input.Entities.Entities, &req)
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
