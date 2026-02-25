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
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/typegen"
)

// FuzzSwarmAuthorization uses swarm testing (Groce et al., ISSTA 2012) to find
// authorization divergences between cedar-go and the Lean formalization. Each
// fuzz iteration gets a fresh random SwarmConfig that independently enables or
// disables Cedar language features with 50% probability. This creates diverse
// configurations that can expose bugs masked by feature interactions.
func FuzzSwarmAuthorization(f *testing.F) {
	f.Add([]byte("swarm-auth-seed"))
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 256))

	config := comparison.DefaultConfig()
	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 32 {
			return // Need extra bytes for swarm config coin tosses
		}

		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		input, err := inputGen.GenerateSwarm(data)
		if err != nil {
			return
		}

		for _, req := range input.Requests {
			goDecision, goDiag := cedar.Authorize(input.Policies, input.Entities.Entities, req)

			leanResp := runTypeDirectedLeanAuthorization(t, input, req)
			if leanResp == nil {
				continue
			}

			goResult := toAuthorizationResult(goDecision, goDiag)
			leanResult := toLeanAuthorizationResult(leanResp)

			diffs := comparison.CompareAuthorization(goResult, leanResult, config)
			if len(diffs) > 0 {
				t.Errorf("Swarm authorization divergence:\n%s\nSchema: %s\nRequest: %+v",
					comparison.FormatDifferences(diffs), string(input.SchemaJSON), req)
			}
		}
	})
}
