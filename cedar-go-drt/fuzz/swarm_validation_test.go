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

	"github.com/cedar-policy/cedar-go/x/exp/schema"

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/comparison"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/typegen"
)

// FuzzSwarmValidation uses swarm testing (Groce et al., ISSTA 2012) to find
// validation divergences between cedar-go and the Lean formalization. Each
// fuzz iteration randomly enables/disables Cedar language features, creating
// diverse configurations that exercise different validation code paths.
func FuzzSwarmValidation(f *testing.F) {
	f.Add([]byte("swarm-val-seed"))
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 256))

	config := comparison.DefaultConfig()
	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 32 {
			return
		}

		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		input, err := inputGen.GenerateSwarm(data)
		if err != nil {
			return
		}

		s, schemaErr := schema.NewFromJSON(input.SchemaJSON)
		if schemaErr != nil {
			return
		}

		goResult := runTypeDirectedGoValidation(s, input.Policies)
		leanResult := buildTypeDirectedLeanResult(t, input)
		if leanResult == nil {
			return
		}

		diffs := comparison.CompareValidation(goResult, leanResult, config)
		if len(diffs) > 0 {
			policyStrings := marshalPoliciesForLog(input.Policies)
			t.Errorf("Swarm validation divergence:\n%s\nSchema: %s\nPolicies: %v",
				comparison.FormatValidationDifferences(diffs), string(input.SchemaJSON), policyStrings)
		}
		if err := comparison.CheckTypeSoundness(goResult, leanResult); err != nil {
			policyStrings := marshalPoliciesForLog(input.Policies)
			t.Errorf("Swarm type soundness violation: %v\nSchema: %s\nPolicies: %v",
				err, string(input.SchemaJSON), policyStrings)
		}
	})
}
