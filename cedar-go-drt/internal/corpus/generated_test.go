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

package corpus

import (
	"encoding/json"
	"testing"

	"github.com/cedar-policy/cedar-go"
)

func TestGenerateEdgeCases(t *testing.T) {
	cases := GenerateEdgeCases()

	if len(cases) == 0 {
		t.Fatal("GenerateEdgeCases returned no cases")
	}

	// Verify each edge case is valid
	for i, tc := range cases {
		// Verify JSON is valid
		var req GoRequest
		if err := json.Unmarshal(tc.Request, &req); err != nil {
			t.Errorf("case %d: invalid request JSON: %v", i, err)
			continue
		}

		// Verify entities is valid JSON
		var entities []any
		if err := json.Unmarshal(tc.Entities, &entities); err != nil {
			t.Errorf("case %d: invalid entities JSON: %v", i, err)
			continue
		}

		// Verify policies can be parsed
		for j, policyStr := range tc.Policies {
			var policy cedar.Policy
			if err := policy.UnmarshalCedar([]byte(policyStr)); err != nil {
				t.Errorf("case %d policy %d: parse error: %v\npolicy: %s", i, j, err, policyStr)
			}
		}
	}

	t.Logf("Generated %d valid edge cases", len(cases))
}

type edgeCaseFlags struct {
	hasEmptyPolicySet     bool
	hasForbidTrumpsPermit bool
	hasEntityHierarchy    bool
	hasContextCondition   bool
}

func TestGenerateEdgeCasesContent(t *testing.T) {
	cases := GenerateEdgeCases()
	flags := analyzeEdgeCases(cases)
	verifyEdgeCaseFlags(t, flags)
}

func analyzeEdgeCases(cases []TestCase) edgeCaseFlags {
	var flags edgeCaseFlags

	for _, tc := range cases {
		analyzeTestCase(tc, &flags)
	}

	return flags
}

func analyzeTestCase(tc TestCase, flags *edgeCaseFlags) {
	if len(tc.Policies) == 0 {
		flags.hasEmptyPolicySet = true
	}

	var hasForbid, hasPermit bool
	for _, p := range tc.Policies {
		analyzePolicyContent(p, flags, &hasForbid, &hasPermit)
	}

	if hasForbid && hasPermit {
		flags.hasForbidTrumpsPermit = true
	}
}

func analyzePolicyContent(policy string, flags *edgeCaseFlags, hasForbid, hasPermit *bool) {
	if containsStr(policy, "forbid") {
		*hasForbid = true
	}
	if containsStr(policy, "permit") {
		*hasPermit = true
	}
	if containsStr(policy, "principal in Group") {
		flags.hasEntityHierarchy = true
	}
	if containsStr(policy, "context.") {
		flags.hasContextCondition = true
	}
}

func verifyEdgeCaseFlags(t *testing.T, flags edgeCaseFlags) {
	if !flags.hasEmptyPolicySet {
		t.Error("missing empty policy set edge case")
	}
	if !flags.hasForbidTrumpsPermit {
		t.Error("missing forbid trumps permit edge case")
	}
	if !flags.hasEntityHierarchy {
		t.Error("missing entity hierarchy edge case")
	}
	if !flags.hasContextCondition {
		t.Error("missing context condition edge case")
	}
}

func TestGenerateTypeDirectedCases(t *testing.T) {
	// Generate a small number of cases
	cases := GenerateTypeDirectedCases(5, false)

	if len(cases) == 0 {
		t.Fatal("GenerateTypeDirectedCases returned no cases")
	}

	// Verify each case is valid
	for i, tc := range cases {
		// Verify request JSON
		var req GoRequest
		if err := json.Unmarshal(tc.Request, &req); err != nil {
			t.Errorf("case %d: invalid request JSON: %v", i, err)
			continue
		}

		// Verify request has required fields
		if req.Principal.Type == "" {
			t.Errorf("case %d: principal type is empty", i)
		}
		if req.Action.Type == "" {
			t.Errorf("case %d: action type is empty", i)
		}
		if req.Resource.Type == "" {
			t.Errorf("case %d: resource type is empty", i)
		}

		// Verify policies exist
		if len(tc.Policies) == 0 {
			t.Errorf("case %d: no policies", i)
		}
	}

	t.Logf("Generated %d type-directed cases from 5 inputs", len(cases))
}

func TestGenerateValidationCases(t *testing.T) {
	cases := GenerateValidationCases(5, false)

	if len(cases) == 0 {
		t.Fatal("GenerateValidationCases returned no cases")
	}

	for i, tc := range cases {
		// Verify schema is non-empty
		if tc.Schema == "" {
			t.Errorf("case %d: empty schema", i)
		}

		// Verify policies exist
		if len(tc.Policies) == 0 {
			t.Errorf("case %d: no policies", i)
		}

		// Verify schema is valid JSON
		var schemaJSON any
		if err := json.Unmarshal([]byte(tc.Schema), &schemaJSON); err != nil {
			t.Errorf("case %d: invalid schema JSON: %v", i, err)
		}
	}

	t.Logf("Generated %d validation cases from 5 inputs", len(cases))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
