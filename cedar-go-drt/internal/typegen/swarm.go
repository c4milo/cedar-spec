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

package typegen

// SwarmConfig controls which features are enabled for a single test case.
//
// Following Groce et al. "Swarm Testing" (ISSTA 2012), each test case gets a
// fresh random configuration where each feature is independently enabled with
// 50% probability. This creates diverse configurations that explore different
// parts of the input space. Some features actively suppress bugs when present
// (active suppression), while others compete for space in finite tests and
// prevent deep exploration of any one feature (passive suppression). Randomly
// omitting features addresses both problems.
type SwarmConfig struct {
	// Schema features
	EnableExtensions  bool // decimal, ipaddr extension types
	EnableSetTypes    bool // Set<T> in schema type generation
	EnableRecordTypes bool // nested Record types in schema
	EnableHierarchy   bool // memberOf relationships between entity types
	EnableContext     bool // context attributes on actions

	// Policy features
	EnableForbid         bool // forbid policies (vs permit-only)
	EnableConditions     bool // when/unless clauses on policies
	EnableLogicalOps     bool // && and || in condition expressions
	EnableNegation       bool // ! operator in condition expressions
	EnableHasChecks      bool // principal/resource has attr
	EnableInChecks       bool // principal/resource in Entity
	EnableIsChecks       bool // principal/resource is Type
	EnableAttrCompare    bool // principal.attr == value comparisons
	EnableContextAccess  bool // context.attr in condition expressions
	EnableMultiPolicies  bool // more than 1 policy per policy set
}

// NewSwarmConfig generates a random swarm configuration by flipping a coin
// (50% probability) for each feature independently. This is the core of the
// swarm testing methodology: each fuzz iteration gets a unique subset of
// enabled features.
func NewSwarmConfig(r *Rand) *SwarmConfig {
	return &SwarmConfig{
		EnableExtensions:    r.Bool(),
		EnableSetTypes:      r.Bool(),
		EnableRecordTypes:   r.Bool(),
		EnableHierarchy:     r.Bool(),
		EnableContext:       r.Bool(),
		EnableForbid:        r.Bool(),
		EnableConditions:    r.Bool(),
		EnableLogicalOps:    r.Bool(),
		EnableNegation:      r.Bool(),
		EnableHasChecks:     r.Bool(),
		EnableInChecks:      r.Bool(),
		EnableIsChecks:      r.Bool(),
		EnableAttrCompare:   r.Bool(),
		EnableContextAccess: r.Bool(),
		EnableMultiPolicies: r.Bool(),
	}
}
