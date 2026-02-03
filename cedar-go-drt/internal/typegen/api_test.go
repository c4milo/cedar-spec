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

import "testing"

// TestAPIExports verifies that exported API functions exist and are callable.
// These functions are intentionally kept for library users even if not used internally.
func TestAPIExports(t *testing.T) {
	// Test Rand methods
	r := NewRand([]byte("test seed data for randomization"))
	_ = r.Float64()
	_ = r.Identifier()

	// Test Shuffle
	items := []int{1, 2, 3}
	Shuffle(r, items)

	// Test MinimalSettings
	_ = MinimalSettings()

	// Test GeneratedSchema.ToNamespacedJSON (requires a schema)
	schemaGen := NewSchemaGenerator(DefaultSettings(), r)
	schema := schemaGen.Generate()
	_, _ = schema.ToNamespacedJSON()

	// Test InputGenerator.GenerateForEvaluation (requires generator)
	gen := NewInputGenerator(DefaultSettings())
	_, _, _ = gen.GenerateForEvaluation([]byte("test data"))
}
