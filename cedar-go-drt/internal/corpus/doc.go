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

// Package corpus provides utilities for loading and generating Cedar test data
// as corpus seeds for differential randomized testing (DRT).
//
// # Data Sources
//
// The package supports loading test data from multiple sources:
//
//   - Cedar policy sandbox directories (tiny_sandboxes format with policies,
//     entities, and requests)
//   - Raw .cedar policy files from the cedar repository
//   - Cedar integration test suites (cedar-integration-tests)
//   - Synthesized test outputs from the Rust DRT framework
//
// # Generated Test Cases
//
// In addition to loading existing test data, the package can generate new
// test cases using two strategies:
//
//   - Type-directed generation via the [typegen] package, which produces
//     well-typed schemas, entities, policies, and requests
//   - Handcrafted edge cases covering boundary conditions such as empty
//     policies, deeply nested expressions, IP/decimal extensions, and
//     context-dependent evaluation
//
// # Usage
//
// Use [LoadSandboxes] and [LoadCedarFiles] to load existing test data.
// Use [GenerateTypeDirected] and [GenerateEdgeCases] to produce synthetic
// test inputs for fuzzing corpus initialization.
//
// For validation-specific corpus data, use [LoadValidationTests] and
// [LoadValidationCedarFiles].
package corpus
