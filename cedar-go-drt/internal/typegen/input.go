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

import (
	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
)

// TypeDirectedInput represents a complete type-directed test input.
type TypeDirectedInput struct {
	Schema    *GeneratedSchema
	Entities  *GeneratedEntities
	Policies  *cedar.PolicySet
	Requests  []cedar.Request
	SchemaJSON []byte
}

// InputGenerator generates complete type-directed test inputs.
type InputGenerator struct {
	settings Settings
}

// NewInputGenerator creates a new input generator with the given settings.
func NewInputGenerator(settings Settings) *InputGenerator {
	return &InputGenerator{settings: settings}
}

// Generate creates a complete type-directed input from fuzzer bytes.
func (g *InputGenerator) Generate(data []byte) (*TypeDirectedInput, error) {
	r := NewRand(data)

	// Generate schema
	schemaGen := NewSchemaGenerator(g.settings, r)
	schema := schemaGen.Generate()

	schemaJSON, err := schema.ToJSON()
	if err != nil {
		return nil, err
	}

	// Generate entities conforming to schema
	entityGen := NewEntityGenerator(schema, r)
	entities := entityGen.Generate()

	// Generate policies conforming to schema
	policyGen := NewPolicyGenerator(schema, entities, r)
	numPolicies := r.IntRange(1, 3)
	policies, err := policyGen.GeneratePolicySet(numPolicies)
	if err != nil {
		return nil, err
	}

	// Generate requests conforming to schema
	requestGen := NewRequestGenerator(schema, entities, r)
	numRequests := r.IntRange(1, 4)
	requests := requestGen.GenerateN(numRequests)

	return &TypeDirectedInput{
		Schema:     schema,
		Entities:   entities,
		Policies:   policies,
		Requests:   requests,
		SchemaJSON: schemaJSON,
	}, nil
}

// GenerateForAuthorization generates input specifically for authorization testing.
func (g *InputGenerator) GenerateForAuthorization(data []byte) (*TypeDirectedInput, error) {
	return g.Generate(data)
}

// GenerateForValidation generates input specifically for validation testing.
func (g *InputGenerator) GenerateForValidation(data []byte) (*TypeDirectedInput, error) {
	return g.Generate(data)
}

// GenerateForEvaluation generates input with a specific expression for evaluation testing.
func (g *InputGenerator) GenerateForEvaluation(data []byte) (*TypeDirectedInput, types.Value, error) {
	input, err := g.Generate(data)
	if err != nil {
		return nil, nil, err
	}

	// Generate a random value to use as expected result type
	r := NewRand(data[len(data)/2:]) // Use different part of data
	entityGen := NewEntityGenerator(input.Schema, r)

	// Generate a value based on a random type
	schemaType := &SchemaType{Type: "Long"}
	switch r.Intn(5) {
	case 0:
		schemaType = &SchemaType{Type: "Boolean"}
	case 1:
		schemaType = &SchemaType{Type: "Long"}
	case 2:
		schemaType = &SchemaType{Type: "String"}
	case 3:
		schemaType = &SchemaType{Type: "Set", Element: &SchemaType{Type: "Long"}}
	}

	value := entityGen.generateValueForType(schemaType.Type, schemaType.Element, nil, 0)

	return input, value, nil
}

// DefaultInputGenerator returns an input generator with default settings.
func DefaultInputGenerator() *InputGenerator {
	return NewInputGenerator(DefaultSettings())
}

// TypeDirectedInputGenerator returns an input generator optimized for type-directed fuzzing.
func TypeDirectedInputGenerator() *InputGenerator {
	return NewInputGenerator(TypeDirectedSettings())
}
