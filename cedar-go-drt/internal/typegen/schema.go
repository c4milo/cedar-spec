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
	"encoding/json"
	"fmt"
)

// SchemaType represents a Cedar type in the schema.
type SchemaType struct {
	Type       string                `json:"type"`
	Element    *SchemaType           `json:"element,omitempty"`
	Name       string                `json:"name,omitempty"`
	Attributes map[string]SchemaAttr `json:"attributes,omitempty"`
}

// SchemaAttr represents an attribute in a schema.
type SchemaAttr struct {
	Type       string                `json:"type"`
	Required   bool                  `json:"required"`
	Element    *SchemaType           `json:"element,omitempty"`
	Name       string                `json:"name,omitempty"`
	Attributes map[string]SchemaAttr `json:"attributes,omitempty"`
}

// SchemaEntity represents an entity type in the schema.
type SchemaEntity struct {
	MemberOfTypes []string    `json:"memberOfTypes,omitempty"`
	Shape         *SchemaType `json:"shape,omitempty"`
}

// SchemaAction represents an action in the schema.
type SchemaAction struct {
	AppliesTo *SchemaAppliesTo `json:"appliesTo,omitempty"`
}

// SchemaAppliesTo defines what an action applies to.
type SchemaAppliesTo struct {
	PrincipalTypes []string    `json:"principalTypes,omitempty"`
	ResourceTypes  []string    `json:"resourceTypes,omitempty"`
	Context        *SchemaType `json:"context,omitempty"`
}

// Schema represents a generated Cedar schema.
type Schema struct {
	EntityTypes map[string]SchemaEntity `json:"entityTypes"`
	Actions     map[string]SchemaAction `json:"actions"`
}

// GeneratedSchema holds a schema and metadata for generation.
type GeneratedSchema struct {
	Schema         Schema
	EntityTypeList []string
	ActionList     []string
	Settings       Settings
}

// SchemaGenerator generates random Cedar schemas.
type SchemaGenerator struct {
	settings Settings
	rand     *Rand
}

// NewSchemaGenerator creates a new schema generator.
func NewSchemaGenerator(settings Settings, r *Rand) *SchemaGenerator {
	return &SchemaGenerator{
		settings: settings,
		rand:     r,
	}
}

// Generate creates a random schema.
func (g *SchemaGenerator) Generate() *GeneratedSchema {
	numEntityTypes := g.rand.IntRange(1, g.settings.MaxEntityTypes)
	numActions := g.rand.IntRange(1, g.settings.MaxActions)

	// Generate entity type names
	entityTypes := make([]string, numEntityTypes)
	for i := range numEntityTypes {
		entityTypes[i] = fmt.Sprintf("Type%d", i)
	}

	// Generate action names
	actions := make([]string, numActions)
	for i := range numActions {
		actions[i] = fmt.Sprintf("action%d", i)
	}

	schema := Schema{
		EntityTypes: make(map[string]SchemaEntity),
		Actions:     make(map[string]SchemaAction),
	}

	swarm := g.settings.Swarm

	// Generate entity types with shapes and memberOf relationships
	for i, name := range entityTypes {
		entity := SchemaEntity{}

		// Add memberOf relationships (to types that come before this one)
		if i > 0 && g.rand.Bool() && (swarm == nil || swarm.EnableHierarchy) {
			numParents := g.rand.IntRange(1, min(i, 2))
			entity.MemberOfTypes = make([]string, numParents)
			for j := range numParents {
				entity.MemberOfTypes[j] = entityTypes[g.rand.Intn(i)]
			}
		}

		// Add shape (attributes)
		if g.rand.Bool() || i == 0 {
			entity.Shape = g.generateRecordType(0)
		}

		schema.EntityTypes[name] = entity
	}

	// Generate actions
	for _, name := range actions {
		action := SchemaAction{
			AppliesTo: &SchemaAppliesTo{},
		}

		// Choose principal types
		numPrincipals := g.rand.IntRange(1, min(len(entityTypes), 3))
		action.AppliesTo.PrincipalTypes = ChooseN(g.rand, entityTypes, numPrincipals)

		// Choose resource types
		numResources := g.rand.IntRange(1, min(len(entityTypes), 3))
		action.AppliesTo.ResourceTypes = ChooseN(g.rand, entityTypes, numResources)

		// Optionally add context
		if g.rand.Bool() && (swarm == nil || swarm.EnableContext) {
			action.AppliesTo.Context = g.generateRecordType(0)
		}

		schema.Actions[name] = action
	}

	return &GeneratedSchema{
		Schema:         schema,
		EntityTypeList: entityTypes,
		ActionList:     actions,
		Settings:       g.settings,
	}
}

// generateType generates a random Cedar type.
func (g *SchemaGenerator) generateType(depth int) *SchemaType {
	if depth >= g.settings.MaxDepth {
		return g.generatePrimitiveType()
	}

	// Choose type kind
	swarm := g.settings.Swarm
	switch g.rand.Intn(10) {
	case 0, 1, 2:
		return &SchemaType{Type: "String"}
	case 3, 4:
		return &SchemaType{Type: "Long"}
	case 5:
		return &SchemaType{Type: "Boolean"}
	case 6:
		if swarm == nil || swarm.EnableSetTypes {
			return g.generateSetType(depth)
		}
		return g.generatePrimitiveType()
	case 7:
		if swarm == nil || swarm.EnableRecordTypes {
			return g.generateRecordType(depth)
		}
		return g.generatePrimitiveType()
	case 8:
		if g.settings.EnableExtensions {
			return g.generateExtensionType()
		}
		return &SchemaType{Type: "String"}
	default:
		return &SchemaType{Type: "String"}
	}
}

func (g *SchemaGenerator) generatePrimitiveType() *SchemaType {
	switch g.rand.Intn(3) {
	case 0:
		return &SchemaType{Type: "String"}
	case 1:
		return &SchemaType{Type: "Long"}
	default:
		return &SchemaType{Type: "Boolean"}
	}
}

func (g *SchemaGenerator) generateSetType(depth int) *SchemaType {
	return &SchemaType{
		Type:    "Set",
		Element: g.generateType(depth + 1),
	}
}

func (g *SchemaGenerator) generateRecordType(depth int) *SchemaType {
	numAttrs := g.rand.IntRange(0, g.settings.MaxAttributes)
	attrs := make(map[string]SchemaAttr)

	for i := range numAttrs {
		attrName := fmt.Sprintf("attr%d", i)
		attrType := g.generateType(depth + 1)
		attrs[attrName] = SchemaAttr{
			Type:       attrType.Type,
			Required:   g.rand.Bool(),
			Element:    attrType.Element,
			Name:       attrType.Name,
			Attributes: attrType.Attributes,
		}
	}

	return &SchemaType{
		Type:       "Record",
		Attributes: attrs,
	}
}

func (g *SchemaGenerator) generateExtensionType() *SchemaType {
	extensions := []string{"decimal", "ipaddr"}
	return &SchemaType{
		Type: "Extension",
		Name: Choose(g.rand, extensions),
	}
}

// ToJSON converts the schema to JSON bytes.
func (s *GeneratedSchema) ToJSON() ([]byte, error) {
	return json.Marshal(s.Schema)
}

// ToNamespacedJSON converts the schema to namespaced JSON format.
func (s *GeneratedSchema) ToNamespacedJSON() ([]byte, error) {
	namespaced := map[string]Schema{"": s.Schema}
	return json.Marshal(namespaced)
}
