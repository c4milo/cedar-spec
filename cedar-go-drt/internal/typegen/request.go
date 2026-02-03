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

// RequestGenerator generates requests that conform to a schema.
type RequestGenerator struct {
	schema   *GeneratedSchema
	entities *GeneratedEntities
	settings Settings
	rand     *Rand
}

// NewRequestGenerator creates a new request generator.
func NewRequestGenerator(schema *GeneratedSchema, entities *GeneratedEntities, r *Rand) *RequestGenerator {
	return &RequestGenerator{
		schema:   schema,
		entities: entities,
		settings: schema.Settings,
		rand:     r,
	}
}

// Generate creates a request valid for the schema.
func (g *RequestGenerator) Generate() cedar.Request {
	// Pick a random action
	actionName := Choose(g.rand, g.schema.ActionList)
	action := g.schema.Schema.Actions[actionName]

	// Pick valid principal and resource types for this action
	var principal types.EntityUID
	var resource types.EntityUID

	if action.AppliesTo != nil && len(action.AppliesTo.PrincipalTypes) > 0 {
		principalType := Choose(g.rand, action.AppliesTo.PrincipalTypes)
		if uids := g.entities.UIDsByType[principalType]; len(uids) > 0 {
			principal = Choose(g.rand, uids)
		} else {
			principal = types.EntityUID{Type: types.EntityType(principalType), ID: "unknown"}
		}
	} else if len(g.entities.PrincipalUIDs) > 0 {
		principal = Choose(g.rand, g.entities.PrincipalUIDs)
	}

	if action.AppliesTo != nil && len(action.AppliesTo.ResourceTypes) > 0 {
		resourceType := Choose(g.rand, action.AppliesTo.ResourceTypes)
		if uids := g.entities.UIDsByType[resourceType]; len(uids) > 0 {
			resource = Choose(g.rand, uids)
		} else {
			resource = types.EntityUID{Type: types.EntityType(resourceType), ID: "unknown"}
		}
	} else if len(g.entities.ResourceUIDs) > 0 {
		resource = Choose(g.rand, g.entities.ResourceUIDs)
	}

	// Generate context matching action's context type
	var context types.Record
	if action.AppliesTo != nil && action.AppliesTo.Context != nil {
		context = g.generateContext(action.AppliesTo.Context)
	} else {
		context = types.NewRecord(types.RecordMap{})
	}

	return cedar.Request{
		Principal: principal,
		Action:    types.EntityUID{Type: "Action", ID: types.String(actionName)},
		Resource:  resource,
		Context:   context,
	}
}

func (g *RequestGenerator) generateContext(contextType *SchemaType) types.Record {
	if contextType == nil || contextType.Attributes == nil {
		return types.NewRecord(types.RecordMap{})
	}

	attrs := make(types.RecordMap)
	for attrName, attrDef := range contextType.Attributes {
		if !attrDef.Required && g.rand.Bool() {
			continue
		}
		value := g.generateValueForType(attrDef.Type, attrDef.Element, attrDef.Attributes, 0)
		attrs[types.String(attrName)] = value
	}

	return types.NewRecord(attrs)
}

func (g *RequestGenerator) generateValueForType(typeName string, element *SchemaType, attributes map[string]SchemaAttr, depth int) types.Value {
	if depth > g.settings.MaxDepth {
		return types.String("max_depth")
	}

	switch typeName {
	case "String":
		return types.String(g.rand.String(10))
	case "Long":
		return types.Long(g.rand.IntRange(-1000, 1000))
	case "Boolean":
		return types.Boolean(g.rand.Bool())
	case "Set":
		return g.generateSetValue(element, depth)
	case "Record":
		return g.generateRecordValue(attributes, depth)
	default:
		return types.String(g.rand.String(8))
	}
}

func (g *RequestGenerator) generateSetValue(element *SchemaType, depth int) types.Value {
	numElements := g.rand.IntRange(0, g.settings.MaxWidth)
	elements := make([]types.Value, numElements)

	elemType := "String"
	var elemElement *SchemaType
	var elemAttrs map[string]SchemaAttr

	if element != nil {
		elemType = element.Type
		elemElement = element.Element
		elemAttrs = element.Attributes
	}

	for i := range numElements {
		elements[i] = g.generateValueForType(elemType, elemElement, elemAttrs, depth+1)
	}

	return types.NewSet(elements...)
}

func (g *RequestGenerator) generateRecordValue(attributes map[string]SchemaAttr, depth int) types.Value {
	attrs := make(types.RecordMap)
	for attrName, attrDef := range attributes {
		if !attrDef.Required && g.rand.Bool() {
			continue
		}
		attrs[types.String(attrName)] = g.generateValueForType(attrDef.Type, attrDef.Element, attrDef.Attributes, depth+1)
	}
	return types.NewRecord(attrs)
}

// GenerateN generates n requests valid for the schema.
func (g *RequestGenerator) GenerateN(n int) []cedar.Request {
	requests := make([]cedar.Request, n)
	for i := range n {
		requests[i] = g.Generate()
	}
	return requests
}
