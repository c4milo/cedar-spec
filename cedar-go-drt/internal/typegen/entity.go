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
	"fmt"

	"github.com/cedar-policy/cedar-go/types"
)

// EntityGenerator generates entities that conform to a schema.
type EntityGenerator struct {
	schema   *GeneratedSchema
	settings Settings
	rand     *Rand
}

// NewEntityGenerator creates a new entity generator for a schema.
func NewEntityGenerator(schema *GeneratedSchema, r *Rand) *EntityGenerator {
	return &EntityGenerator{
		schema:   schema,
		settings: schema.Settings,
		rand:     r,
	}
}

// GeneratedEntities holds generated entities and their UIDs.
type GeneratedEntities struct {
	Entities    types.EntityMap
	UIDsByType  map[string][]types.EntityUID
	AllUIDs     []types.EntityUID
	PrincipalUIDs []types.EntityUID
	ResourceUIDs  []types.EntityUID
}

// Generate creates entities conforming to the schema.
func (g *EntityGenerator) Generate() *GeneratedEntities {
	result := &GeneratedEntities{
		Entities:   make(types.EntityMap),
		UIDsByType: make(map[string][]types.EntityUID),
	}

	g.generateEntitiesForAllTypes(result)
	g.categorizeUIDsByRole(result)

	return result
}

func (g *EntityGenerator) generateEntitiesForAllTypes(result *GeneratedEntities) {
	for _, typeName := range g.schema.EntityTypeList {
		g.generateEntitiesForType(result, typeName)
	}
}

func (g *EntityGenerator) generateEntitiesForType(result *GeneratedEntities, typeName string) {
	numEntities := g.rand.IntRange(1, g.settings.MaxEntitiesPerType)
	entityDef := g.schema.Schema.EntityTypes[typeName]

	for i := range numEntities {
		uid := types.EntityUID{
			Type: types.EntityType(typeName),
			ID:   types.String(fmt.Sprintf("%s%d", typeName, i)),
		}

		entity := types.Entity{
			UID:        uid,
			Attributes: g.generateAttributes(entityDef.Shape),
			Parents:    g.generateParents(typeName, entityDef.MemberOfTypes, result.UIDsByType),
		}

		result.Entities[uid] = entity
		result.UIDsByType[typeName] = append(result.UIDsByType[typeName], uid)
		result.AllUIDs = append(result.AllUIDs, uid)
	}
}

func (g *EntityGenerator) categorizeUIDsByRole(result *GeneratedEntities) {
	principalTypes, resourceTypes := g.collectRoleTypes()

	for typeName, uids := range result.UIDsByType {
		if principalTypes[typeName] {
			result.PrincipalUIDs = append(result.PrincipalUIDs, uids...)
		}
		if resourceTypes[typeName] {
			result.ResourceUIDs = append(result.ResourceUIDs, uids...)
		}
	}
}

func (g *EntityGenerator) collectRoleTypes() (principalTypes, resourceTypes map[string]bool) {
	principalTypes = make(map[string]bool)
	resourceTypes = make(map[string]bool)

	for _, actionName := range g.schema.ActionList {
		action := g.schema.Schema.Actions[actionName]
		if action.AppliesTo == nil {
			continue
		}
		for _, pt := range action.AppliesTo.PrincipalTypes {
			principalTypes[pt] = true
		}
		for _, rt := range action.AppliesTo.ResourceTypes {
			resourceTypes[rt] = true
		}
	}

	return principalTypes, resourceTypes
}

func (g *EntityGenerator) generateAttributes(shape *SchemaType) types.Record {
	if shape == nil || shape.Attributes == nil {
		return types.NewRecord(types.RecordMap{})
	}

	attrs := make(types.RecordMap)
	for attrName, attrDef := range shape.Attributes {
		// Skip optional attributes sometimes
		if !attrDef.Required && g.rand.Bool() {
			continue
		}
		attrs[types.String(attrName)] = g.generateValue(&attrDef)
	}

	return types.NewRecord(attrs)
}

func (g *EntityGenerator) generateParents(typeName string, memberOfTypes []string, uidsByType map[string][]types.EntityUID) types.EntityUIDSet {
	var parentList []types.EntityUID

	for _, parentType := range memberOfTypes {
		parentUIDs := uidsByType[parentType]
		if len(parentUIDs) > 0 && g.rand.Bool() {
			parent := Choose(g.rand, parentUIDs)
			parentList = append(parentList, parent)
		}
	}

	return types.NewEntityUIDSet(parentList...)
}

func (g *EntityGenerator) generateValue(attr *SchemaAttr) types.Value {
	return g.generateValueForType(attr.Type, attr.Element, attr.Attributes, 0)
}

func (g *EntityGenerator) generateValueForType(typeName string, element *SchemaType, attributes map[string]SchemaAttr, depth int) types.Value {
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
	case "Extension":
		return g.generateExtensionValue(element)
	default:
		// Might be an entity reference
		return types.String(g.rand.String(8))
	}
}

func (g *EntityGenerator) generateSetValue(element *SchemaType, depth int) types.Value {
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

func (g *EntityGenerator) generateRecordValue(attributes map[string]SchemaAttr, depth int) types.Value {
	attrs := make(types.RecordMap)
	for attrName, attrDef := range attributes {
		if !attrDef.Required && g.rand.Bool() {
			continue
		}
		attrs[types.String(attrName)] = g.generateValueForType(attrDef.Type, attrDef.Element, attrDef.Attributes, depth+1)
	}
	return types.NewRecord(attrs)
}

func (g *EntityGenerator) generateExtensionValue(element *SchemaType) types.Value {
	extName := ""
	if element != nil {
		extName = element.Name
	}

	switch extName {
	case "decimal":
		// Generate a valid decimal string
		whole := g.rand.IntRange(-999, 999)
		frac := g.rand.IntRange(0, 9999)
		decStr := fmt.Sprintf("%d.%04d", whole, frac)
		dec, err := types.ParseDecimal(decStr)
		if err != nil {
			return types.String(decStr)
		}
		return dec
	case "ipaddr":
		// Generate a valid IP address
		ip := fmt.Sprintf("%d.%d.%d.%d",
			g.rand.IntRange(0, 255),
			g.rand.IntRange(0, 255),
			g.rand.IntRange(0, 255),
			g.rand.IntRange(0, 255))
		addr, err := types.ParseIPAddr(ip)
		if err != nil {
			return types.String(ip)
		}
		return addr
	default:
		return types.String("unknown_extension")
	}
}
