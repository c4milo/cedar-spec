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

package proto

// This file contains schema and entity conversion functions for converting
// cedar-go schema types to protobuf for Lean FFI communication.

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/schema"

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/proto/pb/core"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/proto/pb/validator"
)

// computeTransitiveClosure computes all ancestors (direct and indirect) for an entity.
func computeTransitiveClosure(uid types.EntityUID, entities types.EntityMap) []types.EntityUID {
	visited := make(map[types.EntityUID]bool)
	var result []types.EntityUID

	var visit func(u types.EntityUID)
	visit = func(u types.EntityUID) {
		entity, ok := entities[u]
		if !ok {
			return
		}
		for parent := range entity.Parents.All() {
			if !visited[parent] {
				visited[parent] = true
				result = append(result, parent)
				visit(parent)
			}
		}
	}

	visit(uid)
	return result
}

// convertEntities converts a types.EntityMap to protobuf.
func convertEntities(entities types.EntityMap) (*core.Entities, error) {
	if entities == nil {
		return &core.Entities{Entities: []*core.Entity{}}, nil
	}

	var result []*core.Entity
	for uid, entity := range entities {
		protoEntity := &core.Entity{
			Uid:       convertEntityUID(uid),
			Attrs:     make(map[string]*core.Expr),
			Ancestors: make([]*core.EntityUid, 0),
		}

		// Convert attributes
		for attrKey, attrVal := range entity.Attributes.All() {
			protoEntity.Attrs[string(attrKey)] = convertValue(attrVal)
		}

		// Convert ancestors - compute transitive closure (all direct and indirect parents)
		allAncestors := computeTransitiveClosure(uid, entities)
		for _, ancestor := range allAncestors {
			protoEntity.Ancestors = append(protoEntity.Ancestors, convertEntityUID(ancestor))
		}

		result = append(result, protoEntity)
	}

	return &core.Entities{Entities: result}, nil
}

// jsonSchema mirrors the Cedar JSON schema format for conversion.
// We use these local types because the internal schema/ast types are not exported.
type jsonSchema map[string]*jsonNamespace

type jsonNamespace struct {
	EntityTypes map[string]*jsonEntity `json:"entityTypes"`
	Actions     map[string]*jsonAction `json:"actions"`
}

type jsonEntity struct {
	MemberOfTypes []string  `json:"memberOfTypes,omitempty"`
	Shape         *jsonType `json:"shape,omitempty"`
}

type jsonAction struct {
	AppliesTo *jsonAppliesTo `json:"appliesTo"`
}

type jsonAppliesTo struct {
	PrincipalTypes []string  `json:"principalTypes"`
	ResourceTypes  []string  `json:"resourceTypes"`
	Context        *jsonType `json:"context,omitempty"`
}

type jsonType struct {
	Type       string                    `json:"type"`
	Element    *jsonType                 `json:"element,omitempty"`
	Name       string                    `json:"name,omitempty"`
	Attributes map[string]*jsonAttribute `json:"attributes,omitempty"`
}

type jsonAttribute struct {
	Type       string                    `json:"type"`
	Required   *bool                     `json:"required,omitempty"`
	Element    *jsonType                 `json:"element,omitempty"`
	Name       string                    `json:"name,omitempty"`
	Attributes map[string]*jsonAttribute `json:"attributes,omitempty"`
}

// convertSchema converts a schema.Schema to protobuf.
func convertSchema(s *schema.Schema) (*validator.Schema, error) {
	if s == nil {
		return nil, nil
	}

	js, err := parseSchemaToJSON(s)
	if err != nil {
		return nil, err
	}
	if js == nil {
		return &validator.Schema{}, nil
	}

	return buildSchemaFromJSON(js), nil
}

func parseSchemaToJSON(s *schema.Schema) (jsonSchema, error) {
	jsonBytes, err := s.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal schema to JSON: %w", err)
	}
	if len(jsonBytes) == 0 {
		return nil, nil
	}

	var js jsonSchema
	if err := json.Unmarshal(jsonBytes, &js); err != nil {
		return nil, fmt.Errorf("failed to unmarshal schema JSON: %w", err)
	}
	return js, nil
}

func buildSchemaFromJSON(js jsonSchema) *validator.Schema {
	result := &validator.Schema{
		EntityDecls: []*validator.EntityDecl{},
		ActionDecls: []*validator.ActionDecl{},
	}

	// First pass: create entity declarations with attributes (but not descendants yet)
	entityDeclMap := make(map[string]*validator.EntityDecl)
	for nsName, ns := range js {
		if ns == nil {
			continue
		}
		for entityName, entity := range ns.EntityTypes {
			entityDecl := convertEntityDeclWithoutDescendants(nsName, entityName, entity)
			fullName := resolveFullName(nsName, entityName)
			entityDeclMap[fullName] = entityDecl
			result.EntityDecls = append(result.EntityDecls, entityDecl)
		}
	}

	// Second pass: populate descendants (inverted from memberOfTypes)
	// If Type1 has memberOfTypes: ["Type0"], then Type0's descendants include Type1
	for nsName, ns := range js {
		if ns == nil {
			continue
		}
		for entityName, entity := range ns.EntityTypes {
			if entity == nil {
				continue
			}
			childFullName := resolveFullName(nsName, entityName)
			for _, parentType := range entity.MemberOfTypes {
				parentFullName := resolveTypeNameInNamespace(nsName, parentType)
				if parentDecl, ok := entityDeclMap[parentFullName]; ok {
					parentDecl.Descendants = append(parentDecl.Descendants,
						convertEntityType(types.EntityType(childFullName)))
				}
			}
		}
	}

	// Add action declarations
	for nsName, ns := range js {
		if ns == nil {
			continue
		}
		appendActionDecls(result, nsName, ns)
	}

	return result
}

// convertEntityDeclWithoutDescendants creates an EntityDecl with attributes but no descendants.
// Descendants are populated in a second pass after all entity types are created.
func convertEntityDeclWithoutDescendants(nsName, entityName string, entity *jsonEntity) *validator.EntityDecl {
	fullName := resolveFullName(nsName, entityName)

	entityDecl := &validator.EntityDecl{
		Name:       convertEntityType(types.EntityType(fullName)),
		Attributes: make(map[string]*validator.AttributeType),
	}

	appendEntityAttributes(entityDecl, nsName, entity.Shape)

	return entityDecl
}

func resolveFullName(nsName, name string) string {
	if nsName != "" {
		return nsName + "::" + name
	}
	return name
}

func resolveTypeNameInNamespace(nsName, typeName string) string {
	if nsName != "" && !strings.Contains(typeName, "::") {
		return nsName + "::" + typeName
	}
	return typeName
}

func appendEntityAttributes(entityDecl *validator.EntityDecl, nsName string, shape *jsonType) {
	if shape == nil || shape.Attributes == nil {
		return
	}
	for attrName, attr := range shape.Attributes {
		entityDecl.Attributes[attrName] = convertAttributeType(attr, nsName)
	}
}

func appendActionDecls(result *validator.Schema, nsName string, ns *jsonNamespace) {
	for actionName, action := range ns.Actions {
		actionDecl := convertActionDecl(nsName, actionName, action)
		result.ActionDecls = append(result.ActionDecls, actionDecl)
	}
}

func convertActionDecl(nsName, actionName string, action *jsonAction) *validator.ActionDecl {
	actionDecl := &validator.ActionDecl{
		Name: &core.EntityUid{
			Ty:  &core.Name{Id: "Action"},
			Eid: actionName,
		},
		Context: make(map[string]*validator.AttributeType),
	}

	if action.AppliesTo != nil {
		populateActionAppliesTo(actionDecl, nsName, action.AppliesTo)
	}

	return actionDecl
}

func populateActionAppliesTo(actionDecl *validator.ActionDecl, nsName string, appliesTo *jsonAppliesTo) {
	for _, pt := range appliesTo.PrincipalTypes {
		ptName := resolveTypeNameInNamespace(nsName, pt)
		actionDecl.PrincipalTypes = append(actionDecl.PrincipalTypes,
			convertEntityType(types.EntityType(ptName)))
	}

	for _, rt := range appliesTo.ResourceTypes {
		rtName := resolveTypeNameInNamespace(nsName, rt)
		actionDecl.ResourceTypes = append(actionDecl.ResourceTypes,
			convertEntityType(types.EntityType(rtName)))
	}

	if appliesTo.Context != nil && appliesTo.Context.Attributes != nil {
		for ctxName, ctxAttr := range appliesTo.Context.Attributes {
			actionDecl.Context[ctxName] = convertAttributeType(ctxAttr, nsName)
		}
	}
}

// convertAttributeType converts a JSON attribute to protobuf AttributeType.
func convertAttributeType(attr *jsonAttribute, nsName string) *validator.AttributeType {
	// Cedar JSON schema spec: absent "required" field means required (true).
	isRequired := attr.Required == nil || *attr.Required
	return &validator.AttributeType{
		AttrType:   convertJSONTypeToProto(attr, nsName),
		IsRequired: isRequired,
	}
}

// convertJSONTypeToProto converts a JSON type to protobuf Type.
func convertJSONTypeToProto(attr *jsonAttribute, nsName string) *validator.Type {
	switch attr.Type {
	case "Boolean":
		return &validator.Type{
			Data: &validator.Type_Prim_{Prim: validator.Type_Bool},
		}
	case "Long":
		return &validator.Type{
			Data: &validator.Type_Prim_{Prim: validator.Type_Long},
		}
	case "String":
		return &validator.Type{
			Data: &validator.Type_Prim_{Prim: validator.Type_String},
		}
	case "Set":
		if attr.Element != nil {
			elemAttr := &jsonAttribute{
				Type:       attr.Element.Type,
				Element:    attr.Element.Element,
				Name:       attr.Element.Name,
				Attributes: attr.Element.Attributes,
			}
			return &validator.Type{
				Data: &validator.Type_SetElem{
					SetElem: convertJSONTypeToProto(elemAttr, nsName),
				},
			}
		}
		return &validator.Type{
			Data: &validator.Type_Prim_{Prim: validator.Type_String},
		}
	case "Record":
		recordType := &validator.Type_Record{
			Attrs: make(map[string]*validator.AttributeType),
		}
		for name, recAttr := range attr.Attributes {
			recordType.Attrs[name] = convertAttributeType(recAttr, nsName)
		}
		return &validator.Type{
			Data: &validator.Type_Record_{Record: recordType},
		}
	case "Entity", "EntityOrCommon":
		entityName := attr.Name
		if nsName != "" && entityName != "" && !strings.Contains(entityName, "::") {
			entityName = nsName + "::" + entityName
		}
		return &validator.Type{
			Data: &validator.Type_Entity{
				Entity: convertEntityType(types.EntityType(entityName)),
			},
		}
	case "Extension":
		return &validator.Type{
			Data: &validator.Type_Ext{
				Ext: &core.Name{Id: attr.Name},
			},
		}
	default:
		// Default to String for unknown types
		return &validator.Type{
			Data: &validator.Type_Prim_{Prim: validator.Type_String},
		}
	}
}
