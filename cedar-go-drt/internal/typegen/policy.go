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
	"slices"
	"strings"

	"github.com/cedar-policy/cedar-go"
)

// PolicyGenerator generates policies that conform to a schema.
type PolicyGenerator struct {
	schema   *GeneratedSchema
	entities *GeneratedEntities
	settings Settings
	rand     *Rand
}

// NewPolicyGenerator creates a new policy generator.
func NewPolicyGenerator(schema *GeneratedSchema, entities *GeneratedEntities, r *Rand) *PolicyGenerator {
	return &PolicyGenerator{
		schema:   schema,
		entities: entities,
		settings: schema.Settings,
		rand:     r,
	}
}

// Generate creates a policy valid for the schema.
func (g *PolicyGenerator) Generate() (*cedar.Policy, error) {
	policyStr := g.generatePolicyString()

	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(policyStr)); err != nil {
		return nil, fmt.Errorf("failed to parse generated policy: %w", err)
	}

	return &policy, nil
}

func (g *PolicyGenerator) generatePolicyString() string {
	var sb strings.Builder

	// Effect
	swarm := g.settings.Swarm
	if !g.rand.Bool() && (swarm == nil || swarm.EnableForbid) {
		sb.WriteString("forbid(\n")
	} else {
		sb.WriteString("permit(\n")
	}

	// Principal scope
	sb.WriteString("  principal")
	g.writePrincipalScope(&sb)
	sb.WriteString(",\n")

	// Action scope
	sb.WriteString("  action")
	g.writeActionScope(&sb)
	sb.WriteString(",\n")

	// Resource scope
	sb.WriteString("  resource")
	g.writeResourceScope(&sb)
	sb.WriteString("\n)")

	// Conditions
	if swarm == nil || swarm.EnableConditions {
		numConditions := g.rand.IntRange(0, 2)
		for range numConditions {
			if g.rand.Bool() {
				sb.WriteString("\nwhen { ")
			} else {
				sb.WriteString("\nunless { ")
			}
			g.writeConditionExpr(&sb, 0)
			sb.WriteString(" }")
		}
	}

	sb.WriteString(";")

	return sb.String()
}

func (g *PolicyGenerator) writePrincipalScope(sb *strings.Builder) {
	swarm := g.settings.Swarm
	switch g.rand.Intn(4) {
	case 0:
		// Any principal
	case 1:
		// Specific principal
		if len(g.entities.PrincipalUIDs) > 0 {
			uid := Choose(g.rand, g.entities.PrincipalUIDs)
			fmt.Fprintf(sb, " == %s::\"%s\"", uid.Type, uid.ID)
		}
	case 2:
		// Principal in entity
		if len(g.entities.PrincipalUIDs) > 0 {
			uid := Choose(g.rand, g.entities.PrincipalUIDs)
			fmt.Fprintf(sb, " in %s::\"%s\"", uid.Type, uid.ID)
		}
	case 3:
		// Principal is type
		if (swarm == nil || swarm.EnableIsChecks) && len(g.schema.EntityTypeList) > 0 {
			typeName := Choose(g.rand, g.schema.EntityTypeList)
			fmt.Fprintf(sb, " is %s", typeName)
		}
	}
}

func (g *PolicyGenerator) writeActionScope(sb *strings.Builder) {
	switch g.rand.Intn(3) {
	case 0:
		// Any action
	case 1:
		// Specific action
		if len(g.schema.ActionList) > 0 {
			action := Choose(g.rand, g.schema.ActionList)
			fmt.Fprintf(sb, " == Action::\"%s\"", action)
		}
	case 2:
		// Action in set
		if len(g.schema.ActionList) > 0 {
			numActions := g.rand.IntRange(1, min(len(g.schema.ActionList), 3))
			actions := ChooseN(g.rand, g.schema.ActionList, numActions)
			sb.WriteString(" in [")
			for i, a := range actions {
				if i > 0 {
					sb.WriteString(", ")
				}
				fmt.Fprintf(sb, "Action::\"%s\"", a)
			}
			sb.WriteString("]")
		}
	}
}

func (g *PolicyGenerator) writeResourceScope(sb *strings.Builder) {
	swarm := g.settings.Swarm
	switch g.rand.Intn(4) {
	case 0:
		// Any resource
	case 1:
		// Specific resource
		if len(g.entities.ResourceUIDs) > 0 {
			uid := Choose(g.rand, g.entities.ResourceUIDs)
			fmt.Fprintf(sb, " == %s::\"%s\"", uid.Type, uid.ID)
		}
	case 2:
		// Resource in entity
		if len(g.entities.ResourceUIDs) > 0 {
			uid := Choose(g.rand, g.entities.ResourceUIDs)
			fmt.Fprintf(sb, " in %s::\"%s\"", uid.Type, uid.ID)
		}
	case 3:
		// Resource is type
		if (swarm == nil || swarm.EnableIsChecks) && len(g.schema.EntityTypeList) > 0 {
			typeName := Choose(g.rand, g.schema.EntityTypeList)
			fmt.Fprintf(sb, " is %s", typeName)
		}
	}
}

func (g *PolicyGenerator) writeConditionExpr(sb *strings.Builder, depth int) {
	if depth >= g.settings.MaxDepth {
		sb.WriteString("true")
		return
	}

	swarm := g.settings.Swarm
	switch g.rand.Intn(10) {
	case 0:
		sb.WriteString("true")
	case 1:
		sb.WriteString("false")
	case 2:
		// Comparison with principal/resource attribute
		if swarm == nil || swarm.EnableAttrCompare {
			g.writeAttributeComparison(sb, depth)
		} else {
			sb.WriteString("true")
		}
	case 3:
		// Context attribute access
		if swarm == nil || swarm.EnableContextAccess {
			g.writeContextAccess(sb, depth)
		} else {
			sb.WriteString("true")
		}
	case 4:
		// Logical AND
		if swarm == nil || swarm.EnableLogicalOps {
			g.writeConditionExpr(sb, depth+1)
			sb.WriteString(" && ")
			g.writeConditionExpr(sb, depth+1)
		} else {
			sb.WriteString("true")
		}
	case 5:
		// Logical OR
		if swarm == nil || swarm.EnableLogicalOps {
			g.writeConditionExpr(sb, depth+1)
			sb.WriteString(" || ")
			g.writeConditionExpr(sb, depth+1)
		} else {
			sb.WriteString("true")
		}
	case 6:
		// Negation
		if swarm == nil || swarm.EnableNegation {
			sb.WriteString("!(")
			g.writeConditionExpr(sb, depth+1)
			sb.WriteString(")")
		} else {
			sb.WriteString("true")
		}
	case 7:
		// Has attribute check
		if swarm == nil || swarm.EnableHasChecks {
			g.writeHasCheck(sb)
		} else {
			sb.WriteString("true")
		}
	case 8:
		// In check
		if swarm == nil || swarm.EnableInChecks {
			g.writeInCheck(sb)
		} else {
			sb.WriteString("true")
		}
	default:
		sb.WriteString("true")
	}
}

func (g *PolicyGenerator) writeAttributeComparison(sb *strings.Builder, depth int) {
	// Find common attributes across all principal types for all actions
	// This ensures type safety - only access attributes that ALL principal types have
	commonAttrs := g.findCommonPrincipalAttributes()
	if len(commonAttrs) == 0 {
		sb.WriteString("true")
		return
	}

	// Pick a random common attribute
	var attrNames []string
	for name := range commonAttrs {
		attrNames = append(attrNames, name)
	}
	slices.Sort(attrNames)
	attrName := Choose(g.rand, attrNames)
	attrType := commonAttrs[attrName]

	// Generate comparison based on type
	switch attrType {
	case "String":
		fmt.Fprintf(sb, "principal.%s == \"%s\"", attrName, g.rand.String(5))
	case "Long":
		fmt.Fprintf(sb, "principal.%s == %d", attrName, g.rand.IntRange(-100, 100))
	case "Boolean":
		fmt.Fprintf(sb, "principal.%s", attrName)
	default:
		sb.WriteString("true")
	}
}

// findCommonPrincipalAttributes finds attributes that exist on ALL principal types
// across all actions. Only required attributes with matching types can be safely accessed.
func (g *PolicyGenerator) findCommonPrincipalAttributes() map[string]string {
	if len(g.schema.ActionList) == 0 {
		return nil
	}

	// Collect all principal types across all actions
	allPrincipalTypes := make(map[string]bool)
	for _, actionName := range g.schema.ActionList {
		action := g.schema.Schema.Actions[actionName]
		if action.AppliesTo != nil {
			for _, pt := range action.AppliesTo.PrincipalTypes {
				allPrincipalTypes[pt] = true
			}
		}
	}

	if len(allPrincipalTypes) == 0 {
		return nil
	}

	// Find attributes common to ALL principal types (must be required and same type)
	var commonAttrs map[string]string
	first := true
	for typeName := range allPrincipalTypes {
		entityDef, exists := g.schema.Schema.EntityTypes[typeName]
		if !exists || entityDef.Shape == nil || len(entityDef.Shape.Attributes) == 0 {
			// This type has no attributes, so there can be no common attributes
			return nil
		}

		// Only include required attributes
		typeAttrs := make(map[string]string)
		for name, attr := range entityDef.Shape.Attributes {
			if attr.Required {
				typeAttrs[name] = attr.Type
			}
		}

		if first {
			commonAttrs = typeAttrs
			first = false
		} else {
			// Intersect with existing common attributes (name AND type must match)
			for name, existingType := range commonAttrs {
				if newType, exists := typeAttrs[name]; !exists || newType != existingType {
					delete(commonAttrs, name)
				}
			}
		}

		if len(commonAttrs) == 0 {
			return nil
		}
	}

	return commonAttrs
}

func (g *PolicyGenerator) writeContextAccess(sb *strings.Builder, depth int) {
	// Find context attributes common to ALL actions (name AND type must match)
	commonAttrs := g.findCommonContextAttributes()
	if len(commonAttrs) == 0 {
		sb.WriteString("true")
		return
	}

	// Collect and sort attribute names for determinism
	var attrNames []string
	for name := range commonAttrs {
		attrNames = append(attrNames, name)
	}
	slices.Sort(attrNames)
	attrName := Choose(g.rand, attrNames)
	attrType := commonAttrs[attrName]

	switch attrType {
	case "String":
		fmt.Fprintf(sb, "context.%s == \"%s\"", attrName, g.rand.String(5))
	case "Long":
		fmt.Fprintf(sb, "context.%s > %d", attrName, g.rand.IntRange(-100, 100))
	case "Boolean":
		fmt.Fprintf(sb, "context.%s", attrName)
	default:
		sb.WriteString("true")
	}
}

// findCommonContextAttributes finds context attributes that exist on ALL actions
// with the same name and type. Only required attributes can be safely accessed on `context`.
func (g *PolicyGenerator) findCommonContextAttributes() map[string]string {
	if len(g.schema.ActionList) == 0 {
		return nil
	}

	var commonAttrs map[string]string
	first := true
	for _, actionName := range g.schema.ActionList {
		action := g.schema.Schema.Actions[actionName]

		// Get this action's required context attributes (empty map if no context)
		typeAttrs := make(map[string]string)
		if action.AppliesTo != nil && action.AppliesTo.Context != nil {
			for name, attr := range action.AppliesTo.Context.Attributes {
				if attr.Required {
					typeAttrs[name] = attr.Type
				}
			}
		}

		if first {
			commonAttrs = typeAttrs
			first = false
		} else {
			// Intersect with existing common attributes (name AND type must match)
			for name, existingType := range commonAttrs {
				if newType, exists := typeAttrs[name]; !exists || newType != existingType {
					delete(commonAttrs, name)
				}
			}
		}

		if len(commonAttrs) == 0 {
			return nil
		}
	}

	return commonAttrs
}

func (g *PolicyGenerator) writeHasCheck(sb *strings.Builder) {
	// Use common attributes to ensure type safety
	// has checks are safe even for optional attributes, but the attribute name
	// must exist on all possible types for the variable
	usePrincipal := g.rand.Bool()

	var commonAttrs map[string]string
	if usePrincipal {
		commonAttrs = g.findCommonPrincipalAttributes()
	} else {
		commonAttrs = g.findCommonResourceAttributes()
	}

	if len(commonAttrs) == 0 {
		sb.WriteString("true")
		return
	}

	var attrNames []string
	for name := range commonAttrs {
		attrNames = append(attrNames, name)
	}
	slices.Sort(attrNames)
	attrName := Choose(g.rand, attrNames)

	if usePrincipal {
		fmt.Fprintf(sb, "principal has %s", attrName)
	} else {
		fmt.Fprintf(sb, "resource has %s", attrName)
	}
}

// findCommonResourceAttributes finds attributes that exist on ALL resource types
// across all actions. Only required attributes with matching types can be safely accessed.
func (g *PolicyGenerator) findCommonResourceAttributes() map[string]string {
	if len(g.schema.ActionList) == 0 {
		return nil
	}

	// Collect all resource types across all actions
	allResourceTypes := make(map[string]bool)
	for _, actionName := range g.schema.ActionList {
		action := g.schema.Schema.Actions[actionName]
		if action.AppliesTo != nil {
			for _, rt := range action.AppliesTo.ResourceTypes {
				allResourceTypes[rt] = true
			}
		}
	}

	if len(allResourceTypes) == 0 {
		return nil
	}

	// Find attributes common to ALL resource types (must be required and same type)
	var commonAttrs map[string]string
	first := true
	for typeName := range allResourceTypes {
		entityDef, exists := g.schema.Schema.EntityTypes[typeName]
		if !exists || entityDef.Shape == nil || len(entityDef.Shape.Attributes) == 0 {
			return nil
		}

		// Only include required attributes
		typeAttrs := make(map[string]string)
		for name, attr := range entityDef.Shape.Attributes {
			if attr.Required {
				typeAttrs[name] = attr.Type
			}
		}

		if first {
			commonAttrs = typeAttrs
			first = false
		} else {
			// Intersect with existing common attributes (name AND type must match)
			for name, existingType := range commonAttrs {
				if newType, exists := typeAttrs[name]; !exists || newType != existingType {
					delete(commonAttrs, name)
				}
			}
		}

		if len(commonAttrs) == 0 {
			return nil
		}
	}

	return commonAttrs
}

func (g *PolicyGenerator) writeInCheck(sb *strings.Builder) {
	if len(g.entities.AllUIDs) > 0 {
		uid := Choose(g.rand, g.entities.AllUIDs)
		if g.rand.Bool() {
			fmt.Fprintf(sb, "principal in %s::\"%s\"", uid.Type, uid.ID)
		} else {
			fmt.Fprintf(sb, "resource in %s::\"%s\"", uid.Type, uid.ID)
		}
	} else {
		sb.WriteString("true")
	}
}

// GeneratePolicySet generates a policy set with n policies.
func (g *PolicyGenerator) GeneratePolicySet(n int) (*cedar.PolicySet, error) {
	ps := cedar.NewPolicySet()

	for i := range n {
		policy, err := g.Generate()
		if err != nil {
			continue // Skip invalid policies
		}
		ps.Add(cedar.PolicyID(fmt.Sprintf("policy%d", i)), policy)
	}

	return ps, nil
}
