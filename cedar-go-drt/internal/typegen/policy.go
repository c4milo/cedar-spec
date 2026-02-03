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
	if g.rand.Bool() {
		sb.WriteString("permit(\n")
	} else {
		sb.WriteString("forbid(\n")
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

	sb.WriteString(";")

	return sb.String()
}

func (g *PolicyGenerator) writePrincipalScope(sb *strings.Builder) {
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
		if len(g.schema.EntityTypeList) > 0 {
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
		if len(g.schema.EntityTypeList) > 0 {
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

	switch g.rand.Intn(10) {
	case 0:
		sb.WriteString("true")
	case 1:
		sb.WriteString("false")
	case 2:
		// Comparison with principal/resource attribute
		g.writeAttributeComparison(sb, depth)
	case 3:
		// Context attribute access
		g.writeContextAccess(sb, depth)
	case 4:
		// Logical AND
		g.writeConditionExpr(sb, depth+1)
		sb.WriteString(" && ")
		g.writeConditionExpr(sb, depth+1)
	case 5:
		// Logical OR
		g.writeConditionExpr(sb, depth+1)
		sb.WriteString(" || ")
		g.writeConditionExpr(sb, depth+1)
	case 6:
		// Negation
		sb.WriteString("!(")
		g.writeConditionExpr(sb, depth+1)
		sb.WriteString(")")
	case 7:
		// Has attribute check
		g.writeHasCheck(sb)
	case 8:
		// In check
		g.writeInCheck(sb)
	default:
		sb.WriteString("true")
	}
}

func (g *PolicyGenerator) writeAttributeComparison(sb *strings.Builder, depth int) {
	// Find an entity type with attributes
	for _, typeName := range g.schema.EntityTypeList {
		entityDef := g.schema.Schema.EntityTypes[typeName]
		if entityDef.Shape != nil && len(entityDef.Shape.Attributes) > 0 {
			// Pick a random attribute
			var attrNames []string
			for name := range entityDef.Shape.Attributes {
				attrNames = append(attrNames, name)
			}
			if len(attrNames) > 0 {
				attrName := Choose(g.rand, attrNames)
				attr := entityDef.Shape.Attributes[attrName]

				// Generate comparison based on type
				switch attr.Type {
				case "String":
					fmt.Fprintf(sb, "principal.%s == \"%s\"", attrName, g.rand.String(5))
				case "Long":
					fmt.Fprintf(sb, "principal.%s == %d", attrName, g.rand.IntRange(-100, 100))
				case "Boolean":
					fmt.Fprintf(sb, "principal.%s", attrName)
				default:
					sb.WriteString("true")
				}
				return
			}
		}
	}
	sb.WriteString("true")
}

func (g *PolicyGenerator) writeContextAccess(sb *strings.Builder, depth int) {
	// Pick an action and check its context
	for _, actionName := range g.schema.ActionList {
		action := g.schema.Schema.Actions[actionName]
		if action.AppliesTo != nil && action.AppliesTo.Context != nil && len(action.AppliesTo.Context.Attributes) > 0 {
			var attrNames []string
			for name := range action.AppliesTo.Context.Attributes {
				attrNames = append(attrNames, name)
			}
			if len(attrNames) > 0 {
				attrName := Choose(g.rand, attrNames)
				attr := action.AppliesTo.Context.Attributes[attrName]

				switch attr.Type {
				case "String":
					fmt.Fprintf(sb, "context.%s == \"%s\"", attrName, g.rand.String(5))
				case "Long":
					fmt.Fprintf(sb, "context.%s > %d", attrName, g.rand.IntRange(-100, 100))
				case "Boolean":
					fmt.Fprintf(sb, "context.%s", attrName)
				default:
					sb.WriteString("true")
				}
				return
			}
		}
	}
	sb.WriteString("true")
}

func (g *PolicyGenerator) writeHasCheck(sb *strings.Builder) {
	// Check if principal/resource has an attribute
	for _, typeName := range g.schema.EntityTypeList {
		entityDef := g.schema.Schema.EntityTypes[typeName]
		if entityDef.Shape != nil && len(entityDef.Shape.Attributes) > 0 {
			var attrNames []string
			for name := range entityDef.Shape.Attributes {
				attrNames = append(attrNames, name)
			}
			if len(attrNames) > 0 {
				attrName := Choose(g.rand, attrNames)
				if g.rand.Bool() {
					fmt.Fprintf(sb, "principal has %s", attrName)
				} else {
					fmt.Fprintf(sb, "resource has %s", attrName)
				}
				return
			}
		}
	}
	sb.WriteString("true")
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
