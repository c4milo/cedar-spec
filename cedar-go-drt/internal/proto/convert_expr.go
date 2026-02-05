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

// This file contains expression/AST conversion functions for converting
// cedar-go AST nodes to protobuf expressions.

import (
	"strings"

	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/ast"

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/proto/pb/core"
)

// convertConditions converts policy conditions to a single protobuf expression.
// Multiple conditions are combined with AND.
func convertConditions(conditions []ast.ConditionType) *core.Expr {
	if len(conditions) == 0 {
		return trueLiteral()
	}

	var result *core.Expr
	for _, cond := range conditions {
		// Body is already an IsNode
		bodyExpr := convertExprNode(cond.Body)

		if cond.Condition == ast.ConditionUnless {
			// unless { X } becomes !X
			bodyExpr = &core.Expr{
				ExprKind: &core.Expr_UApp{
					UApp: &core.Expr_UnaryApp{
						Op:   core.Expr_UnaryApp_Not,
						Expr: bodyExpr,
					},
				},
			}
		}

		if result == nil {
			result = bodyExpr
		} else {
			result = &core.Expr{
				ExprKind: &core.Expr_And_{
					And: &core.Expr_And{
						Left:  result,
						Right: bodyExpr,
					},
				},
			}
		}
	}

	return result
}

// convertExprNode converts an AST node to a protobuf expression.
func convertExprNode(node ast.IsNode) *core.Expr {
	if node == nil {
		return trueLiteral()
	}

	switch n := node.(type) {
	case ast.NodeValue:
		return convertValue(n.Value)
	case ast.NodeTypeVariable:
		return convertVariable(n)
	case ast.NodeTypeAccess:
		return convertAccess(n)
	case ast.NodeTypeHas:
		return convertHas(n)
	case ast.NodeTypeEquals, ast.NodeTypeNotEquals,
		ast.NodeTypeLessThan, ast.NodeTypeLessThanOrEqual,
		ast.NodeTypeGreaterThan, ast.NodeTypeGreaterThanOrEqual:
		return convertComparison(node)
	case ast.NodeTypeIn, ast.NodeTypeContains, ast.NodeTypeContainsAll, ast.NodeTypeContainsAny:
		return convertMembership(node)
	case ast.NodeTypeAdd, ast.NodeTypeSub, ast.NodeTypeMult:
		return convertArithmetic(node)
	case ast.NodeTypeAnd, ast.NodeTypeOr:
		return convertLogicalBinary(node)
	case ast.NodeTypeNot, ast.NodeTypeNegate, ast.NodeTypeIsEmpty:
		return convertUnary(node)
	case ast.NodeTypeIfThenElse:
		return convertIfThenElse(n)
	case ast.NodeTypeIs:
		return convertIs(n)
	case ast.NodeTypeIsIn:
		return convertIsIn(n)
	case ast.NodeTypeLike:
		return convertLike(n)
	case ast.NodeTypeSet:
		return convertSet(n)
	case ast.NodeTypeRecord:
		return convertRecord(n)
	case ast.NodeTypeExtensionCall:
		return convertExtensionCall(n)
	default:
		return trueLiteral()
	}
}

// convertVariable converts a variable node to protobuf.
func convertVariable(n ast.NodeTypeVariable) *core.Expr {
	switch string(n.Name) {
	case "principal":
		return &core.Expr{ExprKind: &core.Expr_Var_{Var: core.Expr_Principal}}
	case "action":
		return &core.Expr{ExprKind: &core.Expr_Var_{Var: core.Expr_Action}}
	case "resource":
		return &core.Expr{ExprKind: &core.Expr_Var_{Var: core.Expr_Resource}}
	case "context":
		return &core.Expr{ExprKind: &core.Expr_Var_{Var: core.Expr_Context}}
	default:
		return trueLiteral()
	}
}

// convertAccess converts an attribute access node to protobuf.
func convertAccess(n ast.NodeTypeAccess) *core.Expr {
	return &core.Expr{
		ExprKind: &core.Expr_GetAttr_{
			GetAttr: &core.Expr_GetAttr{
				Expr: convertExprNode(n.Arg),
				Attr: string(n.Value),
			},
		},
	}
}

// convertHas converts a has-attribute node to protobuf.
func convertHas(n ast.NodeTypeHas) *core.Expr {
	return &core.Expr{
		ExprKind: &core.Expr_HasAttr_{
			HasAttr: &core.Expr_HasAttr{
				Expr: convertExprNode(n.Arg),
				Attr: string(n.Value),
			},
		},
	}
}

// convertComparison converts comparison operators to protobuf.
func convertComparison(node ast.IsNode) *core.Expr {
	switch n := node.(type) {
	case ast.NodeTypeEquals:
		return convertBinaryExpr(n.Left, n.Right, core.Expr_BinaryApp_Eq)
	case ast.NodeTypeNotEquals:
		return convertUnaryExpr(core.Expr_UnaryApp_Not,
			convertBinaryExpr(n.Left, n.Right, core.Expr_BinaryApp_Eq))
	case ast.NodeTypeLessThan:
		return convertBinaryExpr(n.Left, n.Right, core.Expr_BinaryApp_Less)
	case ast.NodeTypeLessThanOrEqual:
		return convertBinaryExpr(n.Left, n.Right, core.Expr_BinaryApp_LessEq)
	case ast.NodeTypeGreaterThan:
		return convertBinaryExpr(n.Right, n.Left, core.Expr_BinaryApp_Less)
	case ast.NodeTypeGreaterThanOrEqual:
		return convertBinaryExpr(n.Right, n.Left, core.Expr_BinaryApp_LessEq)
	default:
		return trueLiteral()
	}
}

// convertMembership converts membership operators (in, contains) to protobuf.
func convertMembership(node ast.IsNode) *core.Expr {
	switch n := node.(type) {
	case ast.NodeTypeIn:
		return convertBinaryExpr(n.Left, n.Right, core.Expr_BinaryApp_In)
	case ast.NodeTypeContains:
		return convertBinaryExpr(n.Left, n.Right, core.Expr_BinaryApp_Contains)
	case ast.NodeTypeContainsAll:
		return convertBinaryExpr(n.Left, n.Right, core.Expr_BinaryApp_ContainsAll)
	case ast.NodeTypeContainsAny:
		return convertBinaryExpr(n.Left, n.Right, core.Expr_BinaryApp_ContainsAny)
	default:
		return trueLiteral()
	}
}

// convertArithmetic converts arithmetic operators to protobuf.
func convertArithmetic(node ast.IsNode) *core.Expr {
	switch n := node.(type) {
	case ast.NodeTypeAdd:
		return convertBinaryExpr(n.Left, n.Right, core.Expr_BinaryApp_Add)
	case ast.NodeTypeSub:
		return convertBinaryExpr(n.Left, n.Right, core.Expr_BinaryApp_Sub)
	case ast.NodeTypeMult:
		return convertBinaryExpr(n.Left, n.Right, core.Expr_BinaryApp_Mul)
	default:
		return trueLiteral()
	}
}

// convertLogicalBinary converts binary logical operators (and, or) to protobuf.
func convertLogicalBinary(node ast.IsNode) *core.Expr {
	switch n := node.(type) {
	case ast.NodeTypeAnd:
		return &core.Expr{
			ExprKind: &core.Expr_And_{
				And: &core.Expr_And{
					Left:  convertExprNode(n.Left),
					Right: convertExprNode(n.Right),
				},
			},
		}
	case ast.NodeTypeOr:
		return &core.Expr{
			ExprKind: &core.Expr_Or_{
				Or: &core.Expr_Or{
					Left:  convertExprNode(n.Left),
					Right: convertExprNode(n.Right),
				},
			},
		}
	default:
		return trueLiteral()
	}
}

// convertUnary converts unary operators (not, negate, isEmpty) to protobuf.
func convertUnary(node ast.IsNode) *core.Expr {
	switch n := node.(type) {
	case ast.NodeTypeNot:
		return convertUnaryExpr(core.Expr_UnaryApp_Not, convertExprNode(n.Arg))
	case ast.NodeTypeNegate:
		return convertUnaryExpr(core.Expr_UnaryApp_Neg, convertExprNode(n.Arg))
	case ast.NodeTypeIsEmpty:
		return convertUnaryExpr(core.Expr_UnaryApp_IsEmpty, convertExprNode(n.Arg))
	default:
		return trueLiteral()
	}
}

// convertUnaryExpr creates a unary expression.
func convertUnaryExpr(op core.Expr_UnaryApp_Op, expr *core.Expr) *core.Expr {
	return &core.Expr{
		ExprKind: &core.Expr_UApp{
			UApp: &core.Expr_UnaryApp{
				Op:   op,
				Expr: expr,
			},
		},
	}
}

// convertIfThenElse converts an if-then-else expression to protobuf.
func convertIfThenElse(n ast.NodeTypeIfThenElse) *core.Expr {
	return &core.Expr{
		ExprKind: &core.Expr_If_{
			If: &core.Expr_If{
				TestExpr: convertExprNode(n.If),
				ThenExpr: convertExprNode(n.Then),
				ElseExpr: convertExprNode(n.Else),
			},
		},
	}
}

// convertIs converts an is-type expression to protobuf.
func convertIs(n ast.NodeTypeIs) *core.Expr {
	return &core.Expr{
		ExprKind: &core.Expr_Is_{
			Is: &core.Expr_Is{
				Expr:       convertExprNode(n.Left),
				EntityType: convertEntityType(types.EntityType(n.EntityType)),
			},
		},
	}
}

// convertIsIn converts an is-in expression to protobuf (is type && in entity).
func convertIsIn(n ast.NodeTypeIsIn) *core.Expr {
	isExpr := &core.Expr{
		ExprKind: &core.Expr_Is_{
			Is: &core.Expr_Is{
				Expr:       convertExprNode(n.Left),
				EntityType: convertEntityType(types.EntityType(n.EntityType)),
			},
		},
	}
	inExpr := convertBinaryExpr(n.Left, n.Entity, core.Expr_BinaryApp_In)
	return &core.Expr{
		ExprKind: &core.Expr_And_{
			And: &core.Expr_And{
				Left:  isExpr,
				Right: inExpr,
			},
		},
	}
}

// convertLike converts a like expression to protobuf.
func convertLike(n ast.NodeTypeLike) *core.Expr {
	return &core.Expr{
		ExprKind: &core.Expr_Like_{
			Like: &core.Expr_Like{
				Expr:    convertExprNode(n.Arg),
				Pattern: convertPattern(n.Value),
			},
		},
	}
}

// convertSet converts a set expression to protobuf.
func convertSet(n ast.NodeTypeSet) *core.Expr {
	elements := make([]*core.Expr, len(n.Elements))
	for i, elem := range n.Elements {
		elements[i] = convertExprNode(elem)
	}
	return &core.Expr{
		ExprKind: &core.Expr_Set_{
			Set: &core.Expr_Set{Elements: elements},
		},
	}
}

// convertRecord converts a record expression to protobuf.
func convertRecord(n ast.NodeTypeRecord) *core.Expr {
	items := make(map[string]*core.Expr, len(n.Elements))
	for _, elem := range n.Elements {
		items[string(elem.Key)] = convertExprNode(elem.Value)
	}
	return &core.Expr{
		ExprKind: &core.Expr_Record_{
			Record: &core.Expr_Record{Items: items},
		},
	}
}

// convertExtensionCall converts an extension function call to protobuf.
func convertExtensionCall(n ast.NodeTypeExtensionCall) *core.Expr {
	args := make([]*core.Expr, len(n.Args))
	for i, arg := range n.Args {
		args[i] = convertExprNode(arg)
	}
	return &core.Expr{
		ExprKind: &core.Expr_ExtApp{
			ExtApp: &core.Expr_ExtensionFunctionApp{
				FnName: convertExtensionName(n.Name),
				Args:   args,
			},
		},
	}
}

// convertBinaryExpr creates a binary expression from left, right nodes and an operator.
func convertBinaryExpr(left, right ast.IsNode, op core.Expr_BinaryApp_Op) *core.Expr {
	return &core.Expr{
		ExprKind: &core.Expr_BApp{
			BApp: &core.Expr_BinaryApp{
				Op:    op,
				Left:  convertExprNode(left),
				Right: convertExprNode(right),
			},
		},
	}
}

// convertPattern converts a types.Pattern to protobuf.
// Each character must be a separate PatternElem - Lean expects single characters.
func convertPattern(p types.Pattern) []*core.Expr_Like_PatternElem {
	// Use MarshalCedar to get the pattern string representation
	patternBytes := p.MarshalCedar()
	patternStr := string(patternBytes)

	// Remove surrounding quotes if present
	if len(patternStr) >= 2 && patternStr[0] == '"' && patternStr[len(patternStr)-1] == '"' {
		patternStr = patternStr[1 : len(patternStr)-1]
	}

	// Parse the pattern string into elements
	// IMPORTANT: Each literal character must be a separate PatternElem
	var elements []*core.Expr_Like_PatternElem
	i := 0
	for i < len(patternStr) {
		if patternStr[i] == '*' {
			elements = append(elements, &core.Expr_Like_PatternElem{
				Data: &core.Expr_Like_PatternElem_Wildcard_{
					Wildcard: core.Expr_Like_PatternElem_unit,
				},
			})
			i++
		} else if patternStr[i] == '\\' && i+1 < len(patternStr) {
			// Handle escape sequences - each escaped char is one PatternElem
			next := patternStr[i+1]
			var ch string
			switch next {
			case '*':
				ch = "*"
			case '\\':
				ch = "\\"
			default:
				ch = string(next)
			}
			elements = append(elements, &core.Expr_Like_PatternElem{
				Data: &core.Expr_Like_PatternElem_C{C: ch},
			})
			i += 2
		} else {
			// Single literal character - each char is a separate PatternElem
			elements = append(elements, &core.Expr_Like_PatternElem{
				Data: &core.Expr_Like_PatternElem_C{C: string(patternStr[i])},
			})
			i++
		}
	}

	return elements
}

// convertExtensionName converts a types.Path to a Name proto for extension function.
func convertExtensionName(p types.Path) *core.Name {
	// Path is like "ip" or "decimal::fromString"
	parts := strings.Split(string(p), "::")
	if len(parts) == 1 {
		return &core.Name{Id: parts[0]}
	}
	return &core.Name{
		Id:   parts[len(parts)-1],
		Path: parts[:len(parts)-1],
	}
}

// makeExtensionCallExpr creates an extension function call expression.
// This is used for extension types like decimal, ip, datetime, and duration.
func makeExtensionCallExpr(fnName string, arg string) *core.Expr {
	return &core.Expr{
		ExprKind: &core.Expr_ExtApp{
			ExtApp: &core.Expr_ExtensionFunctionApp{
				FnName: &core.Name{Id: fnName},
				Args: []*core.Expr{
					{
						ExprKind: &core.Expr_Lit{
							Lit: &core.Expr_Literal{Lit: &core.Expr_Literal_S{S: arg}},
						},
					},
				},
			},
		},
	}
}

// trueLiteral returns a true boolean literal expression.
func trueLiteral() *core.Expr {
	return &core.Expr{
		ExprKind: &core.Expr_Lit{
			Lit: &core.Expr_Literal{Lit: &core.Expr_Literal_B{B: true}},
		},
	}
}
