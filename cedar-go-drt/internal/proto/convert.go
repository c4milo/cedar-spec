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

// Package proto provides conversion utilities between cedar-go types
// and protobuf messages used for Lean FFI communication.
package proto

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/ast"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
	"google.golang.org/protobuf/proto"

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/proto/pb/core"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/proto/pb/ffi"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/proto/pb/validator"
)

// AuthorizationRequest represents the data needed for an authorization check.
type AuthorizationRequest struct {
	Request  *cedar.Request
	Policies *cedar.PolicySet
	Entities types.EntityMap
}

// ValidationRequest represents the data needed for a validation check.
type ValidationRequest struct {
	Schema   *schema.Schema
	Policies *cedar.PolicySet
}

// EntityValidationRequest represents data for entity validation.
type EntityValidationRequest struct {
	Schema   *schema.Schema
	Entities types.EntityMap
}

// RequestValidationRequest represents data for request validation.
type RequestValidationRequest struct {
	Schema  *schema.Schema
	Request *cedar.Request
}

// LevelValidationRequest represents data for level-based validation.
type LevelValidationRequest struct {
	Schema   *schema.Schema
	Policies *cedar.PolicySet
	Level    int32
}

// EvaluationRequest represents data for expression evaluation.
type EvaluationRequest struct {
	Expr     ast.Node        // The expression to evaluate
	Request  *cedar.Request  // Request context (principal, action, resource)
	Entities types.EntityMap // Entity store
	Expected ast.Node        // Optional: expected result for comparison
}

// BatchedEvaluationRequest represents data for batched (partial) evaluation.
// This is used for TPE (Template Policy Engine) testing where policies are
// partially evaluated with lazy entity loading.
type BatchedEvaluationRequest struct {
	Policies  *cedar.PolicySet // Policies to evaluate (should contain exactly one policy for TPE)
	Schema    *schema.Schema   // Schema for type information
	Request   *cedar.Request   // Request context
	Entities  types.EntityMap  // Initial entity store
	Iteration uint32           // Maximum number of entity loading iterations
}

// ToProtobuf converts an AuthorizationRequest to protobuf-encoded bytes.
func (r *AuthorizationRequest) ToProtobuf() ([]byte, error) {
	req, err := convertRequest(r.Request)
	if err != nil {
		return nil, fmt.Errorf("failed to convert request: %w", err)
	}

	policies, err := convertPolicySet(r.Policies)
	if err != nil {
		return nil, fmt.Errorf("failed to convert policies: %w", err)
	}

	entities, err := convertEntities(r.Entities)
	if err != nil {
		return nil, fmt.Errorf("failed to convert entities: %w", err)
	}

	msg := &ffi.AuthorizationRequest{
		Request:  req,
		Policies: policies,
		Entities: entities,
	}

	return proto.Marshal(msg)
}

// ToProtobuf converts a ValidationRequest to protobuf-encoded bytes.
func (r *ValidationRequest) ToProtobuf() ([]byte, error) {
	schema, err := convertSchema(r.Schema)
	if err != nil {
		return nil, fmt.Errorf("failed to convert schema: %w", err)
	}

	policies, err := convertPolicySet(r.Policies)
	if err != nil {
		return nil, fmt.Errorf("failed to convert policies: %w", err)
	}

	msg := &ffi.ValidationRequest{
		Schema:   schema,
		Policies: policies,
		Mode:     validator.ValidationMode_Strict,
	}

	return proto.Marshal(msg)
}

// ToProtobuf converts an EvaluationRequest to protobuf-encoded bytes.
func (r *EvaluationRequest) ToProtobuf() ([]byte, error) {
	req, err := convertRequest(r.Request)
	if err != nil {
		return nil, fmt.Errorf("failed to convert request: %w", err)
	}

	entities, err := convertEntities(r.Entities)
	if err != nil {
		return nil, fmt.Errorf("failed to convert entities: %w", err)
	}

	expr := convertExprNode(r.Expr.AsIsNode())

	msg := &ffi.EvaluationRequestChecked{
		Expr:     expr,
		Request:  req,
		Entities: entities,
	}

	// Add expected value if provided
	if r.Expected.AsIsNode() != nil {
		msg.Expected = convertExprNode(r.Expected.AsIsNode())
	}

	return proto.Marshal(msg)
}

// PolicySetFromCedar creates an AuthorizationRequest from cedar-go types.
func PolicySetFromCedar(policies *cedar.PolicySet, entities types.EntityMap, request *cedar.Request) *AuthorizationRequest {
	return &AuthorizationRequest{
		Request:  request,
		Policies: policies,
		Entities: entities,
	}
}

// ValidationFromCedar creates a ValidationRequest from cedar-go types.
func ValidationFromCedar(policies *cedar.PolicySet, s *schema.Schema) *ValidationRequest {
	return &ValidationRequest{
		Schema:   s,
		Policies: policies,
	}
}

// EvaluationFromCedar creates an EvaluationRequest from cedar-go types.
func EvaluationFromCedar(expr ast.Node, entities types.EntityMap, request *cedar.Request, expected ast.Node) *EvaluationRequest {
	return &EvaluationRequest{
		Expr:     expr,
		Request:  request,
		Entities: entities,
		Expected: expected,
	}
}

// EntityValidationFromCedar creates an EntityValidationRequest from cedar-go types.
func EntityValidationFromCedar(s *schema.Schema, entities types.EntityMap) *EntityValidationRequest {
	return &EntityValidationRequest{
		Schema:   s,
		Entities: entities,
	}
}

// RequestValidationFromCedar creates a RequestValidationRequest from cedar-go types.
func RequestValidationFromCedar(s *schema.Schema, request *cedar.Request) *RequestValidationRequest {
	return &RequestValidationRequest{
		Schema:  s,
		Request: request,
	}
}

// LevelValidationFromCedar creates a LevelValidationRequest from cedar-go types.
func LevelValidationFromCedar(s *schema.Schema, policies *cedar.PolicySet, level int32) *LevelValidationRequest {
	return &LevelValidationRequest{
		Schema:   s,
		Policies: policies,
		Level:    level,
	}
}

// BatchedEvaluationFromCedar creates a BatchedEvaluationRequest from cedar-go types.
func BatchedEvaluationFromCedar(policies *cedar.PolicySet, s *schema.Schema, request *cedar.Request, entities types.EntityMap, iteration uint32) *BatchedEvaluationRequest {
	return &BatchedEvaluationRequest{
		Policies:  policies,
		Schema:    s,
		Request:   request,
		Entities:  entities,
		Iteration: iteration,
	}
}

// ToProtobuf converts an EntityValidationRequest to protobuf-encoded bytes.
func (r *EntityValidationRequest) ToProtobuf() ([]byte, error) {
	s, err := convertSchema(r.Schema)
	if err != nil {
		return nil, fmt.Errorf("failed to convert schema: %w", err)
	}

	entities, err := convertEntities(r.Entities)
	if err != nil {
		return nil, fmt.Errorf("failed to convert entities: %w", err)
	}

	msg := &ffi.EntityValidationRequest{
		Schema:   s,
		Entities: entities,
	}

	return proto.Marshal(msg)
}

// ToProtobuf converts a RequestValidationRequest to protobuf-encoded bytes.
func (r *RequestValidationRequest) ToProtobuf() ([]byte, error) {
	s, err := convertSchema(r.Schema)
	if err != nil {
		return nil, fmt.Errorf("failed to convert schema: %w", err)
	}

	req, err := convertRequest(r.Request)
	if err != nil {
		return nil, fmt.Errorf("failed to convert request: %w", err)
	}

	msg := &ffi.RequestValidationRequest{
		Schema:  s,
		Request: req,
	}

	return proto.Marshal(msg)
}

// ToProtobuf converts a LevelValidationRequest to protobuf-encoded bytes.
func (r *LevelValidationRequest) ToProtobuf() ([]byte, error) {
	s, err := convertSchema(r.Schema)
	if err != nil {
		return nil, fmt.Errorf("failed to convert schema: %w", err)
	}

	policies, err := convertPolicySet(r.Policies)
	if err != nil {
		return nil, fmt.Errorf("failed to convert policies: %w", err)
	}

	msg := &ffi.LevelValidationRequest{
		Schema:   s,
		Policies: policies,
		Level:    r.Level,
	}

	return proto.Marshal(msg)
}

// ToProtobuf converts a BatchedEvaluationRequest to protobuf-encoded bytes.
func (r *BatchedEvaluationRequest) ToProtobuf() ([]byte, error) {
	policies, err := convertPolicySet(r.Policies)
	if err != nil {
		return nil, fmt.Errorf("failed to convert policies: %w", err)
	}

	s, err := convertSchema(r.Schema)
	if err != nil {
		return nil, fmt.Errorf("failed to convert schema: %w", err)
	}

	req, err := convertRequest(r.Request)
	if err != nil {
		return nil, fmt.Errorf("failed to convert request: %w", err)
	}

	entities, err := convertEntities(r.Entities)
	if err != nil {
		return nil, fmt.Errorf("failed to convert entities: %w", err)
	}

	msg := &ffi.BatchedEvaluationRequest{
		Policies:  policies,
		Schema:    s,
		Request:   req,
		Entities:  entities,
		Iteration: r.Iteration,
	}

	return proto.Marshal(msg)
}

// convertRequest converts a cedar.Request to protobuf.
func convertRequest(req *cedar.Request) (*core.Request, error) {
	if req == nil {
		return nil, fmt.Errorf("request is nil")
	}

	return &core.Request{
		Principal: convertEntityUID(req.Principal),
		Action:    convertEntityUID(req.Action),
		Resource:  convertEntityUID(req.Resource),
		Context:   convertContextToRecord(req.Context),
	}, nil
}

// convertEntityUID converts a types.EntityUID to protobuf.
func convertEntityUID(uid types.EntityUID) *core.EntityUid {
	return &core.EntityUid{
		Ty:  convertEntityType(uid.Type),
		Eid: string(uid.ID),
	}
}

// convertEntityType converts an entity type to a Name proto.
func convertEntityType(et types.EntityType) *core.Name {
	// EntityType is like "User" or "Namespace::Type"
	parts := strings.Split(string(et), "::")
	if len(parts) == 1 {
		return &core.Name{Id: parts[0]}
	}
	// Last part is the Id, rest is the Path
	return &core.Name{
		Id:   parts[len(parts)-1],
		Path: parts[:len(parts)-1],
	}
}

// convertContextToRecord converts a types.Record to protobuf context map.
func convertContextToRecord(ctx types.Record) map[string]*core.Expr {
	if ctx.Len() == 0 {
		return nil
	}

	result := make(map[string]*core.Expr, ctx.Len())
	for key, val := range ctx.All() {
		result[string(key)] = convertValue(val)
	}
	return result
}

// convertValue converts a types.Value to a protobuf Expr literal.
func convertValue(val types.Value) *core.Expr {
	switch v := val.(type) {
	case types.Boolean:
		return &core.Expr{
			ExprKind: &core.Expr_Lit{
				Lit: &core.Expr_Literal{Lit: &core.Expr_Literal_B{B: bool(v)}},
			},
		}
	case types.Long:
		return &core.Expr{
			ExprKind: &core.Expr_Lit{
				Lit: &core.Expr_Literal{Lit: &core.Expr_Literal_I{I: int64(v)}},
			},
		}
	case types.String:
		return &core.Expr{
			ExprKind: &core.Expr_Lit{
				Lit: &core.Expr_Literal{Lit: &core.Expr_Literal_S{S: string(v)}},
			},
		}
	case types.EntityUID:
		return &core.Expr{
			ExprKind: &core.Expr_Lit{
				Lit: &core.Expr_Literal{
					Lit: &core.Expr_Literal_Euid{
						Euid: convertEntityUID(v),
					},
				},
			},
		}
	case types.Set:
		elements := make([]*core.Expr, 0, v.Len())
		for _, elem := range v.Slice() {
			elements = append(elements, convertValue(elem))
		}
		return &core.Expr{
			ExprKind: &core.Expr_Set_{
				Set: &core.Expr_Set{
					Elements: elements,
				},
			},
		}
	case types.Record:
		items := make(map[string]*core.Expr, v.Len())
		for k, rv := range v.All() {
			items[string(k)] = convertValue(rv)
		}
		return &core.Expr{
			ExprKind: &core.Expr_Record_{
				Record: &core.Expr_Record{
					Items: items,
				},
			},
		}
	case types.Decimal:
		// Extension type: decimal("value")
		return makeExtensionCallExpr("decimal", v.String())
	case types.IPAddr:
		// Extension type: ip("value")
		return makeExtensionCallExpr("ip", v.String())
	case types.Datetime:
		// Extension type: datetime("value")
		return makeExtensionCallExpr("datetime", v.String())
	case types.Duration:
		// Extension type: duration("value")
		return makeExtensionCallExpr("duration", v.String())
	default:
		// For unknown types, return a placeholder
		return trueLiteral()
	}
}

// convertPolicySet converts a cedar.PolicySet to protobuf.
func convertPolicySet(ps *cedar.PolicySet) (*core.PolicySet, error) {
	if ps == nil {
		return &core.PolicySet{
			Templates: []*core.TemplateBody{},
			Links:     []*core.Policy{},
		}, nil
	}

	var templates []*core.TemplateBody
	var links []*core.Policy

	for id, policy := range ps.All() {
		template, link, err := convertPolicyToTemplate(string(id), policy)
		if err != nil {
			return nil, fmt.Errorf("failed to convert policy %s: %w", id, err)
		}
		templates = append(templates, template)
		links = append(links, link)
	}

	return &core.PolicySet{
		Templates: templates,
		Links:     links,
	}, nil
}

// convertPolicyToTemplate converts a single cedar.Policy to a template and link.
func convertPolicyToTemplate(id string, policy *cedar.Policy) (*core.TemplateBody, *core.Policy, error) {
	policyAST := policy.AST()

	// Convert effect
	var effect core.Effect
	if policyAST.Effect == ast.EffectPermit {
		effect = core.Effect_Permit
	} else {
		effect = core.Effect_Forbid
	}

	// Convert principal constraint
	principalConstraint := convertPrincipalScope(policyAST.Principal)

	// Convert action constraint
	actionConstraint := convertActionScope(policyAST.Action)

	// Convert resource constraint
	resourceConstraint := convertResourceScope(policyAST.Resource)

	// Convert conditions (when/unless clauses)
	conditions := convertConditions(policyAST.Conditions)

	template := &core.TemplateBody{
		Id:                  id,
		Effect:              effect,
		PrincipalConstraint: principalConstraint,
		ActionConstraint:    actionConstraint,
		ResourceConstraint:  resourceConstraint,
		NonScopeConstraints: conditions,
	}

	// Create a link for the static policy
	link := &core.Policy{
		TemplateId:     id,
		IsTemplateLink: false,
	}

	return template, link, nil
}

// convertPrincipalScope converts a principal scope constraint to protobuf.
func convertPrincipalScope(scope ast.IsPrincipalScopeNode) *core.PrincipalOrResourceConstraint {
	switch s := scope.(type) {
	case ast.ScopeTypeAll:
		return &core.PrincipalOrResourceConstraint{
			Data: &core.PrincipalOrResourceConstraint_Any_{
				Any: core.PrincipalOrResourceConstraint_unit,
			},
		}
	case ast.ScopeTypeEq:
		return &core.PrincipalOrResourceConstraint{
			Data: &core.PrincipalOrResourceConstraint_Eq{
				Eq: &core.PrincipalOrResourceConstraint_EqMessage{
					Er: &core.EntityReference{
						Data: &core.EntityReference_Euid{
							Euid: convertEntityUID(s.Entity),
						},
					},
				},
			},
		}
	case ast.ScopeTypeIn:
		return &core.PrincipalOrResourceConstraint{
			Data: &core.PrincipalOrResourceConstraint_In{
				In: &core.PrincipalOrResourceConstraint_InMessage{
					Er: &core.EntityReference{
						Data: &core.EntityReference_Euid{
							Euid: convertEntityUID(s.Entity),
						},
					},
				},
			},
		}
	case ast.ScopeTypeIs:
		return &core.PrincipalOrResourceConstraint{
			Data: &core.PrincipalOrResourceConstraint_Is{
				Is: &core.PrincipalOrResourceConstraint_IsMessage{
					EntityType: convertEntityType(s.Type),
				},
			},
		}
	case ast.ScopeTypeIsIn:
		return &core.PrincipalOrResourceConstraint{
			Data: &core.PrincipalOrResourceConstraint_IsIn{
				IsIn: &core.PrincipalOrResourceConstraint_IsInMessage{
					EntityType: convertEntityType(s.Type),
					Er: &core.EntityReference{
						Data: &core.EntityReference_Euid{
							Euid: convertEntityUID(s.Entity),
						},
					},
				},
			},
		}
	default:
		// Default to Any
		return &core.PrincipalOrResourceConstraint{
			Data: &core.PrincipalOrResourceConstraint_Any_{
				Any: core.PrincipalOrResourceConstraint_unit,
			},
		}
	}
}

// convertResourceScope converts a resource scope constraint to protobuf.
func convertResourceScope(scope ast.IsResourceScopeNode) *core.PrincipalOrResourceConstraint {
	switch s := scope.(type) {
	case ast.ScopeTypeAll:
		return &core.PrincipalOrResourceConstraint{
			Data: &core.PrincipalOrResourceConstraint_Any_{
				Any: core.PrincipalOrResourceConstraint_unit,
			},
		}
	case ast.ScopeTypeEq:
		return &core.PrincipalOrResourceConstraint{
			Data: &core.PrincipalOrResourceConstraint_Eq{
				Eq: &core.PrincipalOrResourceConstraint_EqMessage{
					Er: &core.EntityReference{
						Data: &core.EntityReference_Euid{
							Euid: convertEntityUID(s.Entity),
						},
					},
				},
			},
		}
	case ast.ScopeTypeIn:
		return &core.PrincipalOrResourceConstraint{
			Data: &core.PrincipalOrResourceConstraint_In{
				In: &core.PrincipalOrResourceConstraint_InMessage{
					Er: &core.EntityReference{
						Data: &core.EntityReference_Euid{
							Euid: convertEntityUID(s.Entity),
						},
					},
				},
			},
		}
	case ast.ScopeTypeIs:
		return &core.PrincipalOrResourceConstraint{
			Data: &core.PrincipalOrResourceConstraint_Is{
				Is: &core.PrincipalOrResourceConstraint_IsMessage{
					EntityType: convertEntityType(s.Type),
				},
			},
		}
	case ast.ScopeTypeIsIn:
		return &core.PrincipalOrResourceConstraint{
			Data: &core.PrincipalOrResourceConstraint_IsIn{
				IsIn: &core.PrincipalOrResourceConstraint_IsInMessage{
					EntityType: convertEntityType(s.Type),
					Er: &core.EntityReference{
						Data: &core.EntityReference_Euid{
							Euid: convertEntityUID(s.Entity),
						},
					},
				},
			},
		}
	default:
		// Default to Any
		return &core.PrincipalOrResourceConstraint{
			Data: &core.PrincipalOrResourceConstraint_Any_{
				Any: core.PrincipalOrResourceConstraint_unit,
			},
		}
	}
}

// convertActionScope converts an action scope constraint to protobuf.
func convertActionScope(scope ast.IsActionScopeNode) *core.ActionConstraint {
	switch s := scope.(type) {
	case ast.ScopeTypeAll:
		return &core.ActionConstraint{
			Data: &core.ActionConstraint_Any_{
				Any: core.ActionConstraint_unit,
			},
		}
	case ast.ScopeTypeEq:
		return &core.ActionConstraint{
			Data: &core.ActionConstraint_Eq{
				Eq: &core.ActionConstraint_EqMessage{
					Euid: convertEntityUID(s.Entity),
				},
			},
		}
	case ast.ScopeTypeIn:
		return &core.ActionConstraint{
			Data: &core.ActionConstraint_In{
				In: &core.ActionConstraint_InMessage{
					Euids: []*core.EntityUid{convertEntityUID(s.Entity)},
				},
			},
		}
	case ast.ScopeTypeInSet:
		euids := make([]*core.EntityUid, len(s.Entities))
		for i, e := range s.Entities {
			euids[i] = convertEntityUID(e)
		}
		return &core.ActionConstraint{
			Data: &core.ActionConstraint_In{
				In: &core.ActionConstraint_InMessage{
					Euids: euids,
				},
			},
		}
	default:
		// Default to Any
		return &core.ActionConstraint{
			Data: &core.ActionConstraint_Any_{
				Any: core.ActionConstraint_unit,
			},
		}
	}
}

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

// convertExtensionCall creates an extension function call expression.
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
	Required   bool                      `json:"required"`
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

	for nsName, ns := range js {
		if ns == nil {
			continue
		}
		appendEntityDecls(result, nsName, ns)
		appendActionDecls(result, nsName, ns)
	}

	return result
}

func appendEntityDecls(result *validator.Schema, nsName string, ns *jsonNamespace) {
	for entityName, entity := range ns.EntityTypes {
		entityDecl := convertEntityDecl(nsName, entityName, entity)
		result.EntityDecls = append(result.EntityDecls, entityDecl)
	}
}

func convertEntityDecl(nsName, entityName string, entity *jsonEntity) *validator.EntityDecl {
	fullName := resolveFullName(nsName, entityName)

	entityDecl := &validator.EntityDecl{
		Name:       convertEntityType(types.EntityType(fullName)),
		Attributes: make(map[string]*validator.AttributeType),
	}

	appendMemberOfDescendants(entityDecl, nsName, entity.MemberOfTypes)
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

func appendMemberOfDescendants(entityDecl *validator.EntityDecl, nsName string, memberOfTypes []string) {
	for _, memberOf := range memberOfTypes {
		memberName := resolveTypeNameInNamespace(nsName, memberOf)
		entityDecl.Descendants = append(entityDecl.Descendants,
			convertEntityType(types.EntityType(memberName)))
	}
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
	return &validator.AttributeType{
		AttrType:   convertJSONTypeToProto(attr, nsName),
		IsRequired: attr.Required,
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
	default:
		// Default to String for unknown types
		return &validator.Type{
			Data: &validator.Type_Prim_{Prim: validator.Type_String},
		}
	}
}
