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
