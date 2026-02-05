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

// This file contains SymCC (Symbolic Cedar Compiler) request types and
// conversion functions for SMT-based policy analysis.

import (
	"fmt"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
	"google.golang.org/protobuf/proto"

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/proto/pb/core"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/proto/pb/ffi"
)

// =============================================================================
// SymCC (Symbolic Cedar Compiler) Request Types
// =============================================================================

// CheckPolicyRequest represents data for a single-policy SymCC check.
// Used for neverErrors, alwaysMatches, neverMatches.
type CheckPolicyRequest struct {
	Policy     *cedar.Policy // The policy to check
	RequestEnv *RequestEnv   // Request environment (principal type, action, resource type)
}

// CheckPolicySetRequest represents data for a policy set SymCC check.
// Used for alwaysAllows, alwaysDenies.
type CheckPolicySetRequest struct {
	PolicySet  *cedar.PolicySet // The policy set to check
	RequestEnv *RequestEnv      // Request environment
}

// ComparePoliciesRequest represents data for comparing two policies.
// Used for matchesEquivalent, matchesImplies, matchesDisjoint.
type ComparePoliciesRequest struct {
	Policy1    *cedar.Policy // First policy
	Policy2    *cedar.Policy // Second policy
	RequestEnv *RequestEnv   // Request environment
}

// ComparePolicySetsRequest represents data for comparing two policy sets.
// Used for equivalent, implies, disjoint.
type ComparePolicySetsRequest struct {
	SrcPolicySet *cedar.PolicySet // Source policy set
	TgtPolicySet *cedar.PolicySet // Target policy set
	RequestEnv   *RequestEnv      // Request environment
}

// RequestEnv represents the request environment for SymCC operations.
// This defines the types of principal, action, and resource for type checking.
type RequestEnv struct {
	PrincipalType types.EntityType // Principal entity type
	ActionID      types.EntityUID  // Action entity UID
	ResourceType  types.EntityType // Resource entity type
}

// CheckPolicyFromCedar creates a CheckPolicyRequest from cedar-go types.
func CheckPolicyFromCedar(policy *cedar.Policy, env *RequestEnv) *CheckPolicyRequest {
	return &CheckPolicyRequest{
		Policy:     policy,
		RequestEnv: env,
	}
}

// CheckPolicySetFromCedar creates a CheckPolicySetRequest from cedar-go types.
func CheckPolicySetFromCedar(policies *cedar.PolicySet, env *RequestEnv) *CheckPolicySetRequest {
	return &CheckPolicySetRequest{
		PolicySet:  policies,
		RequestEnv: env,
	}
}

// ComparePoliciesFromCedar creates a ComparePoliciesRequest from cedar-go types.
func ComparePoliciesFromCedar(policy1, policy2 *cedar.Policy, env *RequestEnv) *ComparePoliciesRequest {
	return &ComparePoliciesRequest{
		Policy1:    policy1,
		Policy2:    policy2,
		RequestEnv: env,
	}
}

// ComparePolicySetsFromCedar creates a ComparePolicySetsRequest from cedar-go types.
func ComparePolicySetsFromCedar(src, tgt *cedar.PolicySet, env *RequestEnv) *ComparePolicySetsRequest {
	return &ComparePolicySetsRequest{
		SrcPolicySet: src,
		TgtPolicySet: tgt,
		RequestEnv:   env,
	}
}

// ToProtobuf converts a CheckPolicyRequest to protobuf-encoded bytes.
func (r *CheckPolicyRequest) ToProtobuf() ([]byte, error) {
	policy, err := convertSinglePolicy("policy", r.Policy)
	if err != nil {
		return nil, fmt.Errorf("failed to convert policy: %w", err)
	}

	reqEnv := convertRequestEnv(r.RequestEnv)

	msg := &ffi.CheckPolicyRequest{
		Policy:  policy,
		Request: reqEnv,
	}

	return proto.Marshal(msg)
}

// ToProtobuf converts a CheckPolicySetRequest to protobuf-encoded bytes.
func (r *CheckPolicySetRequest) ToProtobuf() ([]byte, error) {
	policySet, err := convertPolicySet(r.PolicySet)
	if err != nil {
		return nil, fmt.Errorf("failed to convert policy set: %w", err)
	}

	reqEnv := convertRequestEnv(r.RequestEnv)

	msg := &ffi.CheckPolicySetRequest{
		PolicySet: policySet,
		Request:   reqEnv,
	}

	return proto.Marshal(msg)
}

// ToProtobuf converts a ComparePoliciesRequest to protobuf-encoded bytes.
func (r *ComparePoliciesRequest) ToProtobuf() ([]byte, error) {
	policy1, err := convertSinglePolicy("policy1", r.Policy1)
	if err != nil {
		return nil, fmt.Errorf("failed to convert policy1: %w", err)
	}

	policy2, err := convertSinglePolicy("policy2", r.Policy2)
	if err != nil {
		return nil, fmt.Errorf("failed to convert policy2: %w", err)
	}

	reqEnv := convertRequestEnv(r.RequestEnv)

	msg := &ffi.ComparePoliciesRequest{
		Policy1: policy1,
		Policy2: policy2,
		Request: reqEnv,
	}

	return proto.Marshal(msg)
}

// ToProtobuf converts a ComparePolicySetsRequest to protobuf-encoded bytes.
func (r *ComparePolicySetsRequest) ToProtobuf() ([]byte, error) {
	srcPolicySet, err := convertPolicySet(r.SrcPolicySet)
	if err != nil {
		return nil, fmt.Errorf("failed to convert source policy set: %w", err)
	}

	tgtPolicySet, err := convertPolicySet(r.TgtPolicySet)
	if err != nil {
		return nil, fmt.Errorf("failed to convert target policy set: %w", err)
	}

	reqEnv := convertRequestEnv(r.RequestEnv)

	msg := &ffi.ComparePolicySetsRequest{
		SrcPolicySet: srcPolicySet,
		TgtPolicySet: tgtPolicySet,
		Request:      reqEnv,
	}

	return proto.Marshal(msg)
}

// SchemaToProtobuf converts a schema to protobuf-encoded bytes for Lean loading.
func SchemaToProtobuf(s *schema.Schema) ([]byte, error) {
	protoSchema, err := convertSchema(s)
	if err != nil {
		return nil, fmt.Errorf("failed to convert schema: %w", err)
	}
	return proto.Marshal(protoSchema)
}

// convertSinglePolicy converts a single cedar.Policy to the ffi.Policy protobuf type.
func convertSinglePolicy(id string, policy *cedar.Policy) (*ffi.Policy, error) {
	// Convert to template and link using the existing conversion
	template, link, err := convertPolicyToTemplate(id, policy)
	if err != nil {
		return nil, err
	}

	return &ffi.Policy{
		Template: template,
		Policy:   link,
	}, nil
}

// convertRequestEnv converts a RequestEnv to protobuf.
func convertRequestEnv(env *RequestEnv) *ffi.RequestEnv {
	if env == nil {
		return &ffi.RequestEnv{
			Principal: &core.Name{Id: "User"},
			Action:    &core.EntityUid{Ty: &core.Name{Id: "Action"}, Eid: "action"},
			Resource:  &core.Name{Id: "Resource"},
		}
	}

	return &ffi.RequestEnv{
		Principal: convertEntityType(env.PrincipalType),
		Action:    convertEntityUID(env.ActionID),
		Resource:  convertEntityType(env.ResourceType),
	}
}
