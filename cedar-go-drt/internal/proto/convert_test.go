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

import (
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
	"google.golang.org/protobuf/proto"

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/proto/pb/ffi"
)

func TestPolicySetFromCedar(t *testing.T) {
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource);`)); err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	policies.Add("test", &policy)

	entities := types.EntityMap{
		types.EntityUID{Type: "User", ID: "alice"}: types.Entity{
			UID: types.EntityUID{Type: "User", ID: "alice"},
		},
	}

	request := &cedar.Request{
		Principal: types.EntityUID{Type: "User", ID: "alice"},
		Action:    types.EntityUID{Type: "Action", ID: "view"},
		Resource:  types.EntityUID{Type: "Document", ID: "doc1"},
		Context:   types.NewRecord(types.RecordMap{}),
	}

	authReq := PolicySetFromCedar(policies, entities, request)

	if authReq.Policies != policies {
		t.Error("policies not set correctly")
	}
	if authReq.Request != request {
		t.Error("request not set correctly")
	}
	if len(authReq.Entities) != 1 {
		t.Errorf("expected 1 entity, got %d", len(authReq.Entities))
	}
}

func TestValidationFromCedar(t *testing.T) {
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource);`)); err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	policies.Add("test", &policy)

	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {},
				"Document": {}
			},
			"actions": {
				"view": {
					"appliesTo": {
						"principalTypes": ["User"],
						"resourceTypes": ["Document"]
					}
				}
			}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("parse schema: %v", err)
	}

	valReq := ValidationFromCedar(policies, &s)

	if valReq.Policies != policies {
		t.Error("policies not set correctly")
	}
	if valReq.Schema != &s {
		t.Error("schema not set correctly")
	}
}

func TestAuthorizationRequestToProtobuf(t *testing.T) {
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource);`)); err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	policies.Add("test", &policy)

	entities := types.EntityMap{}

	request := &cedar.Request{
		Principal: types.EntityUID{Type: "User", ID: "alice"},
		Action:    types.EntityUID{Type: "Action", ID: "view"},
		Resource:  types.EntityUID{Type: "Document", ID: "doc1"},
		Context:   types.NewRecord(types.RecordMap{}),
	}

	authReq := PolicySetFromCedar(policies, entities, request)

	data, err := authReq.ToProtobuf()
	if err != nil {
		t.Fatalf("ToProtobuf error: %v", err)
	}

	if len(data) == 0 {
		t.Error("expected non-empty protobuf data")
	}

	// Verify it's valid protobuf by unmarshaling
	var msg ffi.AuthorizationRequest
	if err := proto.Unmarshal(data, &msg); err != nil {
		t.Fatalf("protobuf unmarshal error: %v", err)
	}

	// Verify request fields
	if msg.Request == nil {
		t.Error("request is nil")
	}
	if msg.Policies == nil {
		t.Error("policies is nil")
	}
}

func TestValidationRequestToProtobuf(t *testing.T) {
	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource);`)); err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	policies.Add("test", &policy)

	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {}
			},
			"actions": {
				"view": {}
			}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("parse schema: %v", err)
	}

	valReq := ValidationFromCedar(policies, &s)

	data, err := valReq.ToProtobuf()
	if err != nil {
		t.Fatalf("ToProtobuf error: %v", err)
	}

	if len(data) == 0 {
		t.Error("expected non-empty protobuf data")
	}

	// Verify it's valid protobuf
	var msg ffi.ValidationRequest
	if err := proto.Unmarshal(data, &msg); err != nil {
		t.Fatalf("protobuf unmarshal error: %v", err)
	}

	if msg.Schema == nil {
		t.Error("schema is nil")
	}
	if msg.Policies == nil {
		t.Error("policies is nil")
	}
}

func TestEntityValidationFromCedar(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {
					"shape": {
						"type": "Record",
						"attributes": {
							"name": {"type": "String", "required": true}
						}
					}
				}
			},
			"actions": {}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("parse schema: %v", err)
	}

	entities := types.EntityMap{
		types.EntityUID{Type: "User", ID: "alice"}: types.Entity{
			UID: types.EntityUID{Type: "User", ID: "alice"},
			Attributes: types.NewRecord(types.RecordMap{
				"name": types.String("Alice"),
			}),
		},
	}

	req := EntityValidationFromCedar(&s, entities)

	if req.Schema != &s {
		t.Error("schema not set correctly")
	}
	if len(req.Entities) != 1 {
		t.Errorf("expected 1 entity, got %d", len(req.Entities))
	}

	// Test ToProtobuf
	data, err := req.ToProtobuf()
	if err != nil {
		t.Fatalf("ToProtobuf error: %v", err)
	}

	var msg ffi.EntityValidationRequest
	if err := proto.Unmarshal(data, &msg); err != nil {
		t.Fatalf("protobuf unmarshal error: %v", err)
	}
}

func TestRequestValidationFromCedar(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {
				"User": {},
				"Document": {}
			},
			"actions": {
				"view": {
					"appliesTo": {
						"principalTypes": ["User"],
						"resourceTypes": ["Document"]
					}
				}
			}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("parse schema: %v", err)
	}

	request := &cedar.Request{
		Principal: types.EntityUID{Type: "User", ID: "alice"},
		Action:    types.EntityUID{Type: "Action", ID: "view"},
		Resource:  types.EntityUID{Type: "Document", ID: "doc1"},
		Context:   types.NewRecord(types.RecordMap{}),
	}

	req := RequestValidationFromCedar(&s, request)

	if req.Schema != &s {
		t.Error("schema not set correctly")
	}
	if req.Request != request {
		t.Error("request not set correctly")
	}

	// Test ToProtobuf
	data, err := req.ToProtobuf()
	if err != nil {
		t.Fatalf("ToProtobuf error: %v", err)
	}

	var msg ffi.RequestValidationRequest
	if err := proto.Unmarshal(data, &msg); err != nil {
		t.Fatalf("protobuf unmarshal error: %v", err)
	}
}

func TestLevelValidationFromCedar(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {"User": {}},
			"actions": {"view": {}}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("parse schema: %v", err)
	}

	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource);`)); err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	policies.Add("test", &policy)

	req := LevelValidationFromCedar(&s, policies, 2)

	if req.Schema != &s {
		t.Error("schema not set correctly")
	}
	if req.Policies != policies {
		t.Error("policies not set correctly")
	}
	if req.Level != 2 {
		t.Errorf("expected level 2, got %d", req.Level)
	}
}

func TestBatchedEvaluationFromCedar(t *testing.T) {
	schemaJSON := `{
		"": {
			"entityTypes": {"User": {}, "Document": {}},
			"actions": {"view": {}}
		}
	}`

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(schemaJSON)); err != nil {
		t.Fatalf("parse schema: %v", err)
	}

	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource);`)); err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	policies.Add("test", &policy)

	request := &cedar.Request{
		Principal: types.EntityUID{Type: "User", ID: "alice"},
		Action:    types.EntityUID{Type: "Action", ID: "view"},
		Resource:  types.EntityUID{Type: "Document", ID: "doc1"},
		Context:   types.NewRecord(types.RecordMap{}),
	}

	entities := types.EntityMap{}

	req := BatchedEvaluationFromCedar(policies, &s, request, entities, 5)

	if req.Policies != policies {
		t.Error("policies not set correctly")
	}
	if req.Schema != &s {
		t.Error("schema not set correctly")
	}
	if req.Request != request {
		t.Error("request not set correctly")
	}
	if req.Iteration != 5 {
		t.Errorf("expected iteration 5, got %d", req.Iteration)
	}
}
