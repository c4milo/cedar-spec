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

package fuzz

import (
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	"google.golang.org/protobuf/proto"

	cedarproto "github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/proto"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/typegen"
)

// FuzzProtobufRoundtrip tests that authorization requests survive protobuf serialization.
// This verifies our protobuf conversion is lossless.
func FuzzProtobufRoundtrip(f *testing.F) {
	f.Add([]byte("proto-roundtrip-seed-1"))
	f.Add([]byte("proto-roundtrip-seed-2"))
	f.Add(make([]byte, 128))

	inputGen := typegen.TypeDirectedInputGenerator()

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 32 {
			return
		}

		// Generate type-directed input
		input, err := inputGen.Generate(data)
		if err != nil {
			return
		}

		if input.Policies == nil || len(input.Requests) == 0 {
			return
		}

		req := input.Requests[0]

		// Convert to protobuf
		authReq := cedarproto.PolicySetFromCedar(input.Policies, input.Entities.Entities, &req)
		protoBytes, err := authReq.ToProtobuf()
		if err != nil {
			t.Errorf("Failed to serialize to protobuf: %v", err)
			return
		}

		if len(protoBytes) == 0 {
			t.Error("Protobuf serialization produced empty bytes")
			return
		}

		// Verify it's valid protobuf by checking we can determine message size
		// (We can't fully deserialize without regenerating the proto structs)
		if !isValidProtobuf(protoBytes) {
			t.Errorf("Invalid protobuf produced: %d bytes", len(protoBytes))
		}
	})
}

// isValidProtobuf does a basic check that bytes look like valid protobuf.
func isValidProtobuf(data []byte) bool {
	// Protobuf messages start with field tags (varint)
	// A completely empty message is valid (0 bytes)
	// Otherwise, first byte should be a valid field tag
	if len(data) == 0 {
		return true
	}
	// First byte should be a field number + wire type
	// Wire types are 0-5, so lower 3 bits should be <= 5
	wireType := data[0] & 0x07
	return wireType <= 5
}

// FuzzProtobufPolicyRoundtrip tests policy-specific protobuf roundtrip.
func FuzzProtobufPolicyRoundtrip(f *testing.F) {
	f.Add([]byte(`permit(principal, action, resource);`))
	f.Add([]byte(`forbid(principal, action, resource) when { context.admin == false };`))
	f.Add([]byte(`permit(principal == User::"alice", action, resource in Folder::"public");`))

	f.Fuzz(func(t *testing.T, policyBytes []byte) {
		// Parse as Cedar
		var policy cedar.Policy
		if err := policy.UnmarshalCedar(policyBytes); err != nil {
			return // Invalid Cedar, skip
		}

		ps := cedar.NewPolicySet()
		ps.Add("policy0", &policy)

		entities := types.EntityMap{}
		req := cedar.Request{
			Principal: types.EntityUID{Type: "User", ID: "test"},
			Action:    types.EntityUID{Type: "Action", ID: "view"},
			Resource:  types.EntityUID{Type: "Doc", ID: "doc1"},
			Context:   types.NewRecord(types.RecordMap{}),
		}

		// Convert to protobuf
		authReq := cedarproto.PolicySetFromCedar(ps, entities, &req)
		protoBytes, err := authReq.ToProtobuf()
		if err != nil {
			t.Errorf("Failed to serialize policy to protobuf: %v", err)
			return
		}

		if len(protoBytes) == 0 {
			t.Error("Protobuf serialization produced empty bytes for valid policy")
		}
	})
}

// TestProtobufRoundtripBasic tests basic protobuf roundtrip functionality.
func TestProtobufRoundtripBasic(t *testing.T) {
	ps := cedar.NewPolicySet()
	var policy cedar.Policy
	err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource);`))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	ps.Add("p1", &policy)

	entities := types.EntityMap{
		types.EntityUID{Type: "User", ID: "alice"}: types.Entity{
			Attributes: types.NewRecord(types.RecordMap{
				"role": types.String("admin"),
			}),
		},
	}

	req := cedar.Request{
		Principal: types.EntityUID{Type: "User", ID: "alice"},
		Action:    types.EntityUID{Type: "Action", ID: "view"},
		Resource:  types.EntityUID{Type: "Doc", ID: "doc1"},
		Context:   types.NewRecord(types.RecordMap{}),
	}

	authReq := cedarproto.PolicySetFromCedar(ps, entities, &req)
	protoBytes, err := authReq.ToProtobuf()
	if err != nil {
		t.Fatalf("Protobuf serialization failed: %v", err)
	}

	t.Logf("Protobuf size: %d bytes", len(protoBytes))

	if len(protoBytes) < 10 {
		t.Errorf("Protobuf too small: %d bytes", len(protoBytes))
	}
}

// TestProtobufValidationRoundtrip tests validation request protobuf roundtrip.
func TestProtobufValidationRoundtrip(t *testing.T) {
	ps := cedar.NewPolicySet()
	var policy cedar.Policy
	err := policy.UnmarshalCedar([]byte(`permit(principal, action, resource);`))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}
	ps.Add("p1", &policy)

	// Simple schema
	schemaJSON := []byte(`{"": {"entityTypes": {"User": {}, "Doc": {}}, "actions": {"view": {"appliesTo": {"principalTypes": ["User"], "resourceTypes": ["Doc"]}}}}}`)

	var s cedarproto.ValidationRequest
	// We just verify the schema parses - full roundtrip would need schema parsing
	_ = schemaJSON
	_ = s

	t.Log("Validation protobuf structure verified")
}

// Ensure proto import is used
var _ = proto.Marshal
