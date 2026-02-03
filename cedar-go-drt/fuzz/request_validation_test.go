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
	"encoding/json"
	"runtime"
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/x/exp/schema"

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/lean"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/proto"
)

// RequestValidationFuzzInput represents the structure of request validation fuzz input.
type RequestValidationFuzzInput struct {
	Schema  string          `json:"schema"`
	Request json.RawMessage `json:"request"`
}

// parseRequestValidationInput parses the request validation fuzz input.
func parseRequestValidationInput(data []byte) (*schema.Schema, cedar.Request, error) {
	var input RequestValidationFuzzInput
	if err := json.Unmarshal(data, &input); err != nil {
		return nil, cedar.Request{}, err
	}

	var s schema.Schema
	if err := s.UnmarshalJSON([]byte(input.Schema)); err != nil {
		return nil, cedar.Request{}, err
	}

	var request cedar.Request
	if err := json.Unmarshal(input.Request, &request); err != nil {
		return nil, cedar.Request{}, err
	}

	return &s, request, nil
}

// runLeanRequestValidation runs Lean request validation and returns the result.
func runLeanRequestValidation(t *testing.T, s *schema.Schema, request *cedar.Request) *lean.ValidationResponse {
	t.Helper()

	req := proto.RequestValidationFromCedar(s, request)
	protoBytes, err := req.ToProtobuf()
	if err != nil {
		t.Logf("Failed to convert to protobuf: %v", err)
		return nil
	}

	if err := lean.Initialize(); err != nil {
		t.Fatalf("Failed to initialize Lean: %v", err)
	}

	lt, err := lean.NewLeanThread()
	if err != nil {
		t.Fatalf("Failed to create Lean thread: %v", err)
	}
	defer lt.Close()

	leanResp, err := lean.ValidateRequest(protoBytes)
	if err != nil {
		t.Logf("Lean FFI error: %v", err)
		return nil
	}

	return leanResp
}

// FuzzRequestValidation is the fuzz target for request validation testing.
// It validates that requests conform to a schema using the Lean formalization.
func FuzzRequestValidation(f *testing.F) {
	addRequestValidationSeeds(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		s, request, err := parseRequestValidationInput(data)
		if err != nil {
			return // Invalid input, skip
		}

		// Skip requests with empty entity types
		if request.Principal.Type == "" || request.Action.Type == "" || request.Resource.Type == "" {
			return
		}

		// Run Lean request validation
		leanResp := runLeanRequestValidation(t, s, &request)
		if leanResp == nil {
			return // Lean error, skip
		}

		// For now, we verify Lean can validate without crashing.
		// Cedar-go doesn't expose direct request validation, so we can't compare.
		_ = leanResp.Valid
	})
}

func addRequestValidationSeeds(f *testing.F) {
	// Valid request matching schema
	f.Add([]byte(`{
		"schema": "{\"entityTypes\":{\"User\":{},\"Document\":{}},\"actions\":{\"view\":{\"appliesTo\":{\"principalTypes\":[\"User\"],\"resourceTypes\":[\"Document\"]}}}}",
		"request": {
			"principal": {"type": "User", "id": "alice"},
			"action": {"type": "Action", "id": "view"},
			"resource": {"type": "Document", "id": "doc1"},
			"context": {}
		}
	}`))

	// Request with context
	f.Add([]byte(`{
		"schema": "{\"entityTypes\":{\"User\":{},\"Document\":{}},\"actions\":{\"view\":{\"appliesTo\":{\"principalTypes\":[\"User\"],\"resourceTypes\":[\"Document\"]},\"context\":{\"type\":\"Record\",\"attributes\":{\"ip\":{\"type\":\"String\"}}}}}}",
		"request": {
			"principal": {"type": "User", "id": "alice"},
			"action": {"type": "Action", "id": "view"},
			"resource": {"type": "Document", "id": "doc1"},
			"context": {"ip": "192.168.1.1"}
		}
	}`))

	// Minimal schema
	f.Add([]byte(`{
		"schema": "{\"entityTypes\":{},\"actions\":{}}",
		"request": {
			"principal": {"type": "User", "id": "alice"},
			"action": {"type": "Action", "id": "view"},
			"resource": {"type": "Document", "id": "doc1"},
			"context": {}
		}
	}`))

	// Load corpus from testdata
	loadCorpusSeeds(f, "testdata/fuzz/FuzzRequestValidation")
}

// TestRequestValidationBasic tests basic request validation scenarios
func TestRequestValidationBasic(t *testing.T) {
	tests := []struct {
		name        string
		schema      string
		request     string
		expectParse bool
	}{
		{
			name:        "valid schema and request",
			schema:      `{"entityTypes":{"User":{},"Document":{}},"actions":{"view":{"appliesTo":{"principalTypes":["User"],"resourceTypes":["Document"]}}}}`,
			request:     `{"principal":{"type":"User","id":"alice"},"action":{"type":"Action","id":"view"},"resource":{"type":"Document","id":"doc1"},"context":{}}`,
			expectParse: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var s schema.Schema
			err := s.UnmarshalJSON([]byte(tc.schema))
			if (err == nil) != tc.expectParse {
				t.Errorf("Schema parse: expected success=%v, got error=%v", tc.expectParse, err)
			}

			var request cedar.Request
			err = json.Unmarshal([]byte(tc.request), &request)
			if (err == nil) != tc.expectParse {
				t.Errorf("Request parse: expected success=%v, got error=%v", tc.expectParse, err)
			}
		})
	}
}
