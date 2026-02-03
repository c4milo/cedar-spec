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

package corpus

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestParseEntityRef(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    EntityRef
		wantErr bool
	}{
		{
			name:  "simple entity",
			input: `User::"alice"`,
			want:  EntityRef{Type: "User", ID: "alice"},
		},
		{
			name:  "namespaced entity",
			input: `MyApp::User::"alice"`,
			want:  EntityRef{Type: "MyApp::User", ID: "alice"},
		},
		{
			name:  "action entity",
			input: `Action::"view"`,
			want:  EntityRef{Type: "Action", ID: "view"},
		},
		{
			name:  "empty id",
			input: `User::""`,
			want:  EntityRef{Type: "User", ID: ""},
		},
		{
			name:  "id with spaces",
			input: `User::"alice smith"`,
			want:  EntityRef{Type: "User", ID: "alice smith"},
		},
		{
			name:    "missing quotes",
			input:   `User::alice`,
			wantErr: true,
		},
		{
			name:    "missing closing quote",
			input:   `User::"alice`,
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   ``,
			wantErr: true,
		},
		{
			name:    "no separator",
			input:   `User"alice"`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseEntityRef(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseEntityRef(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("parseEntityRef(%q) unexpected error: %v", tt.input, err)
				return
			}
			if got != tt.want {
				t.Errorf("parseEntityRef(%q) = %+v, want %+v", tt.input, got, tt.want)
			}
		})
	}
}

func TestFormatGoFuzzCorpus(t *testing.T) {
	data := []byte(`{"key": "value"}`)
	result := formatGoFuzzCorpus(data)

	// Should start with header
	if len(result) < 20 {
		t.Fatal("result too short")
	}

	resultStr := string(result)
	if resultStr[:18] != "go test fuzz v1\n[]" {
		t.Errorf("unexpected header: %q", resultStr[:18])
	}

	// Should contain the data
	if !contains(resultStr, "key") || !contains(resultStr, "value") {
		t.Errorf("result should contain data: %s", resultStr)
	}
}

func TestTestCaseMarshalUnmarshal(t *testing.T) {
	tc := TestCase{
		Policies: []string{`permit(principal, action, resource);`},
		Entities: json.RawMessage(`[{"uid": {"type": "User", "id": "alice"}}]`),
		Request:  json.RawMessage(`{"principal": {"type": "User", "id": "alice"}}`),
	}

	data, err := json.Marshal(tc)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var decoded TestCase
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if len(decoded.Policies) != 1 {
		t.Errorf("expected 1 policy, got %d", len(decoded.Policies))
	}
	if decoded.Policies[0] != tc.Policies[0] {
		t.Errorf("policy mismatch: got %q, want %q", decoded.Policies[0], tc.Policies[0])
	}
}

func TestWriteCorpus(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()
	corpusDir := filepath.Join(tmpDir, "corpus")

	cases := []TestCase{
		{
			Policies: []string{`permit(principal, action, resource);`},
			Entities: json.RawMessage(`[]`),
			Request:  json.RawMessage(`{"principal": {"type": "User", "id": "alice"}}`),
		},
		{
			Policies: []string{`forbid(principal, action, resource);`},
			Entities: json.RawMessage(`[]`),
			Request:  json.RawMessage(`{"principal": {"type": "User", "id": "bob"}}`),
		},
	}

	err := WriteCorpus(cases, corpusDir)
	if err != nil {
		t.Fatalf("WriteCorpus error: %v", err)
	}

	// Verify files were created
	files, err := os.ReadDir(corpusDir)
	if err != nil {
		t.Fatalf("ReadDir error: %v", err)
	}

	if len(files) != 2 {
		t.Errorf("expected 2 files, got %d", len(files))
	}

	// Verify file content format
	content, err := os.ReadFile(filepath.Join(corpusDir, "seed_0000"))
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}

	contentStr := string(content)
	if !contains(contentStr, "go test fuzz v1") {
		t.Errorf("file should have fuzz header: %s", contentStr)
	}
	if !contains(contentStr, "permit") {
		t.Errorf("file should contain policy: %s", contentStr)
	}
}

func TestGoRequestMarshal(t *testing.T) {
	req := GoRequest{
		Principal: EntityRef{Type: "User", ID: "alice"},
		Action:    EntityRef{Type: "Action", ID: "view"},
		Resource:  EntityRef{Type: "Document", ID: "doc1"},
		Context:   json.RawMessage(`{"key": "value"}`),
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var decoded GoRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if decoded.Principal != req.Principal {
		t.Errorf("Principal mismatch: got %+v, want %+v", decoded.Principal, req.Principal)
	}
	if decoded.Action != req.Action {
		t.Errorf("Action mismatch: got %+v, want %+v", decoded.Action, req.Action)
	}
	if decoded.Resource != req.Resource {
		t.Errorf("Resource mismatch: got %+v, want %+v", decoded.Resource, req.Resource)
	}
}

func TestConvertCedarTest(t *testing.T) {
	cedarTest := CedarTestCase{
		Request: CedarTestRequest{
			Principal: `User::"alice"`,
			Action:    `Action::"view"`,
			Resource:  `Document::"doc1"`,
			Context:   json.RawMessage(`{}`),
		},
		Entities: json.RawMessage(`[]`),
		Decision: "Allow",
	}

	policy := `permit(principal, action, resource);`

	tc, err := convertCedarTest(cedarTest, policy)
	if err != nil {
		t.Fatalf("convertCedarTest error: %v", err)
	}

	if len(tc.Policies) != 1 || tc.Policies[0] != policy {
		t.Errorf("policy mismatch: got %v", tc.Policies)
	}

	// Verify request was converted
	var req GoRequest
	if err := json.Unmarshal(tc.Request, &req); err != nil {
		t.Fatalf("unmarshal request error: %v", err)
	}

	if req.Principal.Type != "User" || req.Principal.ID != "alice" {
		t.Errorf("principal mismatch: got %+v", req.Principal)
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
