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

// Package corpus provides utilities for loading Cedar integration test data
// as corpus seeds for differential randomized testing.
//
// This package supports loading test data from multiple sources:
// - Cedar policy sandbox directories (tiny_sandboxes)
// - Raw .cedar policy files from the cedar repository
// - Cedar integration test suites
// - Synthesized test outputs from Rust DRT
package corpus

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// TestCase represents a single authorization test case in Go DRT format.
type TestCase struct {
	Policies []string        `json:"policies"`
	Entities json.RawMessage `json:"entities"`
	Request  json.RawMessage `json:"request"`
}

// CedarTestRequest represents the request format used in cedar-policy test files.
type CedarTestRequest struct {
	Principal string          `json:"principal"`
	Action    string          `json:"action"`
	Resource  string          `json:"resource"`
	Context   json.RawMessage `json:"context"`
}

// CedarTestCase represents a test case from cedar-policy test files.
type CedarTestCase struct {
	Request   CedarTestRequest `json:"request"`
	Entities  json.RawMessage  `json:"entities"`
	Decision  string           `json:"decision"`
	Reason    []string         `json:"reason"`
	NumErrors int              `json:"num_errors"`
}

// GoRequest is the cedar-go request format.
type GoRequest struct {
	Principal EntityRef       `json:"principal"`
	Action    EntityRef       `json:"action"`
	Resource  EntityRef       `json:"resource"`
	Context   json.RawMessage `json:"context"`
}

// EntityRef is the cedar-go entity reference format.
type EntityRef struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// LoadSandboxes loads test cases from cedar-policy sandbox directories.
// Returns test cases converted to Go DRT format.
func LoadSandboxes(sandboxDir string) ([]TestCase, error) {
	entries, err := os.ReadDir(sandboxDir)
	if err != nil {
		return nil, fmt.Errorf("reading sandbox dir: %w", err)
	}

	var cases []TestCase
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		subdir := filepath.Join(sandboxDir, entry.Name())
		loaded, err := loadSandbox(subdir)
		if err != nil {
			// Skip invalid sandboxes
			continue
		}
		cases = append(cases, loaded...)
	}
	return cases, nil
}

func loadSandbox(dir string) ([]TestCase, error) {
	// Read policy file
	policyPath := filepath.Join(dir, "policy.cedar")
	policyBytes, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, fmt.Errorf("reading policy: %w", err)
	}
	policyStr := string(policyBytes)

	// Try to find test files
	testFiles, _ := filepath.Glob(filepath.Join(dir, "tests-*.json"))
	if len(testFiles) == 0 {
		return nil, fmt.Errorf("no test files found")
	}

	var cases []TestCase
	for _, testFile := range testFiles {
		loaded, err := loadTestFile(testFile, policyStr)
		if err != nil {
			continue
		}
		cases = append(cases, loaded...)
	}
	return cases, nil
}

func loadTestFile(path string, policy string) ([]TestCase, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cedarTests []CedarTestCase
	if err := json.Unmarshal(data, &cedarTests); err != nil {
		return nil, err
	}

	var cases []TestCase
	for _, ct := range cedarTests {
		tc, err := convertCedarTest(ct, policy)
		if err != nil {
			continue
		}
		cases = append(cases, tc)
	}
	return cases, nil
}

// convertCedarTest converts a cedar-policy test case to Go DRT format.
func convertCedarTest(ct CedarTestCase, policy string) (TestCase, error) {
	// Parse entity references from Cedar string format
	principal, err := parseEntityRef(ct.Request.Principal)
	if err != nil {
		return TestCase{}, err
	}
	action, err := parseEntityRef(ct.Request.Action)
	if err != nil {
		return TestCase{}, err
	}
	resource, err := parseEntityRef(ct.Request.Resource)
	if err != nil {
		return TestCase{}, err
	}

	// Build Go request
	goReq := GoRequest{
		Principal: principal,
		Action:    action,
		Resource:  resource,
		Context:   ct.Request.Context,
	}
	if goReq.Context == nil {
		goReq.Context = json.RawMessage(`{}`)
	}

	reqBytes, err := json.Marshal(goReq)
	if err != nil {
		return TestCase{}, err
	}

	return TestCase{
		Policies: []string{policy},
		Entities: ct.Entities,
		Request:  reqBytes,
	}, nil
}

// parseEntityRef parses Cedar entity string format like `Type::"id"` to EntityRef.
func parseEntityRef(s string) (EntityRef, error) {
	// Format: Type::"id" or Namespace::Type::"id"
	typ, rest, found := strings.Cut(s, "::\"")
	if !found {
		return EntityRef{}, fmt.Errorf("invalid entity ref: %s", s)
	}

	// Extract id from rest (already has leading quote removed, need to strip trailing)
	if len(rest) < 1 || rest[len(rest)-1] != '"' {
		return EntityRef{}, fmt.Errorf("invalid entity ref: %s", s)
	}
	id := rest[:len(rest)-1]

	return EntityRef{Type: typ, ID: id}, nil
}

// WriteCorpus writes test cases to a Go fuzz corpus directory.
// The files are written in Go's native fuzz corpus format:
//
//	go test fuzz v1
//	[]byte("json data here")
func WriteCorpus(cases []TestCase, corpusDir string) error {
	if err := os.MkdirAll(corpusDir, 0750); err != nil { //nolint:gosec // corpus dir needs group read for CI
		return fmt.Errorf("creating corpus dir: %w", err)
	}

	for i, tc := range cases {
		data, err := json.Marshal(tc)
		if err != nil {
			continue
		}

		// Go fuzz corpus format requires header and Go-syntax value
		content := formatGoFuzzCorpus(data)

		// Go fuzz corpus files are named with content hash, but we'll use index
		filename := filepath.Join(corpusDir, fmt.Sprintf("seed_%04d", i))
		if err := os.WriteFile(filename, content, 0600); err != nil {
			return fmt.Errorf("writing corpus file: %w", err)
		}
	}
	return nil
}

// formatGoFuzzCorpus formats data as a Go fuzz corpus file.
// Format:
//
//	go test fuzz v1
//	[]byte("escaped json")
func formatGoFuzzCorpus(data []byte) []byte {
	var buf strings.Builder
	buf.WriteString("go test fuzz v1\n")
	buf.WriteString("[]byte(")
	buf.WriteString(fmt.Sprintf("%q", string(data)))
	buf.WriteString(")")
	return []byte(buf.String())
}

// LoadCedarFiles loads .cedar policy files from a directory tree.
// This mirrors the Rust DRT's initialize_corpus.sh behavior of copying
// all .cedar files from the cedar repository.
// Each policy file becomes a test case with empty entities and a default request.
func LoadCedarFiles(rootDir string) ([]TestCase, error) {
	var cases []TestCase

	err := filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // Skip inaccessible directories
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".cedar") {
			return nil
		}
		// Skip JSON-format cedar files
		if strings.HasSuffix(path, ".cedar.json") {
			return nil
		}

		policyBytes, err := os.ReadFile(path)
		if err != nil {
			return nil // Skip unreadable files
		}

		// Create a minimal test case with default request
		tc := TestCase{
			Policies: []string{string(policyBytes)},
			Entities: json.RawMessage(`[]`),
			Request: json.RawMessage(`{
				"principal": {"type": "User", "id": "default"},
				"action": {"type": "Action", "id": "access"},
				"resource": {"type": "Resource", "id": "default"},
				"context": {}
			}`),
		}
		cases = append(cases, tc)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("walking cedar files: %w", err)
	}
	return cases, nil
}

// LoadIntegrationTests loads test cases from cedar-integration-tests repository.
// The integration tests use a specific JSON format with policies, entities, and queries.
func LoadIntegrationTests(integrationTestDir string) ([]TestCase, error) {
	var cases []TestCase

	// Integration tests are organized in directories with JSON test files
	// Each JSON file contains: policies (path), entities (path), requests (array)
	entries, err := os.ReadDir(integrationTestDir)
	if err != nil {
		return nil, fmt.Errorf("reading integration test dir: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		testDir := filepath.Join(integrationTestDir, entry.Name())
		loaded, err := loadIntegrationTestDir(testDir)
		if err != nil {
			continue // Skip invalid test directories
		}
		cases = append(cases, loaded...)
	}
	return cases, nil
}

func loadIntegrationTestDir(dir string) ([]TestCase, error) {
	// cedar-integration-tests format: each .json file is a test case
	// JSON contains: policies (path), entities (path), requests (array)
	jsonFiles, _ := filepath.Glob(filepath.Join(dir, "*.json"))

	var cases []TestCase
	// Get the repo root (parent of "tests" directory)
	repoRoot := filepath.Dir(filepath.Dir(dir))

	for _, jsonFile := range jsonFiles {
		loaded, err := loadCedarIntegrationTest(jsonFile, repoRoot)
		if err != nil {
			continue
		}
		cases = append(cases, loaded...)
	}
	return cases, nil
}

// CedarIntegrationTest represents the cedar-integration-tests JSON format.
type CedarIntegrationTest struct {
	Policies       string                        `json:"policies"`
	Entities       string                        `json:"entities"`
	Schema         string                        `json:"schema"`
	ShouldValidate bool                          `json:"shouldValidate"`
	Requests       []CedarIntegrationTestRequest `json:"requests"`
}

// CedarIntegrationTestRequest is a request in cedar-integration-tests format.
type CedarIntegrationTestRequest struct {
	Description string          `json:"description"`
	Principal   EntityRef       `json:"principal"`
	Action      EntityRef       `json:"action"`
	Resource    EntityRef       `json:"resource"`
	Context     json.RawMessage `json:"context"`
	Decision    string          `json:"decision"`
	Reason      []string        `json:"reason"`
	Errors      []string        `json:"errors"`
}

func loadCedarIntegrationTest(jsonPath string, repoRoot string) ([]TestCase, error) {
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, err
	}

	var test CedarIntegrationTest
	if err := json.Unmarshal(data, &test); err != nil {
		return nil, err
	}

	// Load policies from referenced path
	policyPath := filepath.Join(repoRoot, test.Policies)
	policyBytes, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, fmt.Errorf("reading policies %s: %w", test.Policies, err)
	}

	// Load entities from referenced path
	entitiesPath := filepath.Join(repoRoot, test.Entities)
	entitiesBytes, err := os.ReadFile(entitiesPath)
	if err != nil {
		return nil, fmt.Errorf("reading entities %s: %w", test.Entities, err)
	}

	var cases []TestCase
	for _, req := range test.Requests {
		ctx := req.Context
		if len(ctx) == 0 {
			ctx = json.RawMessage(`{}`)
		}

		goReq := GoRequest{
			Principal: req.Principal,
			Action:    req.Action,
			Resource:  req.Resource,
			Context:   ctx,
		}
		reqBytes, err := json.Marshal(goReq)
		if err != nil {
			continue
		}

		cases = append(cases, TestCase{
			Policies: []string{string(policyBytes)},
			Entities: entitiesBytes,
			Request:  reqBytes,
		})
	}
	return cases, nil
}

// LoadSynthesizedTests loads test cases from Rust DRT synthesized test output.
// The synthesized tests are created by running the Rust fuzzer and then
// using synthesize_tests.sh to convert corpus entries to readable format.
//
// The Rust DRT dump format creates multiple files per test case:
// - {name}.json - test case metadata with file references
// - {name}.cedar - Cedar policies
// - {name}.entities.json - Entities
// - {name}.cedarschema - Schema (optional for our purposes)
func LoadSynthesizedTests(synthDir string) ([]TestCase, error) {
	var cases []TestCase

	entries, err := os.ReadDir(synthDir)
	if err != nil {
		return nil, fmt.Errorf("reading synthesized test dir: %w", err)
	}

	// Find all .json test case files (not .entities.json)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		// Skip entities files
		if strings.HasSuffix(name, ".entities.json") {
			continue
		}

		path := filepath.Join(synthDir, name)
		loaded, err := loadRustDRTTestCase(path, synthDir)
		if err != nil {
			continue
		}
		cases = append(cases, loaded...)
	}
	return cases, nil
}

// RustDRTTestCase represents the JSON test case format from Rust DRT dump.
type RustDRTTestCase struct {
	Schema         string           `json:"schema"`
	Policies       string           `json:"policies"`
	Entities       string           `json:"entities"`
	ShouldValidate bool             `json:"should_validate"`
	Requests       []RustDRTRequest `json:"requests"`
}

// RustDRTRequest represents a request in Rust DRT dump format.
type RustDRTRequest struct {
	Description     string          `json:"description"`
	Principal       json.RawMessage `json:"principal"`
	Action          json.RawMessage `json:"action"`
	Resource        json.RawMessage `json:"resource"`
	Context         json.RawMessage `json:"context"`
	ValidateRequest bool            `json:"validate_request"`
	Decision        string          `json:"decision"`
	Reason          []string        `json:"reason"`
	Errors          []string        `json:"errors"`
}

// loadRustDRTTestCase loads a Rust DRT test case and its referenced files.
func loadRustDRTTestCase(jsonPath string, baseDir string) ([]TestCase, error) {
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, err
	}

	var tc RustDRTTestCase
	if err := json.Unmarshal(data, &tc); err != nil {
		return nil, err
	}

	// Load policies from referenced file
	policiesPath := tc.Policies
	if !filepath.IsAbs(policiesPath) {
		policiesPath = filepath.Join(baseDir, filepath.Base(policiesPath))
	}
	policyBytes, err := os.ReadFile(policiesPath)
	if err != nil {
		// Try relative to JSON file
		policiesPath = filepath.Join(filepath.Dir(jsonPath), filepath.Base(tc.Policies))
		policyBytes, err = os.ReadFile(policiesPath)
		if err != nil {
			return nil, fmt.Errorf("reading policies %s: %w", tc.Policies, err)
		}
	}

	// Load entities from referenced file
	entitiesPath := tc.Entities
	if !filepath.IsAbs(entitiesPath) {
		entitiesPath = filepath.Join(baseDir, filepath.Base(entitiesPath))
	}
	entitiesBytes, err := os.ReadFile(entitiesPath)
	if err != nil {
		// Try relative to JSON file
		entitiesPath = filepath.Join(filepath.Dir(jsonPath), filepath.Base(tc.Entities))
		entitiesBytes, err = os.ReadFile(entitiesPath)
		if err != nil {
			return nil, fmt.Errorf("reading entities %s: %w", tc.Entities, err)
		}
	}

	// Create test cases for each request
	var cases []TestCase
	for _, req := range tc.Requests {
		goReq, err := convertRustDRTRequest(req)
		if err != nil {
			continue
		}

		reqBytes, err := json.Marshal(goReq)
		if err != nil {
			continue
		}

		cases = append(cases, TestCase{
			Policies: []string{string(policyBytes)},
			Entities: entitiesBytes,
			Request:  reqBytes,
		})
	}

	return cases, nil
}

// RustDRTEntityUID represents the entity UID format in Rust DRT dumps.
type RustDRTEntityUID struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// convertRustDRTRequest converts a Rust DRT request to Go DRT format.
func convertRustDRTRequest(req RustDRTRequest) (GoRequest, error) {
	var principal, action, resource RustDRTEntityUID

	if err := json.Unmarshal(req.Principal, &principal); err != nil {
		return GoRequest{}, fmt.Errorf("parsing principal: %w", err)
	}
	if err := json.Unmarshal(req.Action, &action); err != nil {
		return GoRequest{}, fmt.Errorf("parsing action: %w", err)
	}
	if err := json.Unmarshal(req.Resource, &resource); err != nil {
		return GoRequest{}, fmt.Errorf("parsing resource: %w", err)
	}

	ctx := req.Context
	if len(ctx) == 0 {
		ctx = json.RawMessage(`{}`)
	}

	return GoRequest{
		Principal: EntityRef(principal),
		Action:    EntityRef(action),
		Resource:  EntityRef(resource),
		Context:   ctx,
	}, nil
}

// LoadConfig specifies the paths to various test data sources.
type LoadConfig struct {
	// CedarRepo is the path to the main cedar-policy repository
	CedarRepo string
	// IntegrationTestRepo is the path to cedar-integration-tests repository
	IntegrationTestRepo string
	// SynthesizedTestDir is the path to Rust DRT synthesized test output
	SynthesizedTestDir string
	// Verbose enables verbose logging
	Verbose bool
}

// LoadAll loads test cases from all configured sources.
func LoadAll(cfg LoadConfig) ([]TestCase, error) {
	var allCases []TestCase

	allCases = append(allCases, loadFromCedarRepo(cfg)...)
	allCases = append(allCases, loadFromIntegrationTests(cfg)...)
	allCases = append(allCases, loadFromSynthesizedTests(cfg)...)

	return allCases, nil
}

// loadFromCedarRepo loads test cases from the cedar-policy repository.
func loadFromCedarRepo(cfg LoadConfig) []TestCase {
	if cfg.CedarRepo == "" {
		return nil
	}

	var cases []TestCase

	// Load from sandbox directories
	sandboxDir := filepath.Join(cfg.CedarRepo, "cedar-policy-cli", "sample-data", "tiny_sandboxes")
	if sandboxCases, err := LoadSandboxes(sandboxDir); err == nil {
		if cfg.Verbose {
			fmt.Printf("Loaded %d test cases from sandboxes\n", len(sandboxCases))
		}
		cases = append(cases, sandboxCases...)
	}

	// Load raw .cedar files
	if cedarCases, err := LoadCedarFiles(cfg.CedarRepo); err == nil {
		if cfg.Verbose {
			fmt.Printf("Loaded %d test cases from .cedar files\n", len(cedarCases))
		}
		cases = append(cases, cedarCases...)
	}

	return cases
}

// loadFromIntegrationTests loads test cases from the integration tests repository.
func loadFromIntegrationTests(cfg LoadConfig) []TestCase {
	if cfg.IntegrationTestRepo == "" {
		return nil
	}

	testsDir := filepath.Join(cfg.IntegrationTestRepo, "tests")
	cases, err := LoadIntegrationTests(testsDir)
	if err != nil {
		return nil
	}

	if cfg.Verbose {
		fmt.Printf("Loaded %d test cases from integration tests\n", len(cases))
	}
	return cases
}

// loadFromSynthesizedTests loads test cases from Rust DRT synthesized output.
func loadFromSynthesizedTests(cfg LoadConfig) []TestCase {
	if cfg.SynthesizedTestDir == "" {
		return nil
	}

	cases, err := LoadSynthesizedTests(cfg.SynthesizedTestDir)
	if err != nil {
		return nil
	}

	if cfg.Verbose {
		fmt.Printf("Loaded %d test cases from synthesized tests\n", len(cases))
	}
	return cases
}
