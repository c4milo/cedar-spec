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
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ValidationTestCase represents a validation test case with schema and policies.
type ValidationTestCase struct {
	Schema   string   `json:"schema"`
	Policies []string `json:"policies"`
}

// LoadValidationTestsFromIntegration loads validation test cases from cedar-integration-tests.
// Each test directory that has shouldValidate: true is included.
func LoadValidationTestsFromIntegration(integrationTestDir string) ([]ValidationTestCase, error) {
	var cases []ValidationTestCase

	testsDir := filepath.Join(integrationTestDir, "tests")
	entries, err := os.ReadDir(testsDir)
	if err != nil {
		return nil, fmt.Errorf("reading tests dir: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		testDir := filepath.Join(testsDir, entry.Name())
		loaded, err := loadValidationFromIntegrationDir(testDir, integrationTestDir)
		if err != nil {
			continue
		}
		cases = append(cases, loaded...)
	}
	return cases, nil
}

func loadValidationFromIntegrationDir(dir string, repoRoot string) ([]ValidationTestCase, error) {
	jsonFiles, _ := filepath.Glob(filepath.Join(dir, "*.json"))

	var cases []ValidationTestCase
	for _, jsonFile := range jsonFiles {
		data, err := os.ReadFile(jsonFile)
		if err != nil {
			continue
		}

		var test CedarIntegrationTest
		if err := json.Unmarshal(data, &test); err != nil {
			continue
		}

		// Skip tests without schema
		if test.Schema == "" {
			continue
		}

		// Load schema
		schemaPath := filepath.Join(repoRoot, test.Schema)
		schemaBytes, err := os.ReadFile(schemaPath)
		if err != nil {
			continue
		}

		// Load policies
		policyPath := filepath.Join(repoRoot, test.Policies)
		policyBytes, err := os.ReadFile(policyPath)
		if err != nil {
			continue
		}

		cases = append(cases, ValidationTestCase{
			Schema:   string(schemaBytes),
			Policies: []string{string(policyBytes)},
		})
	}
	return cases, nil
}

// LoadValidationTestsFromCedar loads validation test cases from the cedar-policy repo.
// It pairs .cedarschema files with .cedar files in the same directory.
func LoadValidationTestsFromCedar(cedarRepo string) ([]ValidationTestCase, error) {
	var cases []ValidationTestCase

	err := filepath.WalkDir(cedarRepo, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}

		tc, ok := loadValidationFromSchemaFile(path)
		if ok {
			cases = append(cases, tc)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}
	return cases, nil
}

func loadValidationFromSchemaFile(path string) (ValidationTestCase, bool) {
	if !isSchemaFile(path) {
		return ValidationTestCase{}, false
	}

	schemaBytes, err := os.ReadFile(path)
	if err != nil {
		return ValidationTestCase{}, false
	}

	policies := loadPoliciesFromDir(filepath.Dir(path))
	if len(policies) == 0 {
		return ValidationTestCase{}, false
	}

	return ValidationTestCase{
		Schema:   string(schemaBytes),
		Policies: policies,
	}, true
}

func isSchemaFile(path string) bool {
	return strings.HasSuffix(path, ".cedarschema") || strings.HasSuffix(path, ".cedarschema.json")
}

func loadPoliciesFromDir(dir string) []string {
	policyFiles, _ := filepath.Glob(filepath.Join(dir, "*.cedar"))

	var policies []string
	for _, pf := range policyFiles {
		if strings.HasSuffix(pf, ".cedar.json") {
			continue
		}
		policyBytes, err := os.ReadFile(pf)
		if err != nil {
			continue
		}
		policies = append(policies, string(policyBytes))
	}
	return policies
}

// LoadValidationTestsFromSynthesized loads validation test cases from Rust DRT synthesized output.
func LoadValidationTestsFromSynthesized(synthDir string) ([]ValidationTestCase, error) {
	var cases []ValidationTestCase

	entries, err := os.ReadDir(synthDir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		tc, ok := loadValidationFromSynthEntry(synthDir, entry)
		if ok {
			cases = append(cases, tc)
		}
	}
	return cases, nil
}

func loadValidationFromSynthEntry(synthDir string, entry os.DirEntry) (ValidationTestCase, bool) {
	if entry.IsDir() {
		return ValidationTestCase{}, false
	}

	name := entry.Name()
	if !strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".entities.json") {
		return ValidationTestCase{}, false
	}

	jsonPath := filepath.Join(synthDir, name)
	tc, ok := parseRustDRTTestCase(jsonPath)
	if !ok || tc.Schema == "" {
		return ValidationTestCase{}, false
	}

	schemaBytes, ok := loadSynthFile(synthDir, jsonPath, tc.Schema)
	if !ok {
		return ValidationTestCase{}, false
	}

	policyBytes, ok := loadSynthFile(synthDir, jsonPath, tc.Policies)
	if !ok {
		return ValidationTestCase{}, false
	}

	return ValidationTestCase{
		Schema:   string(schemaBytes),
		Policies: []string{string(policyBytes)},
	}, true
}

func parseRustDRTTestCase(jsonPath string) (RustDRTTestCase, bool) {
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return RustDRTTestCase{}, false
	}

	var tc RustDRTTestCase
	if err := json.Unmarshal(data, &tc); err != nil {
		return RustDRTTestCase{}, false
	}

	return tc, true
}

func loadSynthFile(synthDir, jsonPath, filename string) ([]byte, bool) {
	path := filepath.Join(synthDir, filepath.Base(filename))
	data, err := os.ReadFile(path)
	if err != nil {
		path = filepath.Join(filepath.Dir(jsonPath), filepath.Base(filename))
		data, err = os.ReadFile(path)
		if err != nil {
			return nil, false
		}
	}
	return data, true
}

// LoadAllValidationTests loads validation test cases from all configured sources.
func LoadAllValidationTests(cfg LoadConfig) ([]ValidationTestCase, error) {
	var allCases []ValidationTestCase

	if cfg.CedarRepo != "" {
		cases, _ := LoadValidationTestsFromCedar(cfg.CedarRepo)
		if cfg.Verbose && len(cases) > 0 {
			fmt.Printf("Loaded %d validation test cases from cedar repo\n", len(cases))
		}
		allCases = append(allCases, cases...)
	}

	if cfg.IntegrationTestRepo != "" {
		cases, _ := LoadValidationTestsFromIntegration(cfg.IntegrationTestRepo)
		if cfg.Verbose && len(cases) > 0 {
			fmt.Printf("Loaded %d validation test cases from integration tests\n", len(cases))
		}
		allCases = append(allCases, cases...)
	}

	if cfg.SynthesizedTestDir != "" {
		cases, _ := LoadValidationTestsFromSynthesized(cfg.SynthesizedTestDir)
		if cfg.Verbose && len(cases) > 0 {
			fmt.Printf("Loaded %d validation test cases from synthesized tests\n", len(cases))
		}
		allCases = append(allCases, cases...)
	}

	return allCases, nil
}

// WriteValidationCorpus writes validation test cases to a Go fuzz corpus directory.
func WriteValidationCorpus(cases []ValidationTestCase, corpusDir string) error {
	if err := os.MkdirAll(corpusDir, 0750); err != nil {
		return fmt.Errorf("creating corpus dir: %w", err)
	}

	for i, tc := range cases {
		data, err := json.Marshal(tc)
		if err != nil {
			continue
		}

		content := formatGoFuzzCorpus(data)
		filename := filepath.Join(corpusDir, fmt.Sprintf("val_seed_%04d", i))
		if err := os.WriteFile(filename, content, 0600); err != nil {
			return fmt.Errorf("writing corpus file: %w", err)
		}
	}
	return nil
}
