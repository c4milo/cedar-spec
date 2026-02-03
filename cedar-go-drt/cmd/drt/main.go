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

// Package main provides a CLI tool for manually testing cedar-go vs Lean
// authorization and validation.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/schema"

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/comparison"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/lean"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/proto"
)

func main() {
	// Parse command line flags
	policyFile := flag.String("policy", "", "Path to Cedar policy file")
	policyStr := flag.String("policy-str", "", "Cedar policy string (alternative to -policy)")
	entitiesFile := flag.String("entities", "", "Path to entities JSON file")
	requestFile := flag.String("request", "", "Path to request JSON file")
	schemaFile := flag.String("schema", "", "Path to Cedar schema file (for validation mode)")
	validate := flag.Bool("validate", false, "Run validation instead of authorization")
	verbose := flag.Bool("verbose", false, "Enable verbose output")
	flag.Parse()

	_ = verbose // Suppress unused warning

	if *policyFile == "" && *policyStr == "" {
		fmt.Fprintln(os.Stderr, "Error: must provide -policy or -policy-str")
		flag.Usage()
		os.Exit(1)
	}

	// Lock to OS thread for Lean FFI
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Initialize Lean
	if err := lean.Initialize(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize Lean: %v\n", err)
		os.Exit(1)
	}

	lt, err := lean.NewLeanThread()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create Lean thread: %v\n", err)
		os.Exit(1)
	}
	defer lt.Close()

	// Load policy
	policies, err := loadPolicies(*policyFile, *policyStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load policy: %v\n", err)
		os.Exit(1)
	}

	if *validate {
		runValidation(policies, *schemaFile)
	} else {
		runAuthorization(policies, *entitiesFile, *requestFile)
	}
}

// loadPolicies loads policies from either a file or a string.
func loadPolicies(policyFile, policyStr string) (*cedar.PolicySet, error) {
	var policyBytes []byte
	if policyFile != "" {
		var err error
		policyBytes, err = os.ReadFile(policyFile)
		if err != nil {
			return nil, fmt.Errorf("read policy file: %w", err)
		}
	} else {
		policyBytes = []byte(policyStr)
	}

	policies := cedar.NewPolicySet()
	var policy cedar.Policy
	if err := policy.UnmarshalCedar(policyBytes); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	policies.Add("policy0", &policy)
	return policies, nil
}

// loadEntities loads entities from a JSON file, or returns an empty map.
func loadEntities(entitiesFile string) (types.EntityMap, error) {
	if entitiesFile == "" {
		return types.EntityMap{}, nil
	}

	entitiesData, err := os.ReadFile(entitiesFile)
	if err != nil {
		return nil, fmt.Errorf("read entities file: %w", err)
	}

	var entities types.EntityMap
	if err := json.Unmarshal(entitiesData, &entities); err != nil {
		return nil, fmt.Errorf("parse entities: %w", err)
	}
	return entities, nil
}

// loadRequest loads a request from a JSON file, or returns a default request.
func loadRequest(requestFile string) (cedar.Request, error) {
	if requestFile == "" {
		return cedar.Request{
			Principal: types.NewEntityUID("User", "test"),
			Action:    types.NewEntityUID("Action", "test"),
			Resource:  types.NewEntityUID("Resource", "test"),
		}, nil
	}

	requestData, err := os.ReadFile(requestFile)
	if err != nil {
		return cedar.Request{}, fmt.Errorf("read request file: %w", err)
	}

	var request cedar.Request
	if err := json.Unmarshal(requestData, &request); err != nil {
		return cedar.Request{}, fmt.Errorf("parse request: %w", err)
	}
	return request, nil
}

func runAuthorization(policies *cedar.PolicySet, entitiesFile, requestFile string) {
	entities, err := loadEntities(entitiesFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load entities: %v\n", err)
		os.Exit(1)
	}

	request, err := loadRequest(requestFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load request: %v\n", err)
		os.Exit(1)
	}

	goDecision, goDiag := cedar.Authorize(policies, entities, request)
	printGoResults(goDecision, goDiag)

	leanResp, err := runLeanAuthorization(policies, entities, request)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Lean FFI error: %v\n", err)
		os.Exit(1)
	}
	printLeanResults(leanResp)

	compareAndReport(goDecision, goDiag, leanResp)
}

func printGoResults(decision cedar.Decision, diag types.Diagnostic) {
	fmt.Println("=== cedar-go Results ===")
	fmt.Printf("Decision: %s\n", decisionToString(decision))
	fmt.Printf("Determining Policies: %v\n", extractReasonPolicyIDs(diag.Reasons))
	fmt.Printf("Erroring Policies: %v\n", extractErrorPolicyIDs(diag.Errors))
}

func runLeanAuthorization(policies *cedar.PolicySet, entities types.EntityMap, request cedar.Request) (*lean.AuthorizationResponse, error) {
	authReq := proto.PolicySetFromCedar(policies, entities, &request)
	protoBytes, err := authReq.ToProtobuf()
	if err != nil {
		return nil, fmt.Errorf("convert to protobuf: %w", err)
	}

	return lean.IsAuthorized(protoBytes)
}

func printLeanResults(resp *lean.AuthorizationResponse) {
	fmt.Println("\n=== Lean Results ===")
	fmt.Printf("Decision: %s\n", resp.Decision)
	fmt.Printf("Determining Policies: %v\n", resp.DeterminingPolicies)
	fmt.Printf("Erroring Policies: %v\n", resp.ErroringPolicies)
}

func compareAndReport(goDecision cedar.Decision, goDiag types.Diagnostic, leanResp *lean.AuthorizationResponse) {
	goResult := &comparison.AuthorizationResult{
		Decision:            decisionToString(goDecision),
		DeterminingPolicies: extractReasonPolicyIDs(goDiag.Reasons),
		ErroringPolicies:    extractErrorPolicyIDs(goDiag.Errors),
	}

	leanResult := &comparison.AuthorizationResult{
		Decision:            leanResp.Decision,
		DeterminingPolicies: leanResp.DeterminingPolicies,
		ErroringPolicies:    leanResp.ErroringPolicies,
	}

	config := comparison.DefaultConfig()
	diffs := comparison.CompareAuthorization(goResult, leanResult, config)

	fmt.Println("\n=== Comparison ===")
	if len(diffs) == 0 {
		fmt.Println("Results match!")
	} else {
		fmt.Println(comparison.FormatDifferences(diffs))
		os.Exit(1)
	}
}

func runValidation(policies *cedar.PolicySet, schemaFile string) {
	if schemaFile == "" {
		fmt.Fprintln(os.Stderr, "Error: -schema required for validation mode")
		os.Exit(1)
	}

	s, err := loadSchema(schemaFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load schema: %v\n", err)
		os.Exit(1)
	}

	// Note: cedar-go doesn't expose policy validation yet
	fmt.Println("=== cedar-go Validation Results ===")
	fmt.Println("Note: cedar-go doesn't expose validation API yet")
	fmt.Println("Schema and policies parsed successfully")
	goValid := true

	// Convert to protobuf for Lean
	valReq := proto.ValidationFromCedar(policies, s)
	protoBytes, err := valReq.ToProtobuf()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to convert to protobuf: %v\n", err)
		os.Exit(1)
	}

	// Run Lean validation
	leanResp, err := lean.Validate(protoBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Lean FFI error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n=== Lean Validation Results ===")
	fmt.Printf("Valid: %v\n", leanResp.Valid)
	if !leanResp.Valid {
		fmt.Printf("Errors: %s\n", leanResp.Errors)
	}

	// Compare results
	goResult := &comparison.ValidationResult{
		Valid:  goValid,
		Errors: nil,
	}

	leanResult := &comparison.ValidationResult{
		Valid:  leanResp.Valid,
		Errors: []string{leanResp.Errors},
	}

	config := comparison.DefaultConfig()
	diffs := comparison.CompareValidation(goResult, leanResult, config)

	fmt.Println("\n=== Comparison ===")
	if len(diffs) == 0 {
		fmt.Println("Results match!")
	} else {
		fmt.Println(comparison.FormatValidationDifferences(diffs))
		os.Exit(1)
	}
}

func loadSchema(schemaFile string) (*schema.Schema, error) {
	schemaData, err := os.ReadFile(schemaFile)
	if err != nil {
		return nil, fmt.Errorf("read schema file: %w", err)
	}

	var s schema.Schema
	if err := s.UnmarshalJSON(schemaData); err != nil {
		// Try Cedar format
		if err := s.UnmarshalCedar(schemaData); err != nil {
			return nil, fmt.Errorf("parse schema: %w", err)
		}
	}
	return &s, nil
}

func decisionToString(d cedar.Decision) string {
	if d {
		return "allow"
	}
	return "deny"
}

func extractReasonPolicyIDs(reasons []types.DiagnosticReason) []string {
	ids := make([]string, 0, len(reasons))
	for _, r := range reasons {
		ids = append(ids, string(r.PolicyID))
	}
	return ids
}

func extractErrorPolicyIDs(errors []types.DiagnosticError) []string {
	ids := make([]string, 0, len(errors))
	for _, e := range errors {
		ids = append(ids, string(e.PolicyID))
	}
	return ids
}
