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

package lean

/*
#include <lean/lean.h>

// Schema loading
extern lean_object* loadProtobufSchema(lean_object* schemaBytes);

// SymCC - Single Policy Checks
extern lean_object* runCheckNeverErrors(lean_object* schema, lean_object* req);
extern lean_object* runCheckAlwaysMatches(lean_object* schema, lean_object* req);
extern lean_object* runCheckNeverMatches(lean_object* schema, lean_object* req);

// SymCC - Two Policy Comparison
extern lean_object* runCheckMatchesEquivalent(lean_object* schema, lean_object* req);
extern lean_object* runCheckMatchesImplies(lean_object* schema, lean_object* req);
extern lean_object* runCheckMatchesDisjoint(lean_object* schema, lean_object* req);

// SymCC - Single PolicySet Checks
extern lean_object* runCheckAlwaysAllows(lean_object* schema, lean_object* req);
extern lean_object* runCheckAlwaysDenies(lean_object* schema, lean_object* req);

// SymCC - Two PolicySet Comparison
extern lean_object* runCheckEquivalent(lean_object* schema, lean_object* req);
extern lean_object* runCheckImplies(lean_object* schema, lean_object* req);
extern lean_object* runCheckDisjoint(lean_object* schema, lean_object* req);

// SymCC - Asserts
extern lean_object* runCheckAsserts(lean_object* schema, lean_object* req);

// SymCC - WithCex variants (returns counterexample on failure)
extern lean_object* runCheckNeverErrorsWithCex(lean_object* schema, lean_object* req);
extern lean_object* runCheckAlwaysMatchesWithCex(lean_object* schema, lean_object* req);
extern lean_object* runCheckNeverMatchesWithCex(lean_object* schema, lean_object* req);
extern lean_object* runCheckMatchesEquivalentWithCex(lean_object* schema, lean_object* req);
extern lean_object* runCheckMatchesImpliesWithCex(lean_object* schema, lean_object* req);
extern lean_object* runCheckMatchesDisjointWithCex(lean_object* schema, lean_object* req);
extern lean_object* runCheckAlwaysAllowsWithCex(lean_object* schema, lean_object* req);
extern lean_object* runCheckAlwaysDeniesWithCex(lean_object* schema, lean_object* req);
extern lean_object* runCheckEquivalentWithCex(lean_object* schema, lean_object* req);
extern lean_object* runCheckImpliesWithCex(lean_object* schema, lean_object* req);
extern lean_object* runCheckDisjointWithCex(lean_object* schema, lean_object* req);

*/
import "C"

import (
	"encoding/json"
	"errors"
	"fmt"
)

// SymCCResponse represents the result of a SymCC check performed by the Lean formalization.
// The SymCC (Symbolic Cedar Compiler) compiles Cedar policies to SMT formulas and uses
// the cvc5 solver to verify properties like always-allows, never-errors, etc.
type SymCCResponse struct {
	// Result is the verification outcome: true if the property holds, false if it doesn't.
	Result bool `json:"result"`

	// Duration is the verification time in nanoseconds.
	Duration uint64 `json:"duration,omitempty"`
}

// SymCCWithCexResponse represents a SymCC check result that may include a counterexample.
type SymCCWithCexResponse struct {
	// Result is nil if the property holds (no counterexample exists),
	// or contains a counterexample environment if the property doesn't hold.
	Result *SymCCCounterexample `json:"result"`

	// Duration is the verification time in nanoseconds.
	Duration uint64 `json:"duration,omitempty"`
}

// SymCCCounterexample represents a counterexample environment found by the solver.
type SymCCCounterexample struct {
	// Request is the request that violates the property.
	Request json.RawMessage `json:"request,omitempty"`

	// Entities are the entities in the counterexample.
	Entities json.RawMessage `json:"entities,omitempty"`
}

// LeanSchema represents a loaded Lean schema object.
// This is an opaque handle to a Lean-managed Schema object.
type LeanSchema struct {
	obj *LeanObject
}

// LoadSchema loads a protobuf-encoded schema into Lean and returns a handle.
// The schema can then be used with multiple SymCC operations.
//
// The schemaBytes parameter must be a protobuf-encoded Schema message.
// The function must be called from within a Lean thread context.
func LoadSchema(schemaBytes []byte) (*LeanSchema, error) {
	inputPtr := prepareInput(schemaBytes)
	result := C.loadProtobufSchema(inputPtr)
	if result == nil {
		return nil, errors.New("loadProtobufSchema returned nil")
	}

	// The result is Except String Schema
	// Use AsResult to handle the Except type
	obj := newLeanObjectOwned(result)

	// AsResult handles both Ok and Error cases
	okVal, errVal, parseErr := obj.AsResult()
	if parseErr != nil {
		return nil, fmt.Errorf("failed to parse schema result: %w", parseErr)
	}

	if errVal != nil {
		// It's an error - extract the error message
		errStr, _ := errVal.AsString()
		return nil, fmt.Errorf("schema loading failed: %s", errStr)
	}

	if okVal == nil {
		return nil, errors.New("schema loading returned nil")
	}

	return &LeanSchema{obj: okVal}, nil
}

// Release releases the Lean schema object.
func (s *LeanSchema) Release() {
	if s.obj != nil {
		s.obj.release()
		s.obj = nil
	}
}

// parseSymCCResult parses a SymCC JSON result into a boolean response.
func parseSymCCResult(jsonStr string) (*SymCCResponse, error) {
	// Parse the outer result structure
	// Lean returns: {"ok": {"duration": N, "data": bool}} or {"error": "msg"}
	var outerResult struct {
		Ok *struct {
			Data     bool   `json:"data"`
			Duration uint64 `json:"duration"`
		} `json:"ok"`
		Error *string `json:"error"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &outerResult); err != nil {
		return nil, fmt.Errorf("failed to parse SymCC result: %w", err)
	}

	if outerResult.Error != nil {
		return nil, fmt.Errorf("SymCC error: %s", *outerResult.Error)
	}

	if outerResult.Ok == nil {
		return nil, errors.New("unexpected response format from SymCC")
	}

	return &SymCCResponse{
		Result:   outerResult.Ok.Data,
		Duration: outerResult.Ok.Duration,
	}, nil
}

// parseSymCCWithCexResult parses a SymCC JSON result with potential counterexample.
func parseSymCCWithCexResult(jsonStr string) (*SymCCWithCexResponse, error) {
	// Parse the outer result structure
	// Lean returns: {"ok": {"duration": N, "data": null | {...}}} or {"error": "msg"}
	var outerResult struct {
		Ok *struct {
			Data     json.RawMessage `json:"data"`
			Duration uint64          `json:"duration"`
		} `json:"ok"`
		Error *string `json:"error"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &outerResult); err != nil {
		return nil, fmt.Errorf("failed to parse SymCC result: %w", err)
	}

	if outerResult.Error != nil {
		return nil, fmt.Errorf("SymCC error: %s", *outerResult.Error)
	}

	if outerResult.Ok == nil {
		return nil, errors.New("unexpected response format from SymCC")
	}

	response := &SymCCWithCexResponse{
		Duration: outerResult.Ok.Duration,
	}

	// Check if data is null (property holds) or contains a counterexample
	if string(outerResult.Ok.Data) == "null" {
		response.Result = nil // Property holds
	} else {
		// Parse counterexample
		var cex SymCCCounterexample
		if err := json.Unmarshal(outerResult.Ok.Data, &cex); err != nil {
			return nil, fmt.Errorf("failed to parse counterexample: %w", err)
		}
		response.Result = &cex
	}

	return response, nil
}

// prepareSymCCCall prepares schema and request for a SymCC call.
// Returns the schema and request pointers, or an error.
func prepareSymCCCall(schema *LeanSchema, request []byte) (*C.lean_object, *C.lean_object, error) {
	if schema == nil || schema.obj == nil {
		return nil, nil, errors.New("schema is nil")
	}

	// Increment schema ref count since FFI function takes ownership
	schemaPtr := schema.obj.ptr
	C.lean_inc(schemaPtr)

	inputPtr := prepareInput(request)
	return schemaPtr, inputPtr, nil
}

// handleSymCCResult parses a SymCC result into a response.
func handleSymCCResult(result *C.lean_object) (*SymCCResponse, error) {
	obj, err := wrapResult(result)
	if err != nil {
		return nil, fmt.Errorf("SymCC FFI call failed: %w", err)
	}
	defer obj.release()

	jsonStr, err := parseResult(obj)
	if err != nil {
		return nil, err
	}

	return parseSymCCResult(jsonStr)
}

// handleSymCCWithCexResult parses a SymCC result with counterexample into a response.
func handleSymCCWithCexResult(result *C.lean_object) (*SymCCWithCexResponse, error) {
	obj, err := wrapResult(result)
	if err != nil {
		return nil, fmt.Errorf("SymCC FFI call failed: %w", err)
	}
	defer obj.release()

	jsonStr, err := parseResult(obj)
	if err != nil {
		return nil, err
	}

	return parseSymCCWithCexResult(jsonStr)
}

// =============================================================================
// Single Policy Checks
// =============================================================================

// CheckNeverErrors verifies that a policy never produces evaluation errors.
// Returns true if the policy is guaranteed to never error for any valid request.
func CheckNeverErrors(schema *LeanSchema, request []byte) (*SymCCResponse, error) {
	schemaPtr, inputPtr, err := prepareSymCCCall(schema, request)
	if err != nil {
		return nil, err
	}
	return handleSymCCResult(C.runCheckNeverErrors(schemaPtr, inputPtr))
}

// CheckNeverErrorsWithCex is like CheckNeverErrors but returns a counterexample on failure.
func CheckNeverErrorsWithCex(schema *LeanSchema, request []byte) (*SymCCWithCexResponse, error) {
	schemaPtr, inputPtr, err := prepareSymCCCall(schema, request)
	if err != nil {
		return nil, err
	}
	return handleSymCCWithCexResult(C.runCheckNeverErrorsWithCex(schemaPtr, inputPtr))
}

// CheckAlwaysMatches verifies that a policy's condition always evaluates to true.
// Returns true if the policy is guaranteed to match for any valid request.
func CheckAlwaysMatches(schema *LeanSchema, request []byte) (*SymCCResponse, error) {
	schemaPtr, inputPtr, err := prepareSymCCCall(schema, request)
	if err != nil {
		return nil, err
	}
	return handleSymCCResult(C.runCheckAlwaysMatches(schemaPtr, inputPtr))
}

// CheckAlwaysMatchesWithCex is like CheckAlwaysMatches but returns a counterexample on failure.
func CheckAlwaysMatchesWithCex(schema *LeanSchema, request []byte) (*SymCCWithCexResponse, error) {
	schemaPtr, inputPtr, err := prepareSymCCCall(schema, request)
	if err != nil {
		return nil, err
	}
	return handleSymCCWithCexResult(C.runCheckAlwaysMatchesWithCex(schemaPtr, inputPtr))
}

// CheckNeverMatches verifies that a policy's condition never evaluates to true.
// Returns true if the policy is guaranteed to never match for any valid request.
func CheckNeverMatches(schema *LeanSchema, request []byte) (*SymCCResponse, error) {
	schemaPtr, inputPtr, err := prepareSymCCCall(schema, request)
	if err != nil {
		return nil, err
	}
	return handleSymCCResult(C.runCheckNeverMatches(schemaPtr, inputPtr))
}

// CheckNeverMatchesWithCex is like CheckNeverMatches but returns a counterexample on failure.
func CheckNeverMatchesWithCex(schema *LeanSchema, request []byte) (*SymCCWithCexResponse, error) {
	schemaPtr, inputPtr, err := prepareSymCCCall(schema, request)
	if err != nil {
		return nil, err
	}
	return handleSymCCWithCexResult(C.runCheckNeverMatchesWithCex(schemaPtr, inputPtr))
}

// =============================================================================
// Two Policy Comparison
// =============================================================================

// CheckMatchesEquivalent verifies that two policies have equivalent conditions.
// Returns true if the policies match on exactly the same requests.
func CheckMatchesEquivalent(schema *LeanSchema, request []byte) (*SymCCResponse, error) {
	schemaPtr, inputPtr, err := prepareSymCCCall(schema, request)
	if err != nil {
		return nil, err
	}
	return handleSymCCResult(C.runCheckMatchesEquivalent(schemaPtr, inputPtr))
}

// CheckMatchesEquivalentWithCex is like CheckMatchesEquivalent but returns a counterexample on failure.
func CheckMatchesEquivalentWithCex(schema *LeanSchema, request []byte) (*SymCCWithCexResponse, error) {
	schemaPtr, inputPtr, err := prepareSymCCCall(schema, request)
	if err != nil {
		return nil, err
	}
	return handleSymCCWithCexResult(C.runCheckMatchesEquivalentWithCex(schemaPtr, inputPtr))
}

// CheckMatchesImplies verifies that one policy's condition implies another's.
// Returns true if policy1 matching implies policy2 also matches.
func CheckMatchesImplies(schema *LeanSchema, request []byte) (*SymCCResponse, error) {
	schemaPtr, inputPtr, err := prepareSymCCCall(schema, request)
	if err != nil {
		return nil, err
	}
	return handleSymCCResult(C.runCheckMatchesImplies(schemaPtr, inputPtr))
}

// CheckMatchesImpliesWithCex is like CheckMatchesImplies but returns a counterexample on failure.
func CheckMatchesImpliesWithCex(schema *LeanSchema, request []byte) (*SymCCWithCexResponse, error) {
	schemaPtr, inputPtr, err := prepareSymCCCall(schema, request)
	if err != nil {
		return nil, err
	}
	return handleSymCCWithCexResult(C.runCheckMatchesImpliesWithCex(schemaPtr, inputPtr))
}

// CheckMatchesDisjoint verifies that two policies' conditions are mutually exclusive.
// Returns true if no request can match both policies.
func CheckMatchesDisjoint(schema *LeanSchema, request []byte) (*SymCCResponse, error) {
	schemaPtr, inputPtr, err := prepareSymCCCall(schema, request)
	if err != nil {
		return nil, err
	}
	return handleSymCCResult(C.runCheckMatchesDisjoint(schemaPtr, inputPtr))
}

// CheckMatchesDisjointWithCex is like CheckMatchesDisjoint but returns a counterexample on failure.
func CheckMatchesDisjointWithCex(schema *LeanSchema, request []byte) (*SymCCWithCexResponse, error) {
	schemaPtr, inputPtr, err := prepareSymCCCall(schema, request)
	if err != nil {
		return nil, err
	}
	return handleSymCCWithCexResult(C.runCheckMatchesDisjointWithCex(schemaPtr, inputPtr))
}

// =============================================================================
// Single PolicySet Checks
// =============================================================================

// CheckAlwaysAllows verifies that a policy set always allows requests.
// Returns true if the policy set is guaranteed to allow any valid request.
func CheckAlwaysAllows(schema *LeanSchema, request []byte) (*SymCCResponse, error) {
	schemaPtr, inputPtr, err := prepareSymCCCall(schema, request)
	if err != nil {
		return nil, err
	}
	return handleSymCCResult(C.runCheckAlwaysAllows(schemaPtr, inputPtr))
}

// CheckAlwaysAllowsWithCex is like CheckAlwaysAllows but returns a counterexample on failure.
func CheckAlwaysAllowsWithCex(schema *LeanSchema, request []byte) (*SymCCWithCexResponse, error) {
	schemaPtr, inputPtr, err := prepareSymCCCall(schema, request)
	if err != nil {
		return nil, err
	}
	return handleSymCCWithCexResult(C.runCheckAlwaysAllowsWithCex(schemaPtr, inputPtr))
}

// CheckAlwaysDenies verifies that a policy set always denies requests.
// Returns true if the policy set is guaranteed to deny any valid request.
func CheckAlwaysDenies(schema *LeanSchema, request []byte) (*SymCCResponse, error) {
	schemaPtr, inputPtr, err := prepareSymCCCall(schema, request)
	if err != nil {
		return nil, err
	}
	return handleSymCCResult(C.runCheckAlwaysDenies(schemaPtr, inputPtr))
}

// CheckAlwaysDeniesWithCex is like CheckAlwaysDenies but returns a counterexample on failure.
func CheckAlwaysDeniesWithCex(schema *LeanSchema, request []byte) (*SymCCWithCexResponse, error) {
	schemaPtr, inputPtr, err := prepareSymCCCall(schema, request)
	if err != nil {
		return nil, err
	}
	return handleSymCCWithCexResult(C.runCheckAlwaysDeniesWithCex(schemaPtr, inputPtr))
}

// =============================================================================
// Two PolicySet Comparison
// =============================================================================

// CheckEquivalent verifies that two policy sets produce the same authorization decision.
// Returns true if both policy sets always agree on allow/deny for any valid request.
func CheckEquivalent(schema *LeanSchema, request []byte) (*SymCCResponse, error) {
	schemaPtr, inputPtr, err := prepareSymCCCall(schema, request)
	if err != nil {
		return nil, err
	}
	return handleSymCCResult(C.runCheckEquivalent(schemaPtr, inputPtr))
}

// CheckEquivalentWithCex is like CheckEquivalent but returns a counterexample on failure.
func CheckEquivalentWithCex(schema *LeanSchema, request []byte) (*SymCCWithCexResponse, error) {
	schemaPtr, inputPtr, err := prepareSymCCCall(schema, request)
	if err != nil {
		return nil, err
	}
	return handleSymCCWithCexResult(C.runCheckEquivalentWithCex(schemaPtr, inputPtr))
}

// CheckImplies verifies that one policy set's allows imply another's.
// Returns true if any request allowed by policy set 1 is also allowed by policy set 2.
func CheckImplies(schema *LeanSchema, request []byte) (*SymCCResponse, error) {
	schemaPtr, inputPtr, err := prepareSymCCCall(schema, request)
	if err != nil {
		return nil, err
	}
	return handleSymCCResult(C.runCheckImplies(schemaPtr, inputPtr))
}

// CheckImpliesWithCex is like CheckImplies but returns a counterexample on failure.
func CheckImpliesWithCex(schema *LeanSchema, request []byte) (*SymCCWithCexResponse, error) {
	schemaPtr, inputPtr, err := prepareSymCCCall(schema, request)
	if err != nil {
		return nil, err
	}
	return handleSymCCWithCexResult(C.runCheckImpliesWithCex(schemaPtr, inputPtr))
}

// CheckDisjoint verifies that two policy sets never both allow the same request.
// Returns true if no request is allowed by both policy sets.
func CheckDisjoint(schema *LeanSchema, request []byte) (*SymCCResponse, error) {
	schemaPtr, inputPtr, err := prepareSymCCCall(schema, request)
	if err != nil {
		return nil, err
	}
	return handleSymCCResult(C.runCheckDisjoint(schemaPtr, inputPtr))
}

// CheckDisjointWithCex is like CheckDisjoint but returns a counterexample on failure.
func CheckDisjointWithCex(schema *LeanSchema, request []byte) (*SymCCWithCexResponse, error) {
	schemaPtr, inputPtr, err := prepareSymCCCall(schema, request)
	if err != nil {
		return nil, err
	}
	return handleSymCCWithCexResult(C.runCheckDisjointWithCex(schemaPtr, inputPtr))
}

// =============================================================================
// Asserts
// =============================================================================

// CheckAsserts verifies that a set of assertions hold.
// Returns true if all assertions are satisfiable.
func CheckAsserts(schema *LeanSchema, request []byte) (*SymCCResponse, error) {
	schemaPtr, inputPtr, err := prepareSymCCCall(schema, request)
	if err != nil {
		return nil, err
	}
	return handleSymCCResult(C.runCheckAsserts(schemaPtr, inputPtr))
}
