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

// CedarFFI function declarations
extern lean_object* isAuthorized(lean_object* req);
extern lean_object* validate(lean_object* req);
extern lean_object* levelValidate(lean_object* req);
extern lean_object* validateEntities(lean_object* req);
extern lean_object* validateRequest(lean_object* req);
extern lean_object* checkEvaluate(lean_object* req);
extern lean_object* batchedEvaluateFFI(lean_object* req);

// Helper to check IO result and show errors
static inline int go_io_is_ok(lean_object* r) {
    return lean_io_result_is_ok(r);
}

static inline void go_io_show_error(lean_object* r) {
    lean_io_result_show_error(r);
}

// Extract value from IO result (takes ownership)
static inline lean_object* go_io_take_value(lean_object* r) {
    if (!lean_io_result_is_ok(r)) {
        return NULL;
    }
    lean_object* v = lean_ctor_get(r, 0);
    lean_inc(v);
    lean_dec(r);
    return v;
}

// Decrement reference
static inline void go_lean_dec(lean_object* o) {
    lean_dec(o);
}
*/
import "C"

import (
	"encoding/json"
	"errors"
	"fmt"
)

// AuthorizationResponse represents the result of an authorization check
// performed by the Lean formalization.
//
// The response contains the authorization decision along with diagnostic
// information about which policies contributed to the decision and which
// policies encountered errors during evaluation.
type AuthorizationResponse struct {
	// Decision is the authorization outcome: "allow" or "deny".
	// A request is allowed only if at least one permit policy is satisfied
	// and no forbid policies are satisfied (forbid trumps permit).
	Decision string `json:"decision"`

	// DeterminingPolicies lists the policy IDs that contributed to the decision.
	// For an "allow" decision, these are the satisfied permit policies.
	// For a "deny" decision, these are either satisfied forbid policies or
	// empty if no permit policies were satisfied.
	DeterminingPolicies []string `json:"determiningPolicies"`

	// ErroringPolicies lists the policy IDs that encountered evaluation errors.
	// These policies could not be fully evaluated due to runtime errors such as
	// missing attributes, type mismatches, or extension function failures.
	ErroringPolicies []string `json:"erroringPolicies"`
}

// ValidationResponse represents the result of a validation check performed
// by the Lean formalization.
//
// Validation checks whether policies are well-typed according to a schema.
// A valid policy is guaranteed not to produce type errors at runtime when
// evaluated against entities that conform to the schema.
type ValidationResponse struct {
	// Valid is true if validation passed (no type errors found).
	Valid bool `json:"valid"`

	// Errors contains validation error messages when Valid is false.
	// The format matches the Lean formalization's error output.
	Errors string `json:"errors,omitempty"`
}

// prepareInput creates a Lean byte array from the request and returns the pointer
// with ownership transferred (caller must ensure Lean function takes ownership).
func prepareInput(req []byte) *C.lean_object {
	input := NewLeanObjectFromBytes(req)
	return input.ForgetOwnership()
}

// wrapResult wraps a Lean result pointer in a LeanObject for safe access.
// Returns an error if the result is nil.
func wrapResult(result *C.lean_object) (*LeanObject, error) {
	if result == nil {
		return nil, errors.New("FFI function returned nil")
	}
	return newLeanObjectOwned(result), nil
}

// parseResult extracts the JSON string from a Lean String object.
// The CedarFFI functions return String directly containing JSON.
//
// Returns the JSON string or an error if not a string.
func parseResult(obj *LeanObject) (string, error) {
	return obj.AsString()
}

// IsAuthorized evaluates an authorization request using the Lean formalization.
//
// The request parameter must be a protobuf-encoded AuthorizationRequest message
// containing the policies, entities, and request to evaluate. Use the proto
// package to construct and encode the request:
//
//	authReq := proto.PolicySetFromCedar(policies, entities, &request)
//	protoBytes, err := authReq.ToProtobuf()
//	if err != nil {
//	    return err
//	}
//	resp, err := lean.IsAuthorized(protoBytes)
//
// The function must be called from within a Lean thread context. Use
// [WithLeanThread] or manually call [Initialize] and [NewLeanThread] first.
//
// Returns an [AuthorizationResponse] containing the decision and diagnostic
// information, or an error if the FFI call fails or Lean returns an error.
func IsAuthorized(request []byte) (*AuthorizationResponse, error) {
	inputPtr := prepareInput(request)
	result, err := wrapResult(C.isAuthorized(inputPtr))
	if err != nil {
		return nil, fmt.Errorf("isAuthorized FFI call failed: %w", err)
	}
	defer result.release()

	jsonStr, err := parseResult(result)
	if err != nil {
		return nil, err
	}

	// Parse the response structure
	// Lean returns: {"ok": {"duration": N, "data": {...}}} or {"error": "msg"}
	var outerResult struct {
		Ok *struct {
			Data     json.RawMessage `json:"data"`
			Duration uint64          `json:"duration"`
		} `json:"ok"`
		Error *string `json:"error"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &outerResult); err != nil {
		return nil, fmt.Errorf("failed to parse outer result: %w", err)
	}

	if outerResult.Error != nil {
		return nil, fmt.Errorf("lean error: %s", *outerResult.Error)
	}

	if outerResult.Ok == nil {
		return nil, errors.New("unexpected response format from Lean")
	}

	// Parse authorization response from Lean's JSON format
	// The Lean format uses nested structures for sets
	var innerResult struct {
		Decision            string `json:"decision"`
		DeterminingPolicies struct {
			Mk struct {
				L []string `json:"l"`
			} `json:"mk"`
		} `json:"determiningPolicies"`
		ErroringPolicies struct {
			Mk struct {
				L []string `json:"l"`
			} `json:"mk"`
		} `json:"erroringPolicies"`
	}
	if err := json.Unmarshal(outerResult.Ok.Data, &innerResult); err != nil {
		return nil, fmt.Errorf("failed to parse authorization response: %w", err)
	}

	return &AuthorizationResponse{
		Decision:            innerResult.Decision,
		DeterminingPolicies: innerResult.DeterminingPolicies.Mk.L,
		ErroringPolicies:    innerResult.ErroringPolicies.Mk.L,
	}, nil
}

// Validate checks whether policies are valid against a schema using the
// Lean formalization.
//
// The request parameter must be a protobuf-encoded ValidationRequest message
// containing the schema and policies to validate. Use the proto package to
// construct and encode the request:
//
//	valReq := proto.ValidationFromCedar(schema, policies)
//	protoBytes, err := valReq.ToProtobuf()
//	if err != nil {
//	    return err
//	}
//	resp, err := lean.Validate(protoBytes)
//
// The function must be called from within a Lean thread context.
//
// Returns a [ValidationResponse] indicating whether validation passed and
// any error messages, or an error if the FFI call fails.
func Validate(request []byte) (*ValidationResponse, error) {
	inputPtr := prepareInput(request)
	result, err := wrapResult(C.validate(inputPtr))
	if err != nil {
		return nil, fmt.Errorf("validate FFI call failed: %w", err)
	}
	defer result.release()

	jsonStr, err := parseResult(result)
	if err != nil {
		return nil, err
	}

	// Handle empty response
	if jsonStr == "" {
		return nil, fmt.Errorf("lean returned empty response")
	}

	// Parse the outer result structure
	// Lean returns: {"ok": {"duration": N, "data": {...}}} or {"error": "msg"}
	var outerResult struct {
		Ok *struct {
			Data     json.RawMessage `json:"data"`
			Duration uint64          `json:"duration"`
		} `json:"ok"`
		Error *string `json:"error"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &outerResult); err != nil {
		return nil, fmt.Errorf("failed to parse outer result: %w", err)
	}

	if outerResult.Error != nil {
		return nil, fmt.Errorf("lean error: %s", *outerResult.Error)
	}

	if outerResult.Ok == nil {
		return nil, errors.New("unexpected response format from Lean")
	}

	// Parse validation response - Lean returns either {"ok": null} or {"error": "msg"}
	var rawResponse map[string]any
	if err := json.Unmarshal(outerResult.Ok.Data, &rawResponse); err != nil {
		return nil, fmt.Errorf("failed to parse validation response: %w", err)
	}

	if _, ok := rawResponse["ok"]; ok {
		return &ValidationResponse{Valid: true}, nil
	}

	if errVal, ok := rawResponse["error"]; ok {
		errStr, _ := errVal.(string)
		return &ValidationResponse{Valid: false, Errors: errStr}, nil
	}

	return &ValidationResponse{Valid: true}, nil
}

// LevelValidate checks policies against a schema at a specific validation level
// using the Lean formalization.
//
// Validation levels control the strictness of type checking:
//   - Level 0: Basic type checking
//   - Higher levels: Additional semantic checks
//
// The request parameter must be a protobuf-encoded LevelValidationRequest.
// The function must be called from within a Lean thread context.
//
// Returns a [ValidationResponse] or an error if the FFI call fails.
func LevelValidate(request []byte) (*ValidationResponse, error) {
	inputPtr := prepareInput(request)
	result, err := wrapResult(C.levelValidate(inputPtr))
	if err != nil {
		return nil, fmt.Errorf("levelValidate FFI call failed: %w", err)
	}
	defer result.release()

	jsonStr, err := parseResult(result)
	if err != nil {
		return nil, err
	}

	// Parse the outer result structure
	// Lean returns: {"ok": {"duration": N, "data": {...}}} or {"error": "msg"}
	var outerResult struct {
		Ok *struct {
			Data     json.RawMessage `json:"data"`
			Duration uint64          `json:"duration"`
		} `json:"ok"`
		Error *string `json:"error"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &outerResult); err != nil {
		return nil, fmt.Errorf("failed to parse outer result: %w", err)
	}

	if outerResult.Error != nil {
		return nil, fmt.Errorf("lean error: %s", *outerResult.Error)
	}

	if outerResult.Ok == nil {
		return nil, errors.New("unexpected response format from Lean")
	}

	var rawResponse map[string]any
	if err := json.Unmarshal(outerResult.Ok.Data, &rawResponse); err != nil {
		return nil, fmt.Errorf("failed to parse validation response: %w", err)
	}

	if _, ok := rawResponse["ok"]; ok {
		return &ValidationResponse{Valid: true}, nil
	}

	if errVal, ok := rawResponse["error"]; ok {
		errStr, _ := errVal.(string)
		return &ValidationResponse{Valid: false, Errors: errStr}, nil
	}

	return &ValidationResponse{Valid: true}, nil
}

// ValidateEntities checks whether entities conform to a schema using the
// Lean formalization.
//
// This validates that:
//   - Entity types are defined in the schema
//   - Entity attributes match their declared types
//   - Parent relationships follow the schema's hierarchy
//
// The request parameter must be a protobuf-encoded EntityValidationRequest
// containing the schema and entities. The function must be called from
// within a Lean thread context.
//
// Returns a [ValidationResponse] or an error if the FFI call fails.
func ValidateEntities(request []byte) (*ValidationResponse, error) {
	inputPtr := prepareInput(request)
	result, err := wrapResult(C.validateEntities(inputPtr))
	if err != nil {
		return nil, fmt.Errorf("validateEntities FFI call failed: %w", err)
	}
	defer result.release()

	jsonStr, err := parseResult(result)
	if err != nil {
		return nil, err
	}

	// Parse the outer result structure
	// Lean returns: {"ok": {"duration": N, "data": {...}}} or {"error": "msg"}
	var outerResult struct {
		Ok *struct {
			Data     json.RawMessage `json:"data"`
			Duration uint64          `json:"duration"`
		} `json:"ok"`
		Error *string `json:"error"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &outerResult); err != nil {
		return nil, fmt.Errorf("failed to parse outer result: %w", err)
	}

	if outerResult.Error != nil {
		return nil, fmt.Errorf("lean error: %s", *outerResult.Error)
	}

	if outerResult.Ok == nil {
		return nil, errors.New("unexpected response format from Lean")
	}

	var rawResponse map[string]any
	if err := json.Unmarshal(outerResult.Ok.Data, &rawResponse); err != nil {
		return nil, fmt.Errorf("failed to parse validation response: %w", err)
	}

	if _, ok := rawResponse["ok"]; ok {
		return &ValidationResponse{Valid: true}, nil
	}

	if errVal, ok := rawResponse["error"]; ok {
		errStr, _ := errVal.(string)
		return &ValidationResponse{Valid: false, Errors: errStr}, nil
	}

	return &ValidationResponse{Valid: true}, nil
}

// ValidateRequest checks whether a request conforms to a schema using the
// Lean formalization.
//
// This validates that:
//   - The principal, action, and resource types are defined in the schema
//   - The action's appliesTo constraints allow the principal/resource types
//   - The context attributes match the action's declared context type
//
// The request parameter must be a protobuf-encoded RequestValidationRequest
// containing the schema and request. The function must be called from
// within a Lean thread context.
//
// Returns a [ValidationResponse] or an error if the FFI call fails.
func ValidateRequest(request []byte) (*ValidationResponse, error) {
	inputPtr := prepareInput(request)
	result, err := wrapResult(C.validateRequest(inputPtr))
	if err != nil {
		return nil, fmt.Errorf("validateRequest FFI call failed: %w", err)
	}
	defer result.release()

	jsonStr, err := parseResult(result)
	if err != nil {
		return nil, err
	}

	// Parse the outer result structure
	// Lean returns: {"ok": {"duration": N, "data": {...}}} or {"error": "msg"}
	var outerResult struct {
		Ok *struct {
			Data     json.RawMessage `json:"data"`
			Duration uint64          `json:"duration"`
		} `json:"ok"`
		Error *string `json:"error"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &outerResult); err != nil {
		return nil, fmt.Errorf("failed to parse outer result: %w", err)
	}

	if outerResult.Error != nil {
		return nil, fmt.Errorf("lean error: %s", *outerResult.Error)
	}

	if outerResult.Ok == nil {
		return nil, errors.New("unexpected response format from Lean")
	}

	var rawResponse map[string]any
	if err := json.Unmarshal(outerResult.Ok.Data, &rawResponse); err != nil {
		return nil, fmt.Errorf("failed to parse validation response: %w", err)
	}

	if _, ok := rawResponse["ok"]; ok {
		return &ValidationResponse{Valid: true}, nil
	}

	if errVal, ok := rawResponse["error"]; ok {
		errStr, _ := errVal.(string)
		return &ValidationResponse{Valid: false, Errors: errStr}, nil
	}

	return &ValidationResponse{Valid: true}, nil
}

// EvaluationResponse represents the result of an expression evaluation
// performed by the Lean formalization.
type EvaluationResponse struct {
	// Match is true if the evaluation result matched the expected value.
	// When no expected value is provided, this indicates successful evaluation.
	Match bool `json:"match"`

	// Result contains the evaluated value as a string representation.
	Result string `json:"result,omitempty"`

	// Error contains any evaluation error message.
	Error string `json:"error,omitempty"`
}

// Evaluate evaluates a Cedar expression using the Lean formalization.
//
// The request parameter must be a protobuf-encoded EvaluationRequestChecked
// message containing the expression to evaluate, the request context (for
// principal, action, resource), and entities.
//
// The function must be called from within a Lean thread context.
//
// Returns an [EvaluationResponse] or an error if the FFI call fails.
func Evaluate(request []byte) (*EvaluationResponse, error) {
	inputPtr := prepareInput(request)
	result, err := wrapResult(C.checkEvaluate(inputPtr))
	if err != nil {
		return nil, fmt.Errorf("checkEvaluate FFI call failed: %w", err)
	}
	defer result.release()

	jsonStr, err := parseResult(result)
	if err != nil {
		return nil, err
	}

	// Parse the outer result structure
	// Lean returns: {"ok": {"duration": N, "data": {...}}} or {"error": "msg"}
	var outerResult struct {
		Ok *struct {
			Data     json.RawMessage `json:"data"`
			Duration uint64          `json:"duration"`
		} `json:"ok"`
		Error *string `json:"error"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &outerResult); err != nil {
		return nil, fmt.Errorf("failed to parse outer result: %w", err)
	}

	if outerResult.Error != nil {
		return nil, fmt.Errorf("lean error: %s", *outerResult.Error)
	}

	if outerResult.Ok == nil {
		return nil, errors.New("unexpected response format from Lean")
	}

	// Parse the evaluation result - Lean returns {"ok": true/false} or {"error": "msg"}
	var rawResponse map[string]any
	if err := json.Unmarshal(outerResult.Ok.Data, &rawResponse); err != nil {
		return nil, fmt.Errorf("failed to parse evaluation response: %w", err)
	}

	// Check for match result (boolean indicating if eval matched expected)
	if okVal, ok := rawResponse["ok"]; ok {
		match, _ := okVal.(bool)
		return &EvaluationResponse{Match: match}, nil
	}

	// Check for error
	if errVal, ok := rawResponse["error"]; ok {
		errStr, _ := errVal.(string)
		return &EvaluationResponse{Match: false, Error: errStr}, nil
	}

	// Default to success if structure is unexpected
	return &EvaluationResponse{Match: true}, nil
}

// BatchedEvaluationResponse represents the result of a batched (partial) evaluation
// performed by the Lean formalization.
//
// Batched evaluation performs partial evaluation with lazy entity loading,
// returning a concrete boolean result when possible, or nil if the result
// cannot be determined (residual).
type BatchedEvaluationResponse struct {
	// Result is the evaluation outcome: true, false, or nil (unknown/residual).
	// When nil, the policy couldn't be fully evaluated with the available information.
	Result *bool `json:"result"`

	// Duration is the evaluation time in nanoseconds.
	Duration uint64 `json:"duration,omitempty"`
}

// BatchedEvaluate performs partial evaluation of a policy using the Lean formalization.
//
// The request parameter must be a protobuf-encoded BatchedEvaluationRequest message
// containing the policy set, schema, request, entities, and iteration limit.
//
// Batched evaluation works by:
// 1. Partially evaluating the policy with available entity information
// 2. Loading entities referenced by the residual expression
// 3. Re-evaluating until a concrete result is found or the iteration limit is reached
//
// The function must be called from within a Lean thread context. Use
// [WithLeanThread] or manually call [Initialize] and [NewLeanThread] first.
//
// Returns a [BatchedEvaluationResponse] containing the result (true/false/nil),
// or an error if the FFI call fails.
func BatchedEvaluate(request []byte) (*BatchedEvaluationResponse, error) {
	inputPtr := prepareInput(request)
	result, err := wrapResult(C.batchedEvaluateFFI(inputPtr))
	if err != nil {
		return nil, fmt.Errorf("batchedEvaluateFFI call failed: %w", err)
	}
	defer result.release()

	jsonStr, err := parseResult(result)
	if err != nil {
		return nil, err
	}

	// Parse the outer response structure
	// Lean returns: {"ok": {"data": ..., "duration": N}} or {"error": "msg"}
	var outerResult struct {
		Ok *struct {
			Data     json.RawMessage `json:"data"`
			Duration uint64          `json:"duration"`
		} `json:"ok"`
		Error *string `json:"error"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &outerResult); err != nil {
		return nil, fmt.Errorf("failed to parse outer result: %w", err)
	}

	if outerResult.Error != nil {
		return nil, fmt.Errorf("lean error: %s", *outerResult.Error)
	}

	if outerResult.Ok == nil {
		return nil, errors.New("unexpected response format from Lean")
	}

	// Parse Option Bool - Lean returns either {"some": bool} or "none"
	var optionResult any
	if err := json.Unmarshal(outerResult.Ok.Data, &optionResult); err != nil {
		return nil, fmt.Errorf("failed to parse option result: %w", err)
	}

	response := &BatchedEvaluationResponse{
		Duration: outerResult.Ok.Duration,
	}

	// Handle Option Bool encoding
	switch v := optionResult.(type) {
	case string:
		// "none" means residual (unknown)
		if v == "none" {
			response.Result = nil
		}
	case map[string]any:
		// {"some": bool} means concrete result
		if someVal, ok := v["some"]; ok {
			if boolVal, ok := someVal.(bool); ok {
				response.Result = &boolVal
			}
		}
	}

	return response, nil
}
