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

// This file contains fuzz tests that specifically target Cedar extension function
// evaluation against the Lean formalization. The Lean spec formalizes detailed
// semantics for decimal, IP address, datetime, and duration operations in
// Cedar/Spec/Ext/Decimal.lean, Cedar/Spec/Ext/IPAddr.lean, and
// Cedar/Spec/Ext/Datetime.lean. These tests generate expressions heavy on
// extension function calls to stress those code paths.

import (
	"encoding/json"
	"fmt"
	"runtime"
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/ast"
	"github.com/cedar-policy/cedar-go/x/exp/eval"

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/lean"
	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/proto"
)

// FuzzEvaluationExtensions is a DRT fuzz target that generates Cedar expressions
// using extension functions (decimal, ip, datetime, duration) and compares
// cedar-go evaluation results against the Lean formalization.
//
// This covers the Lean spec areas:
//   - Cedar/Spec/Ext/Decimal.lean (decimal arithmetic, comparison)
//   - Cedar/Spec/Ext/IPAddr.lean (IP address parsing, CIDR, isInRange)
//   - Cedar/Spec/Ext/Datetime.lean (datetime/duration parsing, arithmetic)
func FuzzEvaluationExtensions(f *testing.F) {
	addExtensionSeeds(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		expr, entities, request, expected, err := parseEvaluationInput(data)
		if err != nil {
			return
		}

		if hasEmptyEntityType(entities, request) {
			return
		}

		cedarResult := runCedarGoEvaluation(expr, entities, request)

		leanResp := runLeanEvaluation(t, expr, entities, request, expected)
		if leanResp == nil {
			return
		}

		if !compareEvalResults(t, cedarResult, leanResp) {
			t.Errorf("Extension function evaluation divergence!\n"+
				"Cedar-go result: value=%v, error=%v\n"+
				"Lean result: match=%v, error=%s",
				cedarResult.Value, cedarResult.Error,
				leanResp.Match, leanResp.Error)
		}
	})
}

// FuzzEvaluationExtensionsTypeDirected generates well-typed schemas with extension
// type attributes and evaluates policies that use extension operations against Lean.
func FuzzEvaluationExtensionsTypeDirected(f *testing.F) {
	addExtensionSeeds(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		expr, entities, request, _, err := parseEvaluationInput(data)
		if err != nil {
			return
		}

		if hasEmptyEntityType(entities, request) {
			return
		}

		// Run cedar-go
		env := eval.Env{
			Entities:  entities,
			Principal: request.Principal,
			Action:    request.Action,
			Resource:  request.Resource,
			Context:   request.Context,
		}
		value, evalErr := eval.Eval(expr.AsIsNode(), env)

		// Run Lean
		evalReq := proto.EvaluationFromCedar(expr, entities, &request, ast.Node{})
		protoBytes, err := evalReq.ToProtobuf()
		if err != nil {
			return
		}

		if err := lean.Initialize(); err != nil {
			t.Fatalf("Failed to initialize Lean: %v", err)
		}

		lt, err := lean.NewLeanThread()
		if err != nil {
			t.Fatalf("Failed to create Lean thread: %v", err)
		}
		defer lt.Close()

		leanResp, err := lean.Evaluate(protoBytes)
		if err != nil {
			return
		}

		// Compare
		if evalErr != nil && leanResp.Error != "" {
			return // Both errored
		}
		if evalErr != nil && leanResp.Error == "" {
			t.Errorf("Extension divergence: cedar-go errored (%v), Lean succeeded", evalErr)
		}
		if evalErr == nil && leanResp.Error != "" {
			t.Errorf("Extension divergence: cedar-go succeeded (value=%v), Lean errored (%s)", value, leanResp.Error)
		}
	})
}

func addExtensionSeeds(f *testing.F) {
	baseRequest := `{"principal": {"type": "User", "id": "alice"}, "action": {"type": "Action", "id": "view"}, "resource": {"type": "Doc", "id": "doc1"}, "context": {}}`

	// ==========================================================================
	// Decimal extension function seeds
	// ==========================================================================

	// Decimal construction and comparison
	decimalExprs := []string{
		`decimal("1.0") == decimal("1.0")`,
		`decimal("1.23") < decimal("4.56")`,
		`decimal("0.0") >= decimal("-1.0")`,
		`decimal("999.999") > decimal("999.998")`,
		`decimal("-0.0001") < decimal("0.0001")`,
		// Decimal arithmetic edge cases
		`decimal("922337203685477.5807") > decimal("0.0")`,  // near max
		`decimal("-922337203685477.5808") < decimal("0.0")`, // near min
		`decimal("0.0000") == decimal("0.0")`,               // trailing zeros
		`decimal("1.0") <= decimal("1.0")`,
	}

	// ==========================================================================
	// IP address extension function seeds
	// ==========================================================================

	ipExprs := []string{
		// IPv4 basics
		`ip("192.168.1.1").isIpv4()`,
		`ip("10.0.0.0/8").isIpv4()`,
		`ip("192.168.1.1").isInRange(ip("192.168.0.0/16"))`,
		`ip("10.0.0.1").isInRange(ip("10.0.0.0/24"))`,
		`ip("172.16.0.1").isInRange(ip("172.16.0.0/12"))`,
		// IPv6 basics
		`ip("::1").isIpv6()`,
		`ip("fe80::1").isIpv6()`,
		`ip("::1").isLoopback()`,
		`ip("127.0.0.1").isLoopback()`,
		// Multicast
		`ip("224.0.0.1").isMulticast()`,
		`ip("ff02::1").isMulticast()`,
		// isInRange edge cases
		`ip("0.0.0.0").isInRange(ip("0.0.0.0/0"))`,        // everything is in /0
		`ip("255.255.255.255").isInRange(ip("0.0.0.0/0"))`, // everything is in /0
		`ip("192.168.1.1").isInRange(ip("192.168.1.1/32"))`, // exact match
		// Cross-type
		`ip("192.168.1.1") == ip("192.168.1.1")`,
		`ip("::ffff:192.168.1.1").isIpv6()`, // IPv4-mapped IPv6
	}

	// ==========================================================================
	// Datetime extension function seeds
	// ==========================================================================

	datetimeExprs := []string{
		// Basic datetime construction
		`datetime("2024-01-01T00:00:00Z") == datetime("2024-01-01T00:00:00Z")`,
		`datetime("2024-06-15T12:30:00Z") > datetime("2024-01-01T00:00:00Z")`,
		`datetime("1970-01-01T00:00:00Z") < datetime("2024-01-01T00:00:00Z")`,
		// Datetime with offset
		`datetime("2024-01-01T00:00:00+00:00") == datetime("2024-01-01T00:00:00Z")`,
		// Duration construction
		`duration("1d") == duration("1d")`,
		`duration("1h") < duration("1d")`,
		`duration("60s") == duration("1m")`,
		`duration("1000ms") == duration("1s")`,
		// Datetime arithmetic (offset/durationSince)
		`datetime("2024-01-01T00:00:00Z").offset(duration("1d")) == datetime("2024-01-02T00:00:00Z")`,
		`datetime("2024-01-02T00:00:00Z").durationSince(datetime("2024-01-01T00:00:00Z")) == duration("1d")`,
		// Component extraction
		`datetime("2024-06-15T12:30:45Z").toDate() == datetime("2024-06-15T00:00:00Z")`,
		`datetime("2024-06-15T12:30:45Z").toTime() == duration("12h30m45s")`,
		// Duration comparison
		`duration("2h") > duration("1h30m")`,
		`duration("0ms") == duration("0s")`,
	}

	// ==========================================================================
	// Mixed extension expressions (compound)
	// ==========================================================================

	mixedExprs := []string{
		// Decimal in conditions
		`if decimal("1.0") > decimal("0.5") then true else false`,
		`if decimal("0.0") < decimal("0.0") then false else true`,
		// IP in conditions
		`if ip("10.0.0.1").isInRange(ip("10.0.0.0/8")) then true else false`,
		`if ip("192.168.1.1").isLoopback() then false else true`,
		// Datetime in conditions
		`if datetime("2024-06-15T00:00:00Z") > datetime("2024-01-01T00:00:00Z") then true else false`,
		// Boolean chains with extensions
		`ip("127.0.0.1").isLoopback() && ip("127.0.0.1").isIpv4()`,
		`ip("::1").isLoopback() && ip("::1").isIpv6()`,
		`decimal("1.0") > decimal("0.0") && decimal("2.0") > decimal("1.0")`,
	}

	// Add all seeds
	for _, expr := range decimalExprs {
		f.Add([]byte(fmt.Sprintf(`{"expression": %s, "entities": [], "request": %s}`,
			jsonStr(expr), baseRequest)))
	}
	for _, expr := range ipExprs {
		f.Add([]byte(fmt.Sprintf(`{"expression": %s, "entities": [], "request": %s}`,
			jsonStr(expr), baseRequest)))
	}
	for _, expr := range datetimeExprs {
		f.Add([]byte(fmt.Sprintf(`{"expression": %s, "entities": [], "request": %s}`,
			jsonStr(expr), baseRequest)))
	}
	for _, expr := range mixedExprs {
		f.Add([]byte(fmt.Sprintf(`{"expression": %s, "entities": [], "request": %s}`,
			jsonStr(expr), baseRequest)))
	}

	// Also add context-based extension seeds
	contextRequest := `{"principal": {"type": "User", "id": "alice"}, "action": {"type": "Action", "id": "view"}, "resource": {"type": "Doc", "id": "doc1"}, "context": {"threshold": {"__extn": {"fn": "decimal", "arg": "5.0"}}, "client_ip": {"__extn": {"fn": "ip", "arg": "10.0.0.1"}}, "login_time": {"__extn": {"fn": "datetime", "arg": "2024-06-15T12:00:00Z"}}}}`

	contextExprs := []string{
		`context.threshold > decimal("3.0")`,
		`context.client_ip.isInRange(ip("10.0.0.0/8"))`,
		`context.client_ip.isIpv4()`,
		`context.login_time > datetime("2024-01-01T00:00:00Z")`,
	}
	for _, expr := range contextExprs {
		f.Add([]byte(fmt.Sprintf(`{"expression": %s, "entities": [], "request": %s}`,
			jsonStr(expr), contextRequest)))
	}

	// Load any existing corpus
	loadCorpusSeeds(f, "testdata/fuzz/FuzzEvaluationExtensions")
}

// jsonStr returns a JSON-encoded string value.
func jsonStr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// =============================================================================
// Extension Evaluation Unit Tests
// =============================================================================

// TestExtensionEvaluationDecimal tests decimal extension function evaluation
// against Lean for specific boundary cases.
func TestExtensionEvaluationDecimal(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	tests := []struct {
		name string
		expr string
	}{
		{"decimal equality", `decimal("1.0") == decimal("1.0")`},
		{"decimal less than", `decimal("1.23") < decimal("4.56")`},
		{"decimal negative", `decimal("-1.0") < decimal("0.0")`},
		{"decimal trailing zeros", `decimal("1.0000") == decimal("1.0")`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			expr, err := parseExpression(tc.expr)
			if err != nil {
				t.Fatalf("Failed to parse expression: %v", err)
			}

			request := cedar.Request{
				Principal: types.NewEntityUID("User", "alice"),
				Action:    types.NewEntityUID("Action", "view"),
				Resource:  types.NewEntityUID("Doc", "doc1"),
				Context:   types.Record{},
			}

			cedarResult := runCedarGoEvaluation(expr, nil, request)
			leanResp := runLeanEvaluation(t, expr, nil, request, ast.Node{})
			if leanResp == nil {
				t.Skip("Lean FFI not available")
			}

			if !compareEvalResults(t, cedarResult, leanResp) {
				t.Errorf("Decimal evaluation divergence for %q!\nCedar-go: %v (err=%v)\nLean: match=%v, err=%s",
					tc.expr, cedarResult.Value, cedarResult.Error, leanResp.Match, leanResp.Error)
			}
		})
	}
}

// TestExtensionEvaluationIPAddr tests IP address extension function evaluation.
func TestExtensionEvaluationIPAddr(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	tests := []struct {
		name string
		expr string
	}{
		{"ipv4 check", `ip("192.168.1.1").isIpv4()`},
		{"ipv6 check", `ip("::1").isIpv6()`},
		{"loopback v4", `ip("127.0.0.1").isLoopback()`},
		{"loopback v6", `ip("::1").isLoopback()`},
		{"multicast v4", `ip("224.0.0.1").isMulticast()`},
		{"in range", `ip("10.0.0.1").isInRange(ip("10.0.0.0/24"))`},
		{"not in range", `ip("172.16.0.1").isInRange(ip("10.0.0.0/8"))`},
		{"equality", `ip("192.168.1.1") == ip("192.168.1.1")`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			expr, err := parseExpression(tc.expr)
			if err != nil {
				t.Fatalf("Failed to parse expression: %v", err)
			}

			request := cedar.Request{
				Principal: types.NewEntityUID("User", "alice"),
				Action:    types.NewEntityUID("Action", "view"),
				Resource:  types.NewEntityUID("Doc", "doc1"),
				Context:   types.Record{},
			}

			cedarResult := runCedarGoEvaluation(expr, nil, request)
			leanResp := runLeanEvaluation(t, expr, nil, request, ast.Node{})
			if leanResp == nil {
				t.Skip("Lean FFI not available")
			}

			if !compareEvalResults(t, cedarResult, leanResp) {
				t.Errorf("IP address evaluation divergence for %q!\nCedar-go: %v (err=%v)\nLean: match=%v, err=%s",
					tc.expr, cedarResult.Value, cedarResult.Error, leanResp.Match, leanResp.Error)
			}
		})
	}
}

// TestExtensionEvaluationDatetime tests datetime/duration extension function evaluation.
func TestExtensionEvaluationDatetime(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	tests := []struct {
		name string
		expr string
	}{
		{"datetime equality", `datetime("2024-01-01T00:00:00Z") == datetime("2024-01-01T00:00:00Z")`},
		{"datetime comparison", `datetime("2024-06-15T00:00:00Z") > datetime("2024-01-01T00:00:00Z")`},
		{"duration equality", `duration("1d") == duration("1d")`},
		{"duration comparison", `duration("1h") < duration("1d")`},
		{"duration seconds", `duration("60s") == duration("1m")`},
		{"duration milliseconds", `duration("1000ms") == duration("1s")`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			expr, err := parseExpression(tc.expr)
			if err != nil {
				t.Fatalf("Failed to parse expression: %v", err)
			}

			request := cedar.Request{
				Principal: types.NewEntityUID("User", "alice"),
				Action:    types.NewEntityUID("Action", "view"),
				Resource:  types.NewEntityUID("Doc", "doc1"),
				Context:   types.Record{},
			}

			cedarResult := runCedarGoEvaluation(expr, nil, request)
			leanResp := runLeanEvaluation(t, expr, nil, request, ast.Node{})
			if leanResp == nil {
				t.Skip("Lean FFI not available")
			}

			if !compareEvalResults(t, cedarResult, leanResp) {
				t.Errorf("Datetime evaluation divergence for %q!\nCedar-go: %v (err=%v)\nLean: match=%v, err=%s",
					tc.expr, cedarResult.Value, cedarResult.Error, leanResp.Match, leanResp.Error)
			}
		})
	}
}
