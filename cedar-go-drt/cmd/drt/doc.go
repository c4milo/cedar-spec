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

/*
Command drt is a CLI tool for manually testing cedar-go against the Lean
formalization of Cedar. It runs both implementations on the same input
and reports any differences.

# Usage

	drt [flags]

# Flags

	-policy string
	    Path to a Cedar policy file

	-policy-str string
	    Cedar policy as a string (alternative to -policy)

	-entities string
	    Path to entities JSON file (optional)

	-request string
	    Path to request JSON file (optional, uses default if not provided)

	-schema string
	    Path to Cedar schema file (required for validation mode)

	-validate
	    Run validation instead of authorization

	-verbose
	    Enable verbose output

# Authorization Mode

By default, drt runs in authorization mode. It evaluates the policy against
the provided entities and request, comparing cedar-go and Lean results.

Example with inline policy:

	drt -policy-str "permit(principal, action, resource);"

Example with files:

	drt -policy policy.cedar -entities entities.json -request request.json

# Validation Mode

Use -validate to check if a policy is valid against a schema:

	drt -validate -policy policy.cedar -schema schema.cedarschema

Note: cedar-go v1.4.1 doesn't fully expose validation, so this mode
primarily tests that schemas and policies parse correctly, then compares
against Lean's validation.

# Input Formats

Policy files should contain Cedar policy syntax:

	permit(principal, action, resource)
	when { principal.role == "admin" };

Entity files should be JSON arrays:

	[
	    {
	        "uid": {"type": "User", "id": "alice"},
	        "attrs": {"role": "admin"},
	        "parents": []
	    }
	]

Request files should be JSON objects:

	{
	    "principal": {"type": "User", "id": "alice"},
	    "action": {"type": "Action", "id": "view"},
	    "resource": {"type": "Document", "id": "doc1"},
	    "context": {}
	}

Schema files can be JSON or Cedar schema format.

# Output

The tool displays results from both implementations and comparison status:

	=== cedar-go Results ===
	Decision: allow
	Determining Policies: [policy0]
	Erroring Policies: []

	=== Lean Results ===
	Decision: allow
	Determining Policies: [policy0]
	Erroring Policies: []

	=== Comparison ===
	Results match!

If there are differences, the exit code is 1 and differences are displayed.

# Building

Build with the Makefile:

	make build

Or directly:

	CGO_ENABLED=1 \
	CGO_LDFLAGS="-L../cedar-lean/.lake/build/lib -lCedarFFI ..." \
	go build ./cmd/drt

# Environment

The Lean shared library must be accessible at runtime. Set the appropriate
library path:

	# macOS
	export DYLD_LIBRARY_PATH=/path/to/lean/libs:$DYLD_LIBRARY_PATH

	# Linux
	export LD_LIBRARY_PATH=/path/to/lean/libs:$LD_LIBRARY_PATH

The Makefile's run-drt target handles this automatically:

	make run-drt ARGS='-policy-str "permit(principal, action, resource);"'

# Exit Codes

	0 - Results match
	1 - Results differ or error occurred
*/
package main
