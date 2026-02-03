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
Package fuzz provides differential randomized testing (DRT) targets that
compare cedar-go against the Lean formalization of Cedar.

# Overview

This package contains Go fuzz tests that exercise the cedar-go library
with randomly generated inputs and compare the results against the
authoritative Lean specification. Any divergence indicates a potential
bug in one of the implementations.

# Fuzz Targets

The package provides these fuzz targets:

  - [FuzzAuthorization]: Tests authorization decisions
  - [FuzzValidation]: Tests policy validation against schemas

# Running Fuzz Tests

Use the standard Go fuzzing commands:

	# Run authorization fuzzing for 5 minutes
	go test -fuzz=FuzzAuthorization -fuzztime=5m ./fuzz/

	# Run validation fuzzing for 5 minutes
	go test -fuzz=FuzzValidation -fuzztime=5m ./fuzz/

	# Run with verbose output
	go test -fuzz=FuzzAuthorization -fuzztime=1m -v ./fuzz/

Or use the Makefile targets:

	make fuzz-auth    # Authorization fuzzing
	make fuzz-val     # Validation fuzzing

# Prerequisites

Before running fuzz tests, ensure:

 1. Lean libraries are built: `make lean`
 2. CGO is properly configured with library paths
 3. The Lean shared library is in LD_LIBRARY_PATH/DYLD_LIBRARY_PATH

The Makefile handles environment setup automatically.

# Input Format

Fuzz tests accept JSON input with this structure for authorization:

	{
	    "policies": ["permit(principal, action, resource);"],
	    "entities": [],
	    "request": {
	        "principal": {"type": "User", "id": "alice"},
	        "action": {"type": "Action", "id": "view"},
	        "resource": {"type": "Document", "id": "doc1"},
	        "context": {}
	    }
	}

And this structure for validation:

	{
	    "schema": "{\"entityTypes\":{...},\"actions\":{...}}",
	    "policies": ["permit(principal, action, resource);"]
	}

# Seed Corpus

Initial seed data is provided in two ways:

 1. Inline seeds in the test functions via f.Add()
 2. JSON files in testdata/ directory

The seed corpus helps the fuzzer find interesting inputs faster.
Add new seeds when you discover edge cases:

	fuzz/testdata/
	├── seed_permit_all.json
	├── seed_forbid_all.json
	├── seed_condition.json
	└── seed_hierarchy.json

# Handling Failures

When fuzzing finds a divergence:

 1. The failing input is saved to testdata/fuzz/<target>/
 2. The test output shows the difference details
 3. Reproduce with: go test -run=FuzzAuthorization/<hash>

To investigate:

	# Run the CLI with the failing input
	make run-drt ARGS='-policy-str "..." -entities entities.json'

	# Or examine the input directly
	cat testdata/fuzz/FuzzAuthorization/<hash>

# Thread Safety Notes

Each fuzz iteration runs in its own goroutine. The tests handle Lean's
thread requirements by:

 1. Locking to OS thread: runtime.LockOSThread()
 2. Initializing Lean thread context: lean.NewLeanThread()
 3. Cleaning up on completion: lt.Close()

This is done automatically in each fuzz function.

# Comparison Configuration

The fuzz tests use [comparison.DefaultConfig] which provides reasonable
defaults for differential testing:

  - Compares decisions and determining policies exactly
  - Compares erroring policy IDs (not error messages)
  - Uses type soundness checking for validation

Modify the config in the test if you need different behavior.

# Unit Tests

The package also includes basic unit tests that don't require Lean:

	go test -v ./fuzz/ -run=TestAuthorization
	go test -v ./fuzz/ -run=TestValidation

These test cedar-go in isolation and are useful for quick sanity checks.
*/
package fuzz
