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
Package lean provides CGO bindings to call the Lean formalization of Cedar
from Go code. It wraps the Lean FFI (Foreign Function Interface) with safe
Go abstractions for memory management and thread safety.

# Overview

The Cedar language has a formal specification written in Lean 4. This package
enables Go programs to call that specification directly, allowing differential
testing between the cedar-go implementation and the authoritative Lean
formalization.

# Thread Safety

Lean requires careful thread management. The Lean runtime must be initialized
once per process, and each OS thread that calls Lean functions must have its
own Lean thread context. This package handles these requirements automatically:

  - The runtime is initialized lazily on first use via [Initialize]
  - Each goroutine must be locked to an OS thread before calling Lean
  - Use [WithLeanThread] or [NewLeanThread] to manage thread contexts

# Basic Usage

The simplest way to call Lean is using [WithLeanThread]:

	err := lean.WithLeanThread(func() error {
	    resp, err := lean.IsAuthorized(protoBytes)
	    if err != nil {
	        return err
	    }
	    fmt.Printf("Decision: %s\n", resp.Decision)
	    return nil
	})

For multiple operations, use [NewLeanThread] directly:

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := lean.Initialize(); err != nil {
	    log.Fatal(err)
	}

	lt, err := lean.NewLeanThread()
	if err != nil {
	    log.Fatal(err)
	}
	defer lt.Close()

	// Now safe to call lean.IsAuthorized, lean.Validate, etc.

# Available FFI Functions

The package exposes high-level wrappers for Lean FFI functions:

  - [IsAuthorized]: Run authorization check (policies + entities + request)
  - [Validate]: Validate policies against a schema
  - [LevelValidate]: Validate at a specific strictness level
  - [ValidateEntities]: Validate entities against a schema
  - [ValidateRequest]: Validate a request against a schema

Each function takes protobuf-encoded bytes as input and returns parsed
Go structs with the results.

# Memory Management

Lean objects are reference-counted. The [LeanObject] type wraps Lean pointers
with Go finalizers to automatically decrement reference counts when objects
are garbage collected. This prevents memory leaks without requiring manual
memory management.

	obj := lean.NewLeanObjectFromBytes(data)
	// obj will be automatically freed when no longer referenced

For advanced use cases, [LeanObject.ForgetOwnership] transfers ownership
to Lean (used internally when passing objects to FFI functions).

# Build Requirements

This package requires:

  - CGO enabled (CGO_ENABLED=1)
  - Lean 4 headers (lean/lean.h) in the include path
  - Lean static libraries linked (CedarFFI, CedarProto, Cedar, etc.)
  - The leanshared dynamic library at runtime

The Makefile in the parent directory sets up the appropriate CGO flags.
Typically:

	CGO_LDFLAGS="-L/path/to/lean/libs -lCedarFFI -lCedarProto -lCedar -lleanshared"

# Error Handling

FFI functions return errors in several cases:

  - Lean runtime initialization failure
  - Protobuf decoding errors in Lean
  - Lean backend errors (returned as error strings from Lean)

All errors are wrapped with context to aid debugging.
*/
package lean
