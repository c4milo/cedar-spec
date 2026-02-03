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
Package proto provides conversion utilities between cedar-go types and the
protobuf message format expected by the Lean FFI layer.

# Overview

The Lean formalization of Cedar uses Protocol Buffers for serializing requests
and responses across the FFI boundary. This package bridges the gap between
cedar-go's native Go types and the protobuf wire format.

# Request Types

The package defines request wrapper types that hold cedar-go objects and can
serialize them for Lean:

  - [AuthorizationRequest]: Policies + entities + request for authorization
  - [ValidationRequest]: Schema + policies for validation
  - [EntityValidationRequest]: Schema + entities for entity validation
  - [RequestValidationRequest]: Schema + request for request validation

# Creating Requests

Use the helper constructors to create request objects from cedar-go types:

	// For authorization
	authReq := proto.PolicySetFromCedar(policies, entities, &request)
	bytes, err := authReq.ToProtobuf()

	// For validation
	valReq := proto.ValidationFromCedar(schema, policies)
	bytes, err := valReq.ToProtobuf()

# Serialization Format

Currently, the package uses JSON as an intermediate serialization format.
This is compatible with the Lean FFI layer which can parse JSON-encoded
protobuf-equivalent structures. The JSON format mirrors the protobuf
message definitions in Messages.proto:

	{
	    "request": { ... },
	    "policies": { ... },
	    "entities": [ ... ]
	}

Future versions may use proper protobuf binary encoding for better
performance and stricter type checking.

# Type Mappings

The conversion handles these cedar-go to protobuf mappings:

	cedar-go Type          → Protobuf Field
	─────────────────────────────────────────
	*cedar.PolicySet       → PolicySet (JSON)
	types.EntityMap        → Entities (JSON array)
	*cedar.Request         → Request (JSON)
	*schema.Schema         → Schema (JSON)

# Example Usage

Complete example for authorization:

	import (
	    "github.com/cedar-policy/cedar-go"
	    "github.com/cedar-policy/cedar-go/types"
	    "github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/proto"
	    "github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/lean"
	)

	func authorize(policies *cedar.PolicySet, entities types.EntityMap, req *cedar.Request) error {
	    // Convert to protobuf format
	    authReq := proto.PolicySetFromCedar(policies, entities, req)
	    protoBytes, err := authReq.ToProtobuf()
	    if err != nil {
	        return fmt.Errorf("conversion failed: %w", err)
	    }

	    // Call Lean FFI
	    resp, err := lean.IsAuthorized(protoBytes)
	    if err != nil {
	        return fmt.Errorf("lean call failed: %w", err)
	    }

	    fmt.Printf("Lean decision: %s\n", resp.Decision)
	    return nil
	}

# Error Handling

The ToProtobuf methods return errors if JSON marshaling fails, which can
happen if cedar-go types contain values that cannot be serialized (rare
in practice). Always check the error return value.
*/
package proto
