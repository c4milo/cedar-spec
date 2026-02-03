# Cedar Go DRT

Differential Randomized Testing (DRT) harness for comparing **cedar-go** implementation against the **Lean formalization** of Cedar.

## Overview

This module provides:

- **CGO bindings** to call Lean FFI functions from Go
- **Comparison logic** to detect behavioral differences between implementations
- **47 fuzz targets** using Go's native fuzzing framework
- **Type-directed input generation** for well-typed random testing
- **CLI tool** for manual testing
- **Corpus expansion tools** with edge case generation

## Prerequisites

- Go 1.24+
- [elan](https://github.com/leanprover/elan) (Lean toolchain manager)
- `protoc` with `protoc-gen-go`
- Lean libraries built (see below)

## Building

### 1. Build Lean Libraries

First, build the Lean static libraries:

```bash
make lean
# Or manually:
cd ../cedar-lean && lake build CedarFFI:static
```

### 2. Generate Protobuf Code

```bash
make proto
```

### 3. Build Go Module

```bash
make build
```

## Usage

### Running Fuzz Tests

```bash
# Authorization fuzzing (5 minutes)
make fuzz-auth

# Type-directed authorization fuzzing
make fuzz-auth-td

# Validation fuzzing (5 minutes)
make fuzz-val

# Strict validation fuzzing (requires exact agreement)
make fuzz-val-strict

# All fuzz targets
make fuzz-all
```

### Corpus Management

```bash
# Basic corpus initialization
make corpus

# Expanded corpus with type-directed and edge cases
make corpus-expanded

# Validation corpus with full coverage
make corpus-validation-expanded
```

### Manual Testing via CLI

```bash
# Test authorization
make run-drt ARGS='-policy-str "permit(principal, action, resource);"'

# Test with files
make run-drt ARGS='-policy policy.cedar -entities entities.json -request request.json'

# Test validation
make run-drt ARGS='-validate -policy policy.cedar -schema schema.cedarschema'
```

### Unit Tests

```bash
make test
```

## Project Structure

```
cedar-go-drt/
├── cmd/
│   ├── drt/                  # CLI tool for manual DRT testing
│   │   └── main.go
│   └── init-corpus/          # Corpus initialization tool
│       └── main.go
├── fuzz/                     # Fuzz targets (47 total)
│   ├── authorization_test.go
│   ├── authorization_type_directed_test.go
│   ├── batch_authorization_test.go
│   ├── batch_evaluation_drt_test.go
│   ├── entity_slicing_test.go
│   ├── entity_validation_test.go
│   ├── evaluation_test.go
│   ├── evaluation_type_directed_test.go
│   ├── input_generation_test.go
│   ├── level_validation_test.go
│   ├── partial_eval_soundness_test.go
│   ├── policy_cedar_to_json_test.go
│   ├── policy_json_to_cedar_test.go
│   ├── rbac_test.go
│   ├── rbac_authorizer_test.go
│   ├── request_validation_test.go
│   ├── roundtrip_test.go
│   ├── schema_resolution_test.go
│   ├── symcc_cex_pbt_test.go
│   ├── tpe_query_action_test.go
│   ├── tpe_query_principal_test.go
│   ├── tpe_query_resource_test.go
│   ├── validation_test.go
│   ├── validation_pbt_test.go
│   ├── validation_strict_test.go
│   ├── validation_type_directed_test.go
│   ├── wildcard_test.go
│   └── testdata/             # Seed corpus
├── internal/
│   ├── lean/                 # CGO bindings to Lean
│   │   ├── cgo.go            # CGO declarations
│   │   ├── init.go           # Lean runtime initialization
│   │   ├── object.go         # Lean object memory management
│   │   └── ffi.go            # High-level FFI functions
│   ├── proto/                # Protobuf conversion
│   │   ├── convert.go        # cedar-go types <-> protobuf
│   │   └── convert_test.go   # Unit tests
│   ├── comparison/           # Result comparison
│   │   ├── modes.go          # Comparison modes
│   │   ├── authorization.go
│   │   └── validation.go
│   ├── corpus/               # Test data loading
│   │   ├── loader.go         # Corpus loading from files
│   │   ├── loader_test.go    # Unit tests
│   │   ├── generated.go      # Type-directed & edge case generation
│   │   └── generated_test.go # Unit tests
│   └── typegen/              # Type-directed input generation
│       └── generator.go
├── go.mod
├── Makefile
└── README.md
```

## Fuzz Targets

### Authorization (Lean Required)

| Make Target | Test File | Description |
|-------------|-----------|-------------|
| `fuzz-auth` | `authorization_test.go` | Basic authorization DRT |
| `fuzz-auth-td` | `authorization_type_directed_test.go` | Type-directed authorization |
| `fuzz-rbac` | `rbac_test.go` | RBAC role hierarchy testing |
| `fuzz-rbac-authorizer` | `rbac_authorizer_test.go` | Abstract policy combinations |
| `fuzz-batch-drt` | `batch_evaluation_drt_test.go` | Batch evaluation vs Lean |

### Validation (Lean Required)

| Make Target | Test File | Description |
|-------------|-----------|-------------|
| `fuzz-val` | `validation_test.go` | Basic validation DRT (type soundness) |
| `fuzz-val-strict` | `validation_strict_test.go` | Strict validation (exact agreement) |
| `fuzz-val-td` | `validation_type_directed_test.go` | Type-directed validation |
| `fuzz-val-pbt` | `validation_pbt_test.go` | Property-based validation |
| `fuzz-entity-val` | `entity_validation_test.go` | Entity validation |
| `fuzz-request-val` | `request_validation_test.go` | Request validation |
| `fuzz-level-val` | `level_validation_test.go` | Level-based validation |

### Evaluation (Lean Required)

| Make Target | Test File | Description |
|-------------|-----------|-------------|
| `fuzz-eval` | `evaluation_test.go` | Basic evaluation DRT |
| `fuzz-eval-td` | `evaluation_type_directed_test.go` | Type-directed evaluation |
| `fuzz-partial-eval` | `partial_eval_soundness_test.go` | Partial evaluation soundness |

### Pure Go (No Lean Required)

| Make Target | Test File | Description |
|-------------|-----------|-------------|
| `fuzz-batch` | `batch_authorization_test.go` | Batch evaluation consistency |
| `fuzz-roundtrip` | `roundtrip_test.go` | Policy/Schema roundtrip |
| `fuzz-wildcard` | `wildcard_test.go` | Wildcard pattern matching |
| `fuzz-policy-cedar-to-json` | `policy_cedar_to_json_test.go` | Cedar→JSON conversion |
| `fuzz-policy-json-to-cedar` | `policy_json_to_cedar_test.go` | JSON→Cedar conversion |
| `fuzz-input-generation` | `input_generation_test.go` | Generator produces valid inputs |

### TPE/Partial Evaluation

| Make Target | Test File | Description |
|-------------|-----------|-------------|
| `fuzz-tpe-query-principal` | `tpe_query_principal_test.go` | Batch with variable principal |
| `fuzz-tpe-query-resource` | `tpe_query_resource_test.go` | Batch with variable resource |
| `fuzz-tpe-query-action` | `tpe_query_action_test.go` | Batch with variable action |

### Entity & Schema

| Make Target | Test File | Description |
|-------------|-----------|-------------|
| `fuzz-entity-slicing` | `entity_slicing_test.go` | Sliced entities preserve decisions |
| `fuzz-schema-resolution` | `schema_resolution_test.go` | JSON/Cedar schema equivalence |
| `fuzz-symcc-cex-pbt` | `symcc_cex_pbt_test.go` | Symbolic counterexample testing |

## Comparison Modes

### Authorization Comparison

- **ErrorComparisonModeIgnore**: Ignore errors during comparison
- **ErrorComparisonModePolicyIDs**: Compare only which policies errored (default)
- **ErrorComparisonModeFull**: Compare error messages as well

### Validation Comparison

- **ValidationComparisonModeAgreeOnValid**: If cedar-go validates, Lean must validate (type soundness) - *default*
- **ValidationComparisonModeAgreeOnAll**: Both must agree on all outcomes - *strict mode*

#### Strict Validation Mode

The `fuzz-val-strict` target uses `ValidationComparisonModeAgreeOnAll` which requires cedar-go and Lean to agree on **all** validation outcomes, not just valid ones. This catches cases where:

- **cedar-go is overly permissive**: accepts policies that Lean rejects
- **cedar-go is overly strict**: rejects policies that Lean accepts

Use strict mode to find places where cedar-go validation differs from the formal specification, even when cedar-go is being conservative.

## Corpus Generation

### Basic Corpus

Initialize from cedar-policy repository test data:

```bash
make corpus
```

### Expanded Corpus

Generate additional test cases using type-directed generation and edge cases:

```bash
# Authorization corpus with type-directed and edge cases
make corpus-expanded

# Validation corpus with type-directed cases
make corpus-validation-expanded
```

### init-corpus Tool Flags

```bash
# Generate N type-directed test cases
go run ./cmd/init-corpus -generate=100

# Include handcrafted edge cases
go run ./cmd/init-corpus -edge-cases

# Full expanded corpus
go run ./cmd/init-corpus -generate=250 -edge-cases -output ./fuzz/testdata/fuzz/FuzzAuthorization
```

### Edge Cases Covered

The edge case generator includes:

- Empty policy sets
- Forbid trumps permit scenarios
- Multiple matching policies
- Entity hierarchies (principal/resource in groups)
- Context attribute conditions
- Resource containment hierarchies
- Action sets
- Unless conditions
- IP address extension usage
- Decimal extension usage
- `has` operator with `like` patterns
- Set `contains` operations
- Record attribute access
- Deeply nested entity hierarchies

## Architecture

```
┌─────────────────────────────────────────┐
│   Go Fuzz Targets / CLI                 │
├─────────────────────────────────────────┤
│   Comparison Layer                      │
│   (authorization.go, validation.go)     │
├─────────────────────────────────────────┤
│   cedar-go        │   Lean CGO          │
│   (native Go)     │   (FFI via C)       │
├───────────────────┼─────────────────────┤
│                   │   Protobuf          │
│                   │   (convert.go)      │
└───────────────────┴─────────────────────┘
                    │
                    ▼
        ┌─────────────────────┐
        │   Lean FFI          │
        │   (CedarFFI.lean)   │
        └─────────────────────┘
```

## Thread Safety

Lean requires careful thread management:

1. The Lean runtime is initialized once per process (`sync.Once`)
2. Each goroutine that calls Lean FFI must be locked to an OS thread (`runtime.LockOSThread()`)
3. Each thread must initialize its Lean context (`lean_initialize_thread()`)
4. The `lean.WithLeanThread()` helper handles this automatically

## Debugging

If a fuzz test finds a divergence:

1. The failing input is saved in `testdata/fuzz/<target>/`
2. Run the CLI with verbose output to see detailed comparison
3. Check if it's a known difference or a real bug

```bash
# Debug a specific failing input
go test -run=FuzzAuthorization/failing_input_name ./fuzz/
```

## Key Properties Tested

1. **Type Soundness**: If cedar-go validates, Lean must validate
2. **Authorization Correctness**: Same decision (Allow/Deny) and determining policies
3. **Forbid Trumps Permit**: Forbid policies override permits
4. **Entity Hierarchy**: `in` operator respects transitive parent relationships
5. **Roundtrip Consistency**: Cedar→JSON→Cedar preserves semantics
6. **Batch Consistency**: Batch results match individual authorization

## Known Differences

Some differences between cedar-go and Lean are expected:

- Error message formatting may differ
- Validation strictness levels may vary
- Extension function edge cases

These are handled via comparison modes in the configuration.

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) in the parent repository.

## License

Apache 2.0 - see [LICENSE](../LICENSE)
