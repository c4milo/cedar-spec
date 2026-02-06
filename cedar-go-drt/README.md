# Cedar Go DRT

Differential Randomized Testing (DRT) harness for comparing **cedar-go** implementation against the **Lean formalization** of Cedar.

## Overview

This module provides:

- **CGO bindings** to call Lean FFI functions from Go
- **Comparison logic** to detect behavioral differences between implementations
- **66 fuzz targets** using Go's native fuzzing framework across 31 test files
- **Type-directed input generation** for well-typed random testing
- **SymCC/SMT analysis** for symbolic verification of policy properties
- **CLI tool** for manual testing
- **Corpus expansion tools** with edge case generation

## Prerequisites

- Go 1.24+
- [elan](https://github.com/leanprover/elan) (Lean toolchain manager)
- `protoc` with `protoc-gen-go`
- Lean libraries built (see below)
- [cvc5](https://cvc5.github.io/) (optional, for SymCC SMT analysis)

## Building

**Always use `make build` instead of `go build ./...`** — the Makefile sets required CGO environment variables for Lean FFI.

### 1. Build Lean Libraries

```bash
make lean
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
# Authorization fuzzing (cedar-go vs Lean)
make fuzz-auth

# Strict validation fuzzing (requires exact agreement)
make fuzz-val-strict

# Pure Go tests (no Lean runtime needed)
make fuzz-roundtrip
make fuzz-wildcard
make fuzz-parser-crash

# Authorization theorems (property-based, no Lean)
make fuzz-forbid-trumps
make fuzz-default-deny

# SymCC SMT analysis (requires cvc5)
ulimit -n 10240 && make fuzz-symcc-all

# See all targets
make help
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
make test          # Internal package tests
make test-fuzz     # Fuzz package non-fuzz tests (excludes SymCC)
make test-symcc    # SymCC unit tests (requires cvc5)
```

## Project Structure

```
cedar-go-drt/
├── cmd/
│   ├── drt/                  # CLI tool for manual DRT testing
│   └── init-corpus/          # Corpus initialization tool
├── fuzz/                     # Fuzz targets (66 across 31 files)
│   ├── authorization_test.go
│   ├── authorization_theorems_test.go
│   ├── authorization_type_directed_test.go
│   ├── batch_evaluation_test.go
│   ├── batched_evaluation_drt_test.go
│   ├── entity_slicing_test.go
│   ├── entity_validation_test.go
│   ├── evaluation_test.go
│   ├── evaluation_type_directed_test.go
│   ├── input_generation_test.go
│   ├── level_validation_test.go
│   ├── partial_evaluation_test.go
│   ├── partial_evaluation_drt_test.go
│   ├── policy_conversion_test.go
│   ├── protobuf_roundtrip_test.go
│   ├── rbac_test.go
│   ├── rbac_authorizer_test.go
│   ├── request_validation_test.go
│   ├── roundtrip_test.go
│   ├── roundtrip_extended_test.go
│   ├── schema_resolution_test.go
│   ├── schema_wellformedness_test.go
│   ├── simple_parser_test.go
│   ├── symcc_test.go
│   ├── tpe_drt_test.go
│   ├── tpe_query_test.go
│   ├── validation_test.go
│   ├── validation_pbt_test.go
│   ├── validation_strict_test.go
│   ├── validation_type_directed_test.go
│   ├── wildcard_matching_test.go
│   └── testdata/             # Seed corpus
├── internal/
│   ├── lean/                 # CGO bindings to Lean
│   │   ├── cgo.go            # CGO declarations
│   │   ├── init.go           # Lean runtime initialization
│   │   ├── object.go         # Lean object memory management
│   │   ├── ffi.go            # High-level FFI functions
│   │   └── symcc.go          # SymCC FFI bindings
│   ├── proto/                # Protobuf conversion
│   │   ├── convert.go        # cedar-go types → protobuf (authorization)
│   │   ├── convert_expr.go   # Expression conversion
│   │   ├── convert_schema.go # Schema conversion
│   │   ├── convert_symcc.go  # SymCC request conversion
│   │   └── convert_test.go
│   ├── comparison/           # Result comparison
│   │   ├── modes.go          # Comparison modes
│   │   ├── authorization.go  # Authorization result comparison
│   │   └── validation.go     # Validation result comparison
│   ├── corpus/               # Test data loading
│   │   ├── loader.go         # Corpus loading from files
│   │   ├── generated.go      # Type-directed & edge case generation
│   │   └── validation.go     # Validation corpus loading
│   └── typegen/              # Type-directed input generation
│       ├── input.go          # Generated input types
│       ├── schema.go         # Schema generation
│       ├── entity.go         # Entity generation
│       ├── policy.go         # Policy generation
│       ├── request.go        # Request generation
│       ├── rand.go           # Random utilities
│       └── settings.go       # Generator configuration
├── go.mod
├── Makefile
└── README.md
```

## Fuzz Targets

### Authorization Theorems (No Lean Required)

Property-based tests verifying Lean authorization theorems hold in cedar-go:

| Make Target | Fuzz Function | Description |
|-------------|---------------|-------------|
| `fuzz-forbid-trumps` | `FuzzForbidTrumpsPermit` | Forbid always overrides permit |
| `fuzz-default-deny` | `FuzzDefaultDeny` | Deny if no permit satisfied |
| `fuzz-order-dup` | `FuzzOrderAndDupIndependent` | Order/duplicates don't affect result |

### Authorization (Lean Required)

| Make Target | Fuzz Function | Description |
|-------------|---------------|-------------|
| `fuzz-auth` | `FuzzAuthorization` | Basic authorization DRT |
| `fuzz-auth-td` | `FuzzAuthorizationTypeDirected` | Type-directed authorization |
| `fuzz-rbac` | `FuzzRBAC` | RBAC role hierarchy testing |
| `fuzz-rbac-authorizer` | `FuzzRBACAuthorizer` | Abstract policy combinations |

### Validation (Lean Required)

| Make Target | Fuzz Function | Description |
|-------------|---------------|-------------|
| `fuzz-val` | `FuzzValidation` | Basic validation DRT (type soundness) |
| `fuzz-val-strict` | `FuzzValidationStrict` | Strict validation (exact agreement) |
| `fuzz-val-td` | `FuzzValidationTypeDirected` | Type-directed validation |
| `fuzz-val-pbt` | `FuzzValidationPBT` | Property-based validation |
| `fuzz-val-pbt-td` | `FuzzValidationPBTTypeDirected` | Type-directed validation PBT |
| `fuzz-entity-val` | `FuzzEntityValidation` | Entity validation |
| `fuzz-request-val` | `FuzzRequestValidation` | Request validation |
| `fuzz-level-val` | `FuzzLevelValidation` | Level-based validation |

### Evaluation (Lean Required)

| Make Target | Fuzz Function | Description |
|-------------|---------------|-------------|
| `fuzz-eval` | `FuzzEvaluation` | Basic evaluation DRT |
| `fuzz-eval-td` | `FuzzEvaluationTypeDirected` | Type-directed evaluation |
| `fuzz-batch-drt` | `FuzzBatchedEvaluationDRT` | Batch evaluation vs Lean |

### Schema Well-Formedness (Lean Required)

| Make Target | Fuzz Function | Description |
|-------------|---------------|-------------|
| `fuzz-schema-wf` | `FuzzSchemaWellFormedness` | Schema well-formedness DRT |
| `fuzz-schema-wf-td` | `FuzzSchemaWellFormednessTypeDirected` | Type-directed schema WF |

### TPE / Partial Evaluation (Lean Required)

| Make Target | Fuzz Function | Description |
|-------------|---------------|-------------|
| `fuzz-tpe-drt` | `FuzzTPEDRT` | TPE DRT (cedar-go batch vs Lean TPE) |
| `fuzz-tpe-soundness` | `FuzzTPESoundness` | Batch result matches full evaluation |
| `fuzz-tpe-reauth` | `FuzzTPEResidualReauthorize` | Partial eval + full eval must match |
| `fuzz-tpe-query-principal` | `FuzzTPEQueryPrincipal` | Batch with variable principal |
| `fuzz-tpe-query-resource` | `FuzzTPEQueryResource` | Batch with variable resource |
| `fuzz-tpe-query-action` | `FuzzTPEQueryAction` | Batch with variable action |
| `fuzz-partial-eval` | `FuzzPartialEvaluation` | Partial evaluation soundness |
| `fuzz-partial-eval-pbt` | `FuzzPartialEvaluationPBT` | Partial evaluation PBT |
| `fuzz-partial-eval-drt` | `FuzzPartialEvaluationDRT` | Partial evaluation DRT vs Lean |
| `fuzz-residual-set-drt` | `FuzzResidualSetDRT` | ResidualSet API DRT vs Lean |

### Parser Crash Testing (No Lean Required)

| Make Target | Fuzz Function | Description |
|-------------|---------------|-------------|
| `fuzz-parser-crash` | `FuzzPolicyParserCrash`, `FuzzSchemaParser`, `FuzzEntityUIDParser` | Parsers don't panic on arbitrary input |
| `fuzz-schema-parser` | `FuzzSchemaParser` | Schema parser crash testing |

Additional parser fuzz targets (no dedicated make target):
- `FuzzSimpleParserString` — String parser crash testing
- `FuzzSimpleParser` — General parser crash testing

### Roundtrip (No Lean Required)

| Make Target | Fuzz Function | Description |
|-------------|---------------|-------------|
| `fuzz-roundtrip` | `FuzzPolicyRoundtrip`, `FuzzSchemaRoundtrip`, `FuzzPolicySetRoundtrip` | Policy/Schema/PolicySet roundtrip |
| `fuzz-policy-cedar-to-json` | `FuzzPolicyCedarToJSON`, `FuzzPolicySetCedarToJSON` | Cedar → JSON conversion |
| `fuzz-policy-json-to-cedar` | `FuzzPolicyJSONToCedar` | JSON → Cedar conversion |
| `fuzz-proto-roundtrip` | `FuzzProtobufRoundtrip`, `FuzzProtobufPolicyRoundtrip` | Protobuf roundtrip |

Additional roundtrip fuzz targets (no dedicated make target):
- `FuzzJSONSchemaRoundtrip` — JSON schema roundtrip
- `FuzzSchemaCedarToJSON` — Schema Cedar → JSON
- `FuzzSchemaJSONToCedar` — Schema JSON → Cedar
- `FuzzEntitiesRoundtrip` — Entities JSON roundtrip
- `FuzzEntitiesRoundtripBytes` — Entities roundtrip from bytes
- `FuzzFormatter` — Policy formatter consistency
- `FuzzFormatterBytes` — Formatter from arbitrary bytes
- `FuzzGeneralRoundtrip` — General parse/format roundtrip

### Pure Go (No Lean Required)

| Make Target | Fuzz Function | Description |
|-------------|---------------|-------------|
| `fuzz-batch` | `FuzzBatchedEvaluation` | Batch evaluation consistency |
| `fuzz-wildcard` | `FuzzWildcardMatching` | Wildcard pattern matching |
| `fuzz-input-generation` | `FuzzInputGeneration` | Generator produces valid inputs |

Additional pure Go fuzz targets (no dedicated make target):
- `FuzzInputGenerationDiversity` — Generator output diversity
- `FuzzInputGenerationStress` — Generator stress testing

### Entity & Schema

| Make Target | Fuzz Function | Description |
|-------------|---------------|-------------|
| `fuzz-entity-slicing` | `FuzzEntitySlicing`, `FuzzEntitySlicingExtended` | Sliced entities preserve decisions |
| `fuzz-schema-resolution` | `FuzzSchemaResolution`, `FuzzSchemaEquivalence` | JSON/Cedar schema equivalence |

### SymCC / SMT Analysis (Lean + cvc5 Required)

| Make Target | Fuzz Function | Description |
|-------------|---------------|-------------|
| `fuzz-symcc-never-errors` | `FuzzSymCCNeverErrors` | Policies don't produce evaluation errors |
| `fuzz-symcc-always-matches` | `FuzzSymCCAlwaysMatches` | Policy conditions always evaluate to true |
| `fuzz-symcc-never-matches` | `FuzzSymCCNeverMatches` | Policy conditions never evaluate to true |
| `fuzz-symcc-always-allows` | `FuzzSymCCAlwaysAllows` | Policy sets always allow requests |
| `fuzz-symcc-always-denies` | `FuzzSymCCAlwaysDenies` | Policy sets always deny requests |
| `fuzz-symcc-matches-equiv` | `FuzzSymCCMatchesEquivalent` | Two policies have equivalent conditions |
| `fuzz-symcc-matches-implies` | `FuzzSymCCMatchesImplies` | One policy's condition implies another's |
| `fuzz-symcc-equiv` | `FuzzSymCCEquivalent` | Two policy sets are equivalent |
| `fuzz-symcc-implies` | `FuzzSymCCImplies` | One policy set implies another |
| `fuzz-symcc-all` | _(runs stable targets)_ | Runs `FuzzSymCCNeverErrors` only |

> **Note:** Some SymCC targets can cause cvc5 to hang on complex SMT queries. `FuzzSymCCNeverErrors` is the most stable target.

## Comparison Modes

### Authorization Comparison

- **ErrorComparisonModeIgnore**: Ignore errors during comparison
- **ErrorComparisonModePolicyIDs**: Compare only which policies errored (default)
- **ErrorComparisonModeFull**: Compare error messages as well

### Validation Comparison

- **ValidationComparisonModeAgreeOnValid**: If cedar-go validates, Lean must validate (type soundness) — *default*
- **ValidationComparisonModeAgreeOnAll**: Both must agree on all outcomes — *strict mode*

#### Strict Validation Mode

The `fuzz-val-strict` target uses `ValidationComparisonModeAgreeOnAll` which requires cedar-go and Lean to agree on **all** validation outcomes, not just valid ones. This catches cases where:

- **cedar-go is overly permissive**: accepts policies that Lean rejects
- **cedar-go is overly strict**: rejects policies that Lean accepts

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
│                   │   (convert*.go)     │
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
2. Reproduce with the exact test case:
   ```bash
   go test -run=FuzzAuthorization/failing_input_name ./fuzz/
   ```
3. Use the CLI with verbose output for detailed comparison:
   ```bash
   make run-drt ARGS='-policy failing.cedar -entities failing_entities.json -request failing_request.json -verbose'
   ```

## Key Properties Tested

1. **Type Soundness**: If cedar-go validates, Lean must validate
2. **Authorization Correctness**: Same decision (Allow/Deny) and determining policies
3. **Forbid Trumps Permit**: Forbid policies always override permits
4. **Default Deny**: No permit satisfied implies deny
5. **Order Independence**: Policy order and duplicates don't affect authorization
6. **Entity Hierarchy**: `in` operator respects transitive parent relationships
7. **Roundtrip Consistency**: Cedar → JSON → Cedar preserves semantics
8. **Batch Consistency**: Batch results match individual authorization
9. **TPE Soundness**: Partial evaluation matches full evaluation
10. **SymCC Properties**: SMT-verified policy analysis (never errors, equivalence, implication)

## Common Issues

### "lean/lean.h not found"
Use `make build` instead of `go build ./...`

### "undefined symbol: lean_*"
Lean libraries not built. Run `make lean` first.

### "library not loaded: libleanshared.dylib"
Runtime library path not set. Use Makefile targets which set `DYLD_FALLBACK_LIBRARY_PATH`.

### "No SMT solver found" (SymCC targets only)
Install cvc5: `brew install cvc5` or from [cvc5.github.io](https://cvc5.github.io/)

### "too many open files" during fuzzing
Increase the file descriptor limit: `ulimit -n 10240`

### Fuzz test hangs
Some Lean operations are slow. Use `-fuzztime=1m` for quick iteration. Some SymCC targets can cause cvc5 to hang on complex SMT queries — `FuzzSymCCNeverErrors` is the most stable.

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) in the parent repository.

## License

Apache 2.0 — see [LICENSE](../LICENSE)
