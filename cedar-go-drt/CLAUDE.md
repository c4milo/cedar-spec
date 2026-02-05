# Cedar Go DRT - Claude Code Instructions

## ⚠️ Critical Build Requirement

**ALWAYS use `make build` instead of `go build ./...`**

The Makefile sets required CGO environment variables for Lean FFI:
- `CGO_CFLAGS` - Include path for Lean headers
- `CGO_LDFLAGS` - Library paths for Cedar/Lean libraries

Direct `go build` will fail with:
```
fatal error: 'lean/lean.h' file not found
```

## Project Overview

This is a **Differential Randomized Testing** (DRT) framework that compares the **cedar-go** implementation against the **Lean formalization** of Cedar. It uses Go's native fuzzing to find behavioral differences.

## Quick Reference

```bash
# Build everything
make build

# Run all unit tests
make test

# Initialize fuzz corpus (first time)
make corpus

# Run specific fuzz targets
make fuzz-auth       # Authorization (requires Lean)
make fuzz-val        # Validation (requires Lean)
make fuzz-val-strict # Strict validation - exact agreement (requires Lean)
make fuzz-roundtrip  # Roundtrip (pure Go, no Lean)
make fuzz-batch      # Batch evaluation (pure Go)

# Expanded corpus generation
make corpus-expanded           # Auth corpus with type-directed + edge cases
make corpus-validation-expanded # Validation corpus with type-directed cases

# Manual DRT testing
make run-drt ARGS='-policy-str "permit(principal, action, resource);"'

# See all targets
make help
```

## Prerequisites

Before building:
1. **Install elan** (Lean toolchain manager)
2. **Build Lean libraries**: `make lean`
3. **Generate protobuf**: `make proto`
4. **Clone cedar-policy repo** to `/tmp/cedar-policy` (for corpus)

## Project Structure

```
cedar-go-drt/
├── cmd/
│   ├── drt/           # Manual DRT CLI tool
│   └── init-corpus/   # Corpus initialization tool
├── fuzz/              # 47 fuzz test targets
├── internal/
│   ├── lean/          # CGO bindings to Lean FFI
│   ├── proto/         # Protobuf conversion (cedar-go ↔ Lean)
│   ├── typegen/       # Type-directed input generation
│   ├── comparison/    # Result comparison logic
│   └── corpus/        # Test data loading
└── Makefile           # Build system with CGO configuration
```

## Internal Packages

### `internal/lean/` - Lean FFI Bindings
CGO bindings to call Lean formalization from Go:
- `Initialize()` - One-time Lean runtime init
- `WithLeanThread(fn)` - Execute in Lean context
- `IsAuthorized([]byte)` - Authorization check
- `Validate([]byte)` - Policy validation
- `Evaluate([]byte)` - Expression evaluation

**Thread Safety**: Lean requires OS thread locking via `runtime.LockOSThread()`.

### `internal/proto/` - Protobuf Conversion
Converts cedar-go types to protobuf for Lean FFI:
- `PolicySetFromCedar()` → AuthorizationRequest
- `ValidationFromCedar()` → ValidationRequest
- `EvaluationFromCedar()` → EvaluationRequest

### `internal/typegen/` - Type-Directed Generation
Generates random but well-typed Cedar inputs:
- `TypeDirectedInputGenerator()` - Main generator
- Produces: Schema, Entities, Policies, Requests
- All generated inputs conform to the generated schema

### `internal/comparison/` - Result Comparison
Compares cedar-go vs Lean results:
- `CompareAuthorization()` - Decision, determining/erroring policies
- `CompareValidation()` - Valid/invalid with error messages
- `CheckTypeSoundness()` - If cedar-go accepts, Lean must too

## Fuzz Targets (51 total)

### Authorization (Lean Required)
| Make Target | Purpose |
|-------------|---------|
| `fuzz-auth` | Basic authorization DRT |
| `fuzz-auth-td` | Type-directed authorization |
| `fuzz-rbac` | RBAC role hierarchy |
| `fuzz-rbac-authorizer` | Abstract policy combinations |

### Validation (Lean Required)
| Make Target | Purpose |
|-------------|---------|
| `fuzz-val` | Basic validation DRT (type soundness) |
| `fuzz-val-strict` | Strict validation (exact agreement) |
| `fuzz-val-td` | Type-directed validation |
| `fuzz-val-pbt` | Property-based validation |
| `fuzz-entity-val` | Entity validation |
| `fuzz-request-val` | Request validation |
| `fuzz-level-val` | Level-based validation |

### Schema Well-Formedness (Lean Required)
| Make Target | Purpose |
|-------------|---------|
| `fuzz-schema-wf` | Schema well-formedness DRT |
| `fuzz-schema-wf-td` | Type-directed schema well-formedness |

### Evaluation (Lean Required)
| Make Target | Purpose |
|-------------|---------|
| `fuzz-eval` | Basic evaluation DRT |
| `fuzz-eval-td` | Type-directed evaluation |
| `fuzz-batch-drt` | Batch evaluation vs Lean |
| `fuzz-partial-eval` | Partial evaluation soundness |

### Parser Crash Testing (No Lean Required) ⚡
| Make Target | Purpose |
|-------------|---------|
| `fuzz-parser-crash` | Tests parsers don't panic on arbitrary input |
| `fuzz-schema-parser` | Schema parser crash testing |

### Pure Go (No Lean Required) ⚡
| Make Target | Purpose |
|-------------|---------|
| `fuzz-batch` | Batch evaluation consistency |
| `fuzz-roundtrip` | Policy/Schema roundtrip |
| `fuzz-wildcard` | Wildcard pattern matching |
| `fuzz-policy-cedar-to-json` | Cedar→JSON conversion |
| `fuzz-policy-json-to-cedar` | JSON→Cedar conversion |

### TPE/Partial Evaluation
| Make Target | Purpose |
|-------------|---------|
| `fuzz-tpe-query-principal` | Batch with variable principal |
| `fuzz-tpe-query-resource` | Batch with variable resource |
| `fuzz-tpe-query-action` | Batch with variable action |

### Entity Slicing & Schema
| Make Target | Purpose |
|-------------|---------|
| `fuzz-entity-slicing` | Sliced entities preserve decisions |
| `fuzz-schema-resolution` | JSON/Cedar schema equivalence |
| `fuzz-input-generation` | Generator produces valid inputs |

## CLI Tools

### drt - Manual DRT Testing
```bash
# Authorization mode (default)
make run-drt ARGS='-policy policy.cedar -entities entities.json -request request.json'

# Inline policy
make run-drt ARGS='-policy-str "permit(principal, action, resource);"'

# Validation mode
make run-drt ARGS='-validate -policy policy.cedar -schema schema.cedarschema'
```

**Flags:**
- `-policy <file>` - Path to Cedar policy file
- `-policy-str <string>` - Inline Cedar policy
- `-entities <file>` - Entities JSON file
- `-request <file>` - Request JSON file
- `-schema <file>` - Schema file (validation mode)
- `-validate` - Enable validation mode
- `-verbose` - Verbose output

### init-corpus - Corpus Initialization
```bash
# Basic corpus from cedar-policy repo
make corpus

# Include Rust DRT synthesized tests
make corpus-from-drt

# Full corpus with integration tests
make corpus-full

# Expanded corpus with type-directed and edge cases
make corpus-expanded

# Validation corpus with type-directed cases
make corpus-validation-expanded

# Direct tool usage with flags
go run ./cmd/init-corpus -generate=100 -edge-cases -output ./fuzz/testdata/fuzz/FuzzAuthorization
```

**init-corpus Flags:**
- `-generate N` - Generate N type-directed test cases
- `-edge-cases` - Include handcrafted edge cases (15 scenarios)
- `-output PATH` - Output directory for generated corpus
- `-verbose` - Verbose output

## Corpus Sources

The fuzzer can be seeded from multiple sources:
1. **Cedar sandboxes**: `cedar-policy/cedar-policy-cli/sample-data/tiny_sandboxes`
2. **Raw .cedar files**: Policy files from cedar repository
3. **Integration tests**: `cedar-integration-tests` repo (sibling directory)
4. **Rust DRT synthesized**: `cedar-drt/corpus-tests/` (run Rust DRT first)

## Comparison Modes

### Validation Comparison Modes
- **AgreeOnValid** (default): If cedar-go validates, Lean must validate (type soundness)
- **AgreeOnAll** (strict): Both must agree on ALL outcomes - valid AND invalid

The **strict validation mode** (`fuzz-val-strict`) catches:
- **Overly permissive**: cedar-go accepts policies that Lean rejects
- **Overly strict**: cedar-go rejects policies that Lean accepts

### Authorization Error Modes
- **Ignore**: Skip error comparison
- **PolicyIDs**: Compare which policies errored (default)
- **Full**: Compare complete error messages

## Key Properties Tested

1. **Soundness**: Partial evaluation preserves authorization decisions
2. **Type Soundness**: If cedar-go validates, Lean must validate
3. **Strict Agreement**: cedar-go and Lean agree on all validation outcomes
4. **Consistency**: Batch results match individual authorization
5. **Determinism**: Same input → same output
6. **Equivalence**: Format conversions preserve semantics
7. **Correctness**: Forbid trumps permit

## Environment Variables (Auto-configured by Makefile)

| Variable | Purpose |
|----------|---------|
| `LEAN_SYSROOT` | Lean toolchain root (auto-detected via elan) |
| `LEAN_BUILD_DIR` | Cedar Lean build libraries |
| `BATTERIES_BUILD_DIR` | Batteries library |
| `CGO_CFLAGS` | `-I$(LEAN_SYSROOT)/include` |
| `CGO_LDFLAGS` | Library linking flags |
| `DYLD_FALLBACK_LIBRARY_PATH` | Runtime library path (macOS) |

## Workflow Examples

### Running a Quick Test
```bash
# Pure Go tests (fast, no Lean setup needed)
make fuzz-roundtrip
make fuzz-wildcard
```

### Full DRT Testing
```bash
# 1. Build Lean libraries (one-time)
make lean

# 2. Build everything
make build

# 3. Initialize corpus
make corpus

# 4. Run authorization fuzzing
make fuzz-auth
```

### Debugging a Divergence
```bash
# Run manual DRT with specific input
make run-drt ARGS='-policy failing.cedar -entities failing_entities.json -request failing_request.json -verbose'
```

## Architecture Flow

```
Fuzzer Input (bytes)
    ↓
[typegen] Generate well-typed inputs
    ↓
[proto] Convert to Protobuf
    ↓
[lean] Call Lean FFI (thread-locked)
    ↓
[comparison] Compare cedar-go vs Lean
    ↓
Report differences (if any)
```

## Common Issues

### "lean/lean.h not found"
Use `make build` instead of `go build ./...`

### "undefined symbol: lean_*"
Lean libraries not built. Run `make lean` first.

### "library not loaded: libleanshared.dylib"
Runtime library path not set. Use Makefile targets which set `DYLD_FALLBACK_LIBRARY_PATH`.

### Fuzz test hangs
Some Lean operations are slow. Use `-fuzztime=1m` for quick iteration.
