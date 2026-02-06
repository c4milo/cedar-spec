# Cedar Specification - Claude Code Guide

## Project Overview

This repository contains the **formal specification of Cedar**, an authorization policy language developed by AWS. It includes:

- **Lean 4 Formalization** (`cedar-lean/`): Mathematical specification with 100+ verified theorems
- **Differential Randomized Testing** (`cedar-drt/`): Fuzzing infrastructure comparing Lean spec vs Rust implementation
- **FFI Bindings** (`cedar-lean-ffi/`): Bridge between Rust and Lean via Protobuf
- **CLI Tool** (`cedar-lean-cli/`): Command-line interface for policy analysis

## Directory Structure

```
cedar-spec/
├── cedar-lean/           # Lean 4 formalization (primary)
│   ├── Cedar/Spec/       # Core definitions (Expr, Value, Policy, Evaluator)
│   ├── Cedar/Validation/ # Type checking and validation logic
│   ├── Cedar/SymCC/      # Symbolic compiler for SMT-based analysis
│   ├── Cedar/Thm/        # Formal theorems and proofs
│   ├── Cedar/TPE/        # Template policy engine
│   └── lakefile.lean     # Lake build configuration
├── cedar-drt/            # Differential testing framework
│   ├── fuzz/fuzz_targets/# 30+ fuzzing targets
│   └── src/              # DRT core library
├── cedar-lean-ffi/       # Lean-to-Rust FFI bindings
├── cedar-lean-cli/       # CLI tool
└── cedar-policy-generators/  # Test data generators
```

## Build Commands

### Lean Formalization

```bash
# Build main formalization
cd cedar-lean && lake build Cedar

# Build symbolic compiler
lake build SymCC

# Build everything
lake build

# Check proofs (lint for unchecked theorems)
lake lint
```

### Rust Components

```bash
# Build FFI library (requires Lean static lib first)
cd cedar-lean && ./build_lean_lib.sh
cd ../cedar-lean-ffi && cargo build

# Build CLI
cd cedar-lean-cli && cargo build

# Build DRT framework
cd cedar-drt && cargo build
```

### Docker (Full Environment)

```bash
docker build -t cedar-spec .
docker run -it cedar-spec
```

## Testing

### Lean Unit Tests

```bash
cd cedar-lean
lake exe CedarUnitTests    # Core unit tests
lake exe CedarSymTests     # Symbolic computation tests
```

### Differential Fuzzing (DRT)

```bash
cd cedar-drt

# Initialize corpus (first time)
./initialize_corpus.sh

# Run a specific fuzz target
cargo fuzz run -s none abac
cargo fuzz run -s none validation-drt
cargo fuzz run -s none eval-type-directed

# List all fuzz targets
cargo fuzz list
```

**Key fuzz targets:**
- `abac`, `rbac`: Authorization testing
- `validation-drt`: Validation logic
- `eval-type-directed`: Expression evaluation
- `symcc-*`: Symbolic compiler targets

### Integration Tests

```bash
# Requires cedar and cedar-integration-tests repos cloned as siblings
cargo test --features "integration-testing"
```

## Code Style

### Lean Conventions

- **Types**: `UpperCamelCase` (e.g., `Value`, `Policy`, `Expr`)
- **Functions**: `lowerCamelCase` (e.g., `evaluate`, `satisfied`)
- **Theorems/Props**: `lower_snake_case` (e.g., `forbid_trumps_permit`)
- Prefer anonymous hypotheses over named ones
- Use `simp only` instead of `simp` for stable proofs
- Add docstrings (`/-- ... -/`) for main theorems

See `cedar-lean/GUIDE.md` for detailed Lean style guide.

### Rust Conventions

- Standard Rust formatting (`cargo fmt`)
- Clippy compliance (`cargo clippy`)
- Edition 2024 features enabled

## Key Theorems

The formalization proves critical authorization properties:

| Theorem | Location | Property |
|---------|----------|----------|
| `forbid_trumps_permit` | `Cedar/Thm/Authorization.lean` | Forbid policies override permits |
| `well_typed_is_sound` | `Cedar/Thm/Typechecking.lean` | Type checking correctness |
| `compile_is_sound` | `Cedar/Thm/SymbolicCompilation.lean` | SMT encoding soundness |
| `slice_sound` | `Cedar/Thm/Slicing.lean` | Policy slicing preserves semantics |

## Development Workflow

1. **Before starting work**: Open a GitHub issue to discuss changes
2. **Build and test locally**:
   ```bash
   cd cedar-lean && lake build Cedar SymCC && lake lint
   lake exe CedarUnitTests && lake exe CedarSymTests
   ```
3. **Run DRT for changed areas**: `cargo fuzz run -s none <relevant-target>`
4. **Submit PR** against `main` branch
5. **CI must pass**: Lean build, lint, DRT, FFI, CLI, integration tests

## Dependencies

- **Lean**: Version pinned in `cedar-lean/lean-toolchain`
- **Rust**: Edition 2024
- **Protoc**: v29+ required
- **cvc5**: SMT solver for symbolic analysis features
- **Cedar**: Core library versions locked to 4.4.0+

## Architecture

```
┌─────────────────────────────────────────┐
│   CLI / Analysis Tools                  │
├─────────────────────────────────────────┤
│   Rust FFI (Protobuf serialization)     │
├─────────────────────────────────────────┤
│   Lean Formalization                    │
│   ├── Specification (Spec/)             │
│   ├── Validation & Type Checking        │
│   ├── Symbolic Compiler (SymCC → SMT)   │
│   └── Verified Theorems (Thm/)          │
├─────────────────────────────────────────┤
│   Production Rust (cedar-policy repo)   │
└─────────────────────────────────────────┘
```

The Lean formalization serves as the source of truth. DRT continuously verifies that the production Rust implementation matches the formal specification.

## Common Tasks

### Adding a New Theorem

1. Create theorem in appropriate `Cedar/Thm/*.lean` file
2. Follow naming convention: `property_being_proven`
3. Add docstring explaining the property
4. Run `lake lint` to verify no `sorry` or unchecked code

### Adding a New Fuzz Target

1. Create target in `cedar-drt/fuzz/fuzz_targets/`
2. Register in `cedar-drt/fuzz/Cargo.toml`
3. Add corpus initialization if needed
4. Document target purpose in source file

### Debugging DRT Failures

1. Check fuzzing output for failing input
2. Use `cargo fuzz fmt <target> <artifact>` to inspect
3. Compare Lean vs Rust outputs for the failing case
4. Fix divergence in either spec or implementation

## Resources

- [Cedar Language Documentation](https://docs.cedarpolicy.com/)
- [Cedar GitHub Repository](https://github.com/cedar-policy/cedar)
- [Lean 4 Documentation](https://lean-lang.org/documentation/)
- [Contributing Guide](./CONTRIBUTING.md)
