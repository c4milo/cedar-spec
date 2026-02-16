# Copyright Cedar Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Cedar Go DRT Makefile

LEAN_DIR := ../cedar-lean
LEAN_BUILD_DIR := $(LEAN_DIR)/.lake/build/lib
PROTO_SCHEMA_DIR := ../cedar-lean-ffi/protobuf_schema
CEDAR_REPO := /tmp/cedar-policy
CEDAR_PROTO_DIR := $(CEDAR_REPO)/cedar-policy/protobuf_schema
PROTO_OUT_DIR := internal/proto/pb

# Lean library names (in dependency order: most dependent first)
LEAN_LIBS := CedarFFI CedarProto Cedar Cedar_SymCC Protobuf

# Additional library directories
BATTERIES_BUILD_DIR := $(LEAN_DIR)/.lake/packages/batteries/.lake/build/lib

# Get the Lean sysroot for leanshared
# Try elan from PATH first, then from ~/.elan/bin
LEAN_SYSROOT := $(shell (elan which lean 2>/dev/null || ~/.elan/bin/elan which lean 2>/dev/null) | xargs dirname 2>/dev/null | xargs dirname 2>/dev/null || echo "")

# CGO compile flags - include path for Lean headers
CGO_COMPILE_FLAGS := -I$(LEAN_SYSROOT)/include

# CGO link flags - order matters for static libraries
# Include rpath flags for macOS dynamic library loading
CGO_LINK_FLAGS := -L$(LEAN_BUILD_DIR) $(addprefix -l,$(LEAN_LIBS)) \
	-L$(BATTERIES_BUILD_DIR) -lBatteries \
	-L$(LEAN_SYSROOT)/lib/lean -lleanshared \
	-Wl,-rpath,$(LEAN_SYSROOT)/lib/lean \
	-Wl,-rpath,$(CURDIR)/$(LEAN_BUILD_DIR) \
	-Wl,-rpath,$(CURDIR)/$(BATTERIES_BUILD_DIR)

# Platform-specific settings
# On macOS, DYLD_LIBRARY_PATH can be stripped by SIP, use DYLD_FALLBACK_LIBRARY_PATH instead
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    DYLIB_PATH_VAR := DYLD_FALLBACK_LIBRARY_PATH
else
    DYLIB_PATH_VAR := LD_LIBRARY_PATH
endif

# SMT solver paths for SymCC targets
# The Lean code uses CVC5 if available, falling back to Z3
# To force z3 only: make fuzz-symcc-never-errors USE_Z3=1
Z3_PATH := $(or $(Z3),$(shell which z3 2>/dev/null),$(wildcard /opt/homebrew/bin/z3),$(wildcard /usr/local/bin/z3))
ifdef USE_Z3
CVC5_PATH :=
else
CVC5_PATH := $(or $(CVC5),$(shell which cvc5 2>/dev/null),$(wildcard $(HOME)/.local/bin/cvc5),$(wildcard /usr/local/bin/cvc5),$(wildcard /opt/homebrew/bin/cvc5))
endif

# SMT solver environment variables (set both, Lean picks CVC5 first)
SMT_ENV := $(if $(CVC5_PATH),CVC5="$(CVC5_PATH)") $(if $(Z3_PATH),Z3="$(Z3_PATH)")

# Check if at least one solver is available
HAS_SMT_SOLVER := $(or $(CVC5_PATH),$(Z3_PATH))

# Fuzz time for SymCC targets (can be overridden: make fuzz-symcc-all SYMCC_FUZZTIME=1m)
SYMCC_FUZZTIME ?= 2m

# Fuzz parallel workers (reduce for SymCC to avoid "too many open files": make fuzz-symcc-* FUZZ_PARALLEL=1)
FUZZ_PARALLEL ?=
FUZZ_PARALLEL_FLAG := $(if $(FUZZ_PARALLEL),-parallel=$(FUZZ_PARALLEL))

.PHONY: all lean proto build test test-fuzz test-symcc lint deadcode fmt fuzz-auth fuzz-val fuzz-val-strict fuzz-eval fuzz-eval-td fuzz-eval-ext fuzz-eval-ext-td fuzz-entity-val fuzz-request-val fuzz-level-val fuzz-auth-td fuzz-val-td fuzz-batch fuzz-batch-drt fuzz-roundtrip fuzz-proto-roundtrip fuzz-rbac fuzz-rbac-authorizer fuzz-val-pbt fuzz-val-pbt-td fuzz-wildcard fuzz-partial-eval fuzz-partial-eval-pbt fuzz-policy-cedar-to-json fuzz-policy-json-to-cedar fuzz-tpe-query-principal fuzz-tpe-query-resource fuzz-tpe-query-action fuzz-entity-slicing fuzz-schema-resolution fuzz-input-generation fuzz-parser-crash fuzz-schema-parser fuzz-schema-wf fuzz-schema-wf-td fuzz-forbid-trumps fuzz-default-deny fuzz-order-dup fuzz-denied-iff fuzz-add-permit fuzz-add-forbid fuzz-det-err-disjoint fuzz-unchanged-det fuzz-unchanged-err fuzz-error-irrel fuzz-rm-forbid fuzz-rm-permit fuzz-decomp fuzz-error-irrel-drt fuzz-rm-forbid-drt fuzz-rm-permit-drt fuzz-decomp-drt fuzz-tpe-drt fuzz-tpe-soundness fuzz-tpe-reauth fuzz-symcc-never-errors fuzz-symcc-always-matches fuzz-symcc-never-matches fuzz-symcc-always-allows fuzz-symcc-always-denies fuzz-symcc-matches-equiv fuzz-symcc-matches-implies fuzz-symcc-matches-disjoint fuzz-symcc-equiv fuzz-symcc-implies fuzz-symcc-disjoint fuzz-symcc-withcex fuzz-symcc-all corpus corpus-from-drt corpus-full corpus-expanded corpus-validation corpus-validation-expanded clean help

all: proto build

## corpus: Initialize fuzz corpus from all available test data sources
## Loads from: cedar-policy sandboxes, .cedar files, integration tests, Rust DRT synthesized tests
corpus:
	go run ./cmd/init-corpus -cedar-repo=$(CEDAR_REPO) -v

## corpus-from-drt: Initialize corpus including synthesized tests from Rust DRT
## Requires running Rust DRT first: cd ../cedar-drt && ./create_corpus.sh
corpus-from-drt:
	go run ./cmd/init-corpus -cedar-repo=$(CEDAR_REPO) -synthesized=../cedar-drt/corpus-tests -v

## corpus-full: Initialize corpus from all sources including integration tests
## Requires cedar-integration-tests repo cloned as sibling
corpus-full:
	go run ./cmd/init-corpus -cedar-repo=$(CEDAR_REPO) \
		-integration-tests=../cedar-integration-tests \
		-synthesized=../cedar-drt/corpus-tests -v

## corpus-validation: Initialize validation fuzz corpus with schema+policy pairs
corpus-validation:
	go run ./cmd/init-corpus -cedar-repo=$(CEDAR_REPO) \
		-integration-tests=../cedar-integration-tests \
		-synthesized=../cedar-drt/corpus-tests \
		-validation -v

## corpus-expanded: Initialize expanded corpus with generated test cases and edge cases
## Includes: all sources + 100 type-directed generated cases + handcrafted edge cases
corpus-expanded:
	go run ./cmd/init-corpus -cedar-repo=$(CEDAR_REPO) \
		-integration-tests=../cedar-integration-tests \
		-synthesized=../cedar-drt/corpus-tests \
		-generate=100 -edge-cases -v

## corpus-validation-expanded: Expanded validation corpus with generated cases
corpus-validation-expanded:
	go run ./cmd/init-corpus -cedar-repo=$(CEDAR_REPO) \
		-integration-tests=../cedar-integration-tests \
		-synthesized=../cedar-drt/corpus-tests \
		-validation -generate=100 -v

## lean: Build Lean static libraries
lean:
	cd $(LEAN_DIR) && lake build Cedar:static Protobuf:static CedarProto:static Cedar.SymCC:static CedarFFI:static Batteries:static

## proto: Generate Go protobuf code from proto definitions
proto: $(PROTO_OUT_DIR)/ffi/Messages.pb.go

$(PROTO_OUT_DIR)/ffi/Messages.pb.go: $(PROTO_SCHEMA_DIR)/Messages.proto
	@mkdir -p $(PROTO_OUT_DIR)/core $(PROTO_OUT_DIR)/validator $(PROTO_OUT_DIR)/ffi
	@# Generate core.proto
	protoc \
		--proto_path=$(CEDAR_PROTO_DIR) \
		--go_out=$(PROTO_OUT_DIR)/core \
		--go_opt=paths=source_relative \
		--go_opt=Mcore.proto=github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/proto/pb/core \
		$(CEDAR_PROTO_DIR)/core.proto
	@# Generate validator.proto
	protoc \
		--proto_path=$(CEDAR_PROTO_DIR) \
		--go_out=$(PROTO_OUT_DIR)/validator \
		--go_opt=paths=source_relative \
		--go_opt=Mcore.proto=github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/proto/pb/core \
		--go_opt=Mvalidator.proto=github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/proto/pb/validator \
		$(CEDAR_PROTO_DIR)/validator.proto
	@# Generate Messages.proto
	protoc \
		--proto_path=$(PROTO_SCHEMA_DIR) \
		--proto_path=$(CEDAR_PROTO_DIR) \
		--go_out=$(PROTO_OUT_DIR)/ffi \
		--go_opt=paths=source_relative \
		--go_opt=Mcore.proto=github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/proto/pb/core \
		--go_opt=Mvalidator.proto=github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/proto/pb/validator \
		--go_opt=MMessages.proto=github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/proto/pb/ffi \
		$(PROTO_SCHEMA_DIR)/Messages.proto

## build: Build Go module
build: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	go build ./...

## test: Run unit tests (internal packages)
test: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	go test -v ./internal/...

## test-fuzz: Run unit tests in fuzz package (non-fuzz tests only, excludes SymCC tests)
test-fuzz: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	go test -v -run '^Test[^S]|^TestS[^y]' ./fuzz/

## test-symcc: Run SymCC unit tests (requires cvc5)
test-symcc: proto
	@if [ -z "$(HAS_SMT_SOLVER)" ]; then echo "Error: No SMT solver found. Install cvc5 or z3."; exit 1; fi
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -v -run '^TestSymCC' ./fuzz/

## lint: Run Go linters (golangci-lint preferred, falls back to go vet)
lint:
	@if which golangci-lint > /dev/null 2>&1; then \
		CGO_ENABLED=1 \
		CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
		CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed, using go vet"; \
		CGO_ENABLED=1 \
		CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
		CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
		go vet ./...; \
	fi

## deadcode: Find unreachable functions using whole-program analysis
## See: https://go.dev/blog/deadcode
## Note: Uses -test flag to include test code in the analysis
deadcode:
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	go run golang.org/x/tools/cmd/deadcode@latest -test ./...

## fmt: Format Go code
fmt:
	go fmt ./...
	@which goimports > /dev/null 2>&1 && goimports -w . || echo "goimports not installed, skipping"

## fuzz-auth: Run authorization fuzzing
fuzz-auth: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz='FuzzAuthorization$$' -fuzztime=5m ./fuzz/

## fuzz-val: Run validation fuzzing
fuzz-val: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz='FuzzValidation$$' -fuzztime=5m ./fuzz/

## fuzz-val-strict: Run strict validation fuzzing (requires exact agreement)
## This catches cases where cedar-go is overly strict OR overly permissive
fuzz-val-strict: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz='FuzzValidationStrict$$' -fuzztime=5m ./fuzz/

## fuzz-eval: Run evaluation fuzzing
fuzz-eval: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz='^FuzzEvaluation$$' -fuzztime=5m ./fuzz/

## fuzz-eval-td: Run type-directed evaluation fuzzing
fuzz-eval-td: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz=FuzzEvaluationTypeDirected -fuzztime=5m ./fuzz/

## fuzz-eval-ext: Run extension function evaluation DRT (decimal, IP, datetime, duration)
## Tests Cedar extension functions against Lean Ext/Decimal.lean, Ext/IPAddr.lean, Ext/Datetime.lean
fuzz-eval-ext: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz='^FuzzEvaluationExtensions$$' -fuzztime=5m ./fuzz/

## fuzz-eval-ext-td: Run type-directed extension function evaluation DRT
fuzz-eval-ext-td: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz=FuzzEvaluationExtensionsTypeDirected -fuzztime=5m ./fuzz/

## fuzz-entity-val: Run entity validation fuzzing
fuzz-entity-val: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz=FuzzEntityValidation -fuzztime=5m ./fuzz/

## fuzz-request-val: Run request validation fuzzing
fuzz-request-val: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz=FuzzRequestValidation -fuzztime=5m ./fuzz/

## fuzz-level-val: Run level-based validation fuzzing
fuzz-level-val: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz=FuzzLevelValidation -fuzztime=5m ./fuzz/

## fuzz-auth-td: Run type-directed authorization fuzzing
fuzz-auth-td: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz=FuzzAuthorizationTypeDirected -fuzztime=5m ./fuzz/

## fuzz-val-td: Run type-directed validation fuzzing
fuzz-val-td: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz=FuzzValidationTypeDirected -fuzztime=5m ./fuzz/

## fuzz-batch: Run batched evaluation fuzzing (property-based, no Lean FFI calls but needs CGO for build)
fuzz-batch: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(SMT_ENV) \
	go test -fuzz='^FuzzBatchedEvaluation$$' -fuzztime=5m ./fuzz/

## fuzz-roundtrip: Run roundtrip fuzzing (no Lean FFI calls but needs CGO for build)
fuzz-roundtrip: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(SMT_ENV) \
	go test -fuzz=FuzzPolicyRoundtrip -fuzztime=2m ./fuzz/
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(SMT_ENV) \
	go test -fuzz=FuzzSchemaRoundtrip -fuzztime=2m ./fuzz/
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(SMT_ENV) \
	go test -fuzz=FuzzPolicySetRoundtrip -fuzztime=2m ./fuzz/

## fuzz-rbac: Run RBAC role hierarchy fuzzing
fuzz-rbac: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz='^FuzzRBAC$$' -fuzztime=5m ./fuzz/

## fuzz-rbac-authorizer: Run abstract policy combination fuzzing
fuzz-rbac-authorizer: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz=FuzzRBACAuthorizer -fuzztime=5m ./fuzz/

## fuzz-batch-drt: Run batched evaluation DRT (compares against Lean)
fuzz-batch-drt: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz=FuzzBatchedEvaluationDRT -fuzztime=5m ./fuzz/

## fuzz-proto-roundtrip: Run protobuf roundtrip fuzzing
fuzz-proto-roundtrip: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz=FuzzProtobufRoundtrip -fuzztime=5m ./fuzz/

## fuzz-val-pbt: Run validation property-based testing
fuzz-val-pbt: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz='^FuzzValidationPBT$$' -fuzztime=5m ./fuzz/

## fuzz-val-pbt-td: Run validation PBT type-directed
fuzz-val-pbt-td: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz=FuzzValidationPBTTypeDirected -fuzztime=5m ./fuzz/

## fuzz-wildcard: Run wildcard pattern matching fuzzing (no Lean FFI calls but needs CGO for build)
fuzz-wildcard: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(SMT_ENV) \
	go test -fuzz=FuzzWildcardMatching -fuzztime=2m ./fuzz/

## fuzz-partial-eval: Run partial evaluation soundness fuzzing
fuzz-partial-eval: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz='^FuzzPartialEvaluation$$' -fuzztime=5m ./fuzz/

## fuzz-partial-eval-pbt: Run partial evaluation property-based testing
fuzz-partial-eval-pbt: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz=FuzzPartialEvaluationPBT -fuzztime=5m ./fuzz/

## fuzz-partial-eval-drt: Run partial evaluation DRT (compares cedar-go against Lean)
fuzz-partial-eval-drt: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz=FuzzPartialEvaluationDRT -fuzztime=5m ./fuzz/

## fuzz-residual-set-drt: Run ResidualSet API DRT (compares cedar-go against Lean)
fuzz-residual-set-drt: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz=FuzzResidualSetDRT -fuzztime=5m ./fuzz/

## fuzz-policy-cedar-to-json: Run policy Cedar->JSON conversion fuzzing (no Lean FFI calls but needs CGO for build)
fuzz-policy-cedar-to-json: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(SMT_ENV) \
	go test -fuzz=FuzzPolicyCedarToJSON -fuzztime=2m ./fuzz/

## fuzz-policy-json-to-cedar: Run policy JSON->Cedar conversion fuzzing (no Lean FFI calls but needs CGO for build)
fuzz-policy-json-to-cedar: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(SMT_ENV) \
	go test -fuzz=FuzzPolicyJSONToCedar -fuzztime=2m ./fuzz/

## fuzz-tpe-query-principal: Run TPE principal query fuzzing
fuzz-tpe-query-principal: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz=FuzzTPEQueryPrincipal -fuzztime=5m ./fuzz/

## fuzz-tpe-query-resource: Run TPE resource query fuzzing
fuzz-tpe-query-resource: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz=FuzzTPEQueryResource -fuzztime=5m ./fuzz/

## fuzz-tpe-query-action: Run TPE action query fuzzing
fuzz-tpe-query-action: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz=FuzzTPEQueryAction -fuzztime=5m ./fuzz/

## fuzz-tpe-query-multi: Run TPE multi-variable query fuzzing (Lean required)
fuzz-tpe-query-multi: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz=FuzzTPEQueryMultiVariable -fuzztime=5m ./fuzz/

## fuzz-tpe-query-context: Run TPE context query fuzzing (Lean required)
fuzz-tpe-query-context: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz='^FuzzTPEQueryContext$$' -fuzztime=5m ./fuzz/

## fuzz-tpe-query-context-field: Run TPE context field query fuzzing (Lean required)
fuzz-tpe-query-context-field: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz=FuzzTPEQueryContextField -fuzztime=5m ./fuzz/

## fuzz-entity-slicing: Run entity slicing fuzzing
fuzz-entity-slicing: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz='^FuzzEntitySlicing$$' -fuzztime=5m ./fuzz/

## fuzz-schema-resolution: Run schema resolution fuzzing
fuzz-schema-resolution: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz=FuzzSchemaResolution -fuzztime=5m ./fuzz/

## fuzz-input-generation: Run input generation fuzzing
fuzz-input-generation: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz='FuzzInputGeneration$$' -fuzztime=5m ./fuzz/

## fuzz-parser-crash: Run parser crash testing (no Lean FFI calls, but needs CGO for build)
## Tests that parsers don't panic on arbitrary/malformed input
fuzz-parser-crash: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(SMT_ENV) \
	go test -fuzz=FuzzPolicyParserCrash -fuzztime=2m ./fuzz/
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(SMT_ENV) \
	go test -fuzz=FuzzSchemaParser -fuzztime=2m ./fuzz/
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(SMT_ENV) \
	go test -fuzz=FuzzEntityUIDParser -fuzztime=2m ./fuzz/

## fuzz-schema-parser: Run schema parser crash testing (no Lean FFI calls, but needs CGO for build)
fuzz-schema-parser: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(SMT_ENV) \
	go test -fuzz=FuzzSchemaParser -fuzztime=2m ./fuzz/

## fuzz-schema-wf: Run schema well-formedness DRT (compares cedar-go against Lean)
## Tests that both implementations agree on what constitutes a well-formed schema
fuzz-schema-wf: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz='FuzzSchemaWellFormedness$$' -fuzztime=5m ./fuzz/

## fuzz-schema-wf-td: Run type-directed schema well-formedness DRT
fuzz-schema-wf-td: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz=FuzzSchemaWellFormednessTypeDirected -fuzztime=5m ./fuzz/

## fuzz-forbid-trumps: Run forbid_trumps_permit theorem fuzzing (property-based)
## Tests that if a forbid policy is satisfied, the decision must be deny
fuzz-forbid-trumps: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(SMT_ENV) \
	go test -fuzz=FuzzForbidTrumpsPermit -fuzztime=2m ./fuzz/

## fuzz-default-deny: Run default_deny theorem fuzzing (property-based)
## Tests that if no permit policy is satisfied, the decision must be deny
fuzz-default-deny: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(SMT_ENV) \
	go test -fuzz=FuzzDefaultDeny -fuzztime=2m ./fuzz/

## fuzz-order-dup: Run order_and_dup_independent theorem fuzzing (property-based)
## Tests that authorization is independent of policy order and duplicates
fuzz-order-dup: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(SMT_ENV) \
	go test -fuzz=FuzzOrderAndDupIndependent -fuzztime=2m ./fuzz/

## fuzz-denied-iff: Run denied_iff_explicitly_denied_or_not_permitted theorem fuzzing
## Tests that deny ↔ (explicitly forbidden ∨ ¬explicitly permitted)
fuzz-denied-iff: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(SMT_ENV) \
	go test -fuzz=FuzzDeniedIffExplicitlyDeniedOrNotPermitted -fuzztime=2m ./fuzz/

## fuzz-add-permit: Run unchanged_allow_when_add_permit theorem fuzzing
## Tests that adding a permit policy won't change an Allow decision
fuzz-add-permit: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(SMT_ENV) \
	go test -fuzz=FuzzUnchangedAllowWhenAddPermit -fuzztime=2m ./fuzz/

## fuzz-add-forbid: Run unchanged_deny_when_add_forbid theorem fuzzing
## Tests that adding a forbid policy won't change a Deny decision
fuzz-add-forbid: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(SMT_ENV) \
	go test -fuzz=FuzzUnchangedDenyWhenAddForbid -fuzztime=2m ./fuzz/

## fuzz-det-err-disjoint: Run determining_erroring_disjoint theorem fuzzing
## Tests that determining and erroring policy sets are always disjoint
fuzz-det-err-disjoint: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(SMT_ENV) \
	go test -fuzz=FuzzDeterminingErroringDisjoint -fuzztime=2m ./fuzz/

## fuzz-unchanged-det: Run unchanged_determining theorem fuzzing
## Tests that determining policies are preserved when adding a policy that doesn't change the decision
fuzz-unchanged-det: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(SMT_ENV) \
	go test -fuzz=FuzzUnchangedDeterminingWhenDecisionUnchanged -fuzztime=2m ./fuzz/

## fuzz-unchanged-err: Run unchanged_erroring theorem fuzzing
## Tests that erroring policies are preserved when adding any policy
fuzz-unchanged-err: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(SMT_ENV) \
	go test -fuzz=FuzzUnchangedErroringWhenAddPolicy -fuzztime=2m ./fuzz/

## fuzz-error-irrel: Run error_irrelevance theorem fuzzing
## Tests that erroring policies never influence the authorization decision
fuzz-error-irrel: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(SMT_ENV) \
	go test -fuzz=FuzzErrorIrrelevance -fuzztime=2m ./fuzz/

## fuzz-rm-forbid: Run removing_forbid_preserves_allow theorem fuzzing
## Tests that removing a forbid policy can never flip Allow to Deny
fuzz-rm-forbid: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(SMT_ENV) \
	go test -fuzz=FuzzRemovingForbidPreservesAllow -fuzztime=2m ./fuzz/

## fuzz-rm-permit: Run removing_permit_preserves_deny theorem fuzzing
## Tests that removing a permit policy can never flip Deny to Allow
fuzz-rm-permit: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(SMT_ENV) \
	go test -fuzz=FuzzRemovingPermitPreservesDeny -fuzztime=2m ./fuzz/

## fuzz-decomp: Run decision_decomposition theorem fuzzing
## Tests that decisions depend only on (∃ satisfied forbid, ∃ satisfied permit)
fuzz-decomp: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(SMT_ENV) \
	go test -fuzz=FuzzDecisionDecomposition -fuzztime=2m ./fuzz/

## fuzz-error-irrel-drt: Run error_irrelevance DRT (theorem + Lean comparison)
## Tests error_irrelevance against both cedar-go and Lean formalization
fuzz-error-irrel-drt: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz=FuzzErrorIrrelevanceDRT -fuzztime=5m ./fuzz/

## fuzz-rm-forbid-drt: Run removing_forbid_preserves_allow DRT (theorem + Lean comparison)
## Tests removing_forbid_preserves_allow against both cedar-go and Lean formalization
fuzz-rm-forbid-drt: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz=FuzzRemovingForbidPreservesAllowDRT -fuzztime=5m ./fuzz/

## fuzz-rm-permit-drt: Run removing_permit_preserves_deny DRT (theorem + Lean comparison)
## Tests removing_permit_preserves_deny against both cedar-go and Lean formalization
fuzz-rm-permit-drt: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz=FuzzRemovingPermitPreservesDenyDRT -fuzztime=5m ./fuzz/

## fuzz-decomp-drt: Run decision_decomposition DRT (theorem + Lean comparison)
## Tests decision_decomposition against both cedar-go and Lean formalization
fuzz-decomp-drt: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz=FuzzDecisionDecompositionDRT -fuzztime=5m ./fuzz/

## fuzz-tpe-drt: Run TPE DRT (compares cedar-go batch evaluation against Lean TPE)
fuzz-tpe-drt: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz='^FuzzTPEDRT$$' -fuzztime=5m ./fuzz/

## fuzz-tpe-soundness: Run TPE soundness fuzzing (batch result matches full evaluation)
fuzz-tpe-soundness: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz=FuzzTPESoundness -fuzztime=5m ./fuzz/

## fuzz-tpe-reauth: Run TPE reauthorize fuzzing (partial eval + full eval must match)
fuzz-tpe-reauth: proto
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(SMT_ENV) \
	go test -fuzz=FuzzTPEResidualReauthorize -fuzztime=5m ./fuzz/

## fuzz-symcc-never-errors: Run SymCC neverErrors fuzzing (requires cvc5)
## Tests that policies don't produce evaluation errors
fuzz-symcc-never-errors: proto
	@if [ -z "$(HAS_SMT_SOLVER)" ]; then echo "Error: No SMT solver found. Install cvc5 or z3."; exit 1; fi
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz='^FuzzSymCCNeverErrors$$' -fuzztime=5m $(FUZZ_PARALLEL_FLAG) ./fuzz/

## fuzz-symcc-always-matches: Run SymCC alwaysMatches fuzzing (requires cvc5)
## Tests that policy conditions always evaluate to true
fuzz-symcc-always-matches: proto
	@if [ -z "$(HAS_SMT_SOLVER)" ]; then echo "Error: No SMT solver found. Install cvc5 or z3."; exit 1; fi
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz='^FuzzSymCCAlwaysMatches$$' -fuzztime=5m $(FUZZ_PARALLEL_FLAG) ./fuzz/

## fuzz-symcc-never-matches: Run SymCC neverMatches fuzzing (requires cvc5)
## Tests that policy conditions never evaluate to true
fuzz-symcc-never-matches: proto
	@if [ -z "$(HAS_SMT_SOLVER)" ]; then echo "Error: No SMT solver found. Install cvc5 or z3."; exit 1; fi
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz='^FuzzSymCCNeverMatches$$' -fuzztime=5m $(FUZZ_PARALLEL_FLAG) ./fuzz/

## fuzz-symcc-always-allows: Run SymCC alwaysAllows fuzzing (requires cvc5)
## Tests that policy sets always allow requests
fuzz-symcc-always-allows: proto
	@if [ -z "$(HAS_SMT_SOLVER)" ]; then echo "Error: No SMT solver found. Install cvc5 or z3."; exit 1; fi
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz='^FuzzSymCCAlwaysAllows$$' -fuzztime=5m $(FUZZ_PARALLEL_FLAG) ./fuzz/

## fuzz-symcc-always-denies: Run SymCC alwaysDenies fuzzing (requires cvc5)
## Tests that policy sets always deny requests
fuzz-symcc-always-denies: proto
	@if [ -z "$(HAS_SMT_SOLVER)" ]; then echo "Error: No SMT solver found. Install cvc5 or z3."; exit 1; fi
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz='^FuzzSymCCAlwaysDenies$$' -fuzztime=5m $(FUZZ_PARALLEL_FLAG) ./fuzz/

## fuzz-symcc-matches-equiv: Run SymCC matchesEquivalent fuzzing (requires cvc5)
## Tests that two policies have equivalent conditions
fuzz-symcc-matches-equiv: proto
	@if [ -z "$(HAS_SMT_SOLVER)" ]; then echo "Error: No SMT solver found. Install cvc5 or z3."; exit 1; fi
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz='^FuzzSymCCMatchesEquivalent$$' -fuzztime=5m $(FUZZ_PARALLEL_FLAG) ./fuzz/

## fuzz-symcc-matches-implies: Run SymCC matchesImplies fuzzing (requires cvc5)
## Tests that one policy's condition implies another's
fuzz-symcc-matches-implies: proto
	@if [ -z "$(HAS_SMT_SOLVER)" ]; then echo "Error: No SMT solver found. Install cvc5 or z3."; exit 1; fi
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz='^FuzzSymCCMatchesImplies$$' -fuzztime=5m $(FUZZ_PARALLEL_FLAG) ./fuzz/

## fuzz-symcc-equiv: Run SymCC equivalent fuzzing (requires cvc5)
## Tests that two policy sets are equivalent
fuzz-symcc-equiv: proto
	@if [ -z "$(HAS_SMT_SOLVER)" ]; then echo "Error: No SMT solver found. Install cvc5 or z3."; exit 1; fi
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz='^FuzzSymCCEquivalent$$' -fuzztime=5m $(FUZZ_PARALLEL_FLAG) ./fuzz/

## fuzz-symcc-implies: Run SymCC implies fuzzing (requires cvc5)
## Tests that one policy set implies another
fuzz-symcc-implies: proto
	@if [ -z "$(HAS_SMT_SOLVER)" ]; then echo "Error: No SMT solver found. Install cvc5 or z3."; exit 1; fi
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz='^FuzzSymCCImplies$$' -fuzztime=5m $(FUZZ_PARALLEL_FLAG) ./fuzz/

## fuzz-symcc-matches-disjoint: Run SymCC matchesDisjoint fuzzing (requires cvc5)
## Tests that two policies' conditions are mutually exclusive
fuzz-symcc-matches-disjoint: proto
	@if [ -z "$(HAS_SMT_SOLVER)" ]; then echo "Error: No SMT solver found. Install cvc5 or z3."; exit 1; fi
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz='^FuzzSymCCMatchesDisjoint$$' -fuzztime=5m $(FUZZ_PARALLEL_FLAG) ./fuzz/

## fuzz-symcc-disjoint: Run SymCC disjoint fuzzing (requires cvc5)
## Tests that two policy sets never both allow the same request
fuzz-symcc-disjoint: proto
	@if [ -z "$(HAS_SMT_SOLVER)" ]; then echo "Error: No SMT solver found. Install cvc5 or z3."; exit 1; fi
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz='^FuzzSymCCDisjoint$$' -fuzztime=5m $(FUZZ_PARALLEL_FLAG) ./fuzz/

## fuzz-symcc-withcex: Run SymCC counterexample consistency fuzzing (requires cvc5)
## Verifies that base checks and WithCex variants agree
fuzz-symcc-withcex: proto
	@if [ -z "$(HAS_SMT_SOLVER)" ]; then echo "Error: No SMT solver found. Install cvc5 or z3."; exit 1; fi
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz='^FuzzSymCCWithCexConsistency$$' -fuzztime=5m $(FUZZ_PARALLEL_FLAG) ./fuzz/

## fuzz-symcc-all: Run stable SymCC fuzz targets (requires cvc5)
## Note: Run 'ulimit -n 10240' first to avoid "too many open files" errors
## Note: Some SymCC targets (alwaysMatches, alwaysAllows, alwaysDenies, etc.) can cause
##       cvc5 to hang on complex SMT queries. This target runs only the stable neverErrors test.
##       Use individual targets (fuzz-symcc-*) to run other tests with caution.
fuzz-symcc-all: proto
	@if [ -z "$(HAS_SMT_SOLVER)" ]; then echo "Error: No SMT solver found. Install cvc5 or z3."; exit 1; fi
	@echo "Running stable SymCC fuzz target (FuzzSymCCNeverErrors)..."
	@echo "Note: Other SymCC targets may hang on complex SMT queries."
	@echo "      Run them individually with 'make fuzz-symcc-<target>' if needed."
	@echo ""
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	$(SMT_ENV) \
	go test -fuzz='^FuzzSymCCNeverErrors$$' -fuzztime=$(SYMCC_FUZZTIME) $(FUZZ_PARALLEL_FLAG) ./fuzz/
	@echo ""
	@echo "Stable SymCC fuzz target completed!"
	@echo ""
	@echo "To run other SymCC targets individually (may hang on complex inputs):"
	@echo "  make fuzz-symcc-always-matches"
	@echo "  make fuzz-symcc-never-matches"
	@echo "  make fuzz-symcc-always-allows"
	@echo "  make fuzz-symcc-always-denies"
	@echo "  make fuzz-symcc-matches-equiv"
	@echo "  make fuzz-symcc-matches-implies"
	@echo "  make fuzz-symcc-equiv"
	@echo "  make fuzz-symcc-implies"

## run-drt: Run manual DRT test via CLI
run-drt: proto build
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CGO_COMPILE_FLAGS)" \
	CGO_LDFLAGS="$(CGO_LINK_FLAGS)" \
	$(DYLIB_PATH_VAR)="$(LEAN_BUILD_DIR):$(BATTERIES_BUILD_DIR):$(LEAN_SYSROOT)/lib/lean" \
	go run ./cmd/drt $(ARGS)

## clean: Clean build artifacts
clean:
	rm -rf $(PROTO_OUT_DIR)/*.pb.go
	go clean ./...

## help: Show this help
help:
	@echo "Cedar Go DRT - Differential Randomized Testing for cedar-go vs Lean"
	@echo ""
	@echo "Prerequisites:"
	@echo "  - Go 1.24+"
	@echo "  - elan (Lean toolchain manager)"
	@echo "  - protoc with protoc-gen-go"
	@echo "  - Lean libraries built: make lean"
	@echo ""
	@echo "Targets:"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'
	@echo ""
	@echo "Corpus Sources:"
	@echo "  The corpus loader supports multiple test data sources:"
	@echo "  - Cedar sandbox directories (cedar-policy/cedar-policy-cli/sample-data/tiny_sandboxes)"
	@echo "  - Raw .cedar policy files from the cedar repository"
	@echo "  - Cedar integration test suites (cedar-integration-tests repo)"
	@echo "  - Synthesized tests from Rust DRT (cedar-drt/corpus-tests)"
	@echo ""
	@echo "Environment:"
	@echo "  LEAN_BUILD_DIR      = $(LEAN_BUILD_DIR)"
	@echo "  BATTERIES_BUILD_DIR = $(BATTERIES_BUILD_DIR)"
	@echo "  LEAN_SYSROOT        = $(LEAN_SYSROOT)"
	@echo "  CEDAR_REPO          = $(CEDAR_REPO)"
