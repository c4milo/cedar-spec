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

// Vendored Lean 4 Runtime Header
//
// This is a minimal header containing only the declarations needed for
// cedar-go-drt's CGO bindings. It provides forward declarations that are
// resolved at link time against the actual Lean runtime library (leanshared).
//
// The full Lean 4 runtime header is available in the Lean toolchain at:
//   $(elan which lean)/../lib/lean/include/lean/lean.h

#ifndef LEAN_LEAN_H
#define LEAN_LEAN_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

// Lean object is an opaque pointer type.
// The actual structure is managed by the Lean runtime.
typedef struct lean_object lean_object;

// Memory management - reference counting
void lean_inc(lean_object* o);
void lean_dec(lean_object* o);
void lean_dec_ref(lean_object* o);

// Runtime initialization
void lean_initialize_runtime_module_locked(void);
void lean_initialize_thread(void);
void lean_finalize_thread(void);
void lean_io_mark_end_initialization(void);
void lean_set_exit_on_panic(bool flag);

// IO operations
lean_object* lean_io_mk_world(void);
bool lean_io_result_is_ok(lean_object* r);
void lean_io_result_show_error(lean_object* r);

// Object type queries
unsigned lean_ptr_tag(lean_object* o);
bool lean_is_ctor(lean_object* o);
bool lean_is_string(lean_object* o);

// Constructor operations
lean_object* lean_ctor_get(lean_object* o, unsigned i);

// String operations
const char* lean_string_cstr(lean_object* o);

// Scalar array operations (for byte arrays)
lean_object* lean_alloc_sarray(unsigned elem_size, size_t size, size_t capacity);
uint8_t* lean_sarray_cptr(lean_object* o);

#ifdef __cplusplus
}
#endif

#endif // LEAN_LEAN_H
