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

package lean

/*
// Note: CFLAGS and LDFLAGS are provided via Makefile CGO_CFLAGS and CGO_LDFLAGS
// to allow flexibility in Lean installation paths. The header path is:
// -I$(LEAN_SYSROOT)/include
// The libraries linked are:
// -lCedarFFI -lCedarProto -lCedar -lCedar_SymCC -lProtobuf -lBatteries -lleanshared

#include <lean/lean.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Forward declarations of Lean FFI functions
extern lean_object* isAuthorized(lean_object* req);
extern lean_object* validate(lean_object* req);
extern lean_object* levelValidate(lean_object* req);
extern lean_object* validateEntities(lean_object* req);
extern lean_object* validateRequest(lean_object* req);
extern lean_object* checkEvaluate(lean_object* req);
extern lean_object* initialize_Cedar_CedarFFI_Main(uint8_t builtin, lean_object* ob);

// Helper to check if Lean IO result is OK
static inline int lean_io_is_ok(lean_object* o) {
    return lean_io_result_is_ok(o);
}

// Helper to create IO world
static inline lean_object* lean_mk_world() {
    return lean_io_mk_world();
}

// Helper to show IO error
static inline void lean_show_error(lean_object* o) {
    lean_io_result_show_error(o);
}

// Create a Lean byte array from Go bytes
static inline lean_object* go_create_byte_array(const uint8_t* data, size_t len) {
    lean_object* arr = lean_alloc_sarray(1, len, len);
    if (arr != NULL && data != NULL && len > 0) {
        uint8_t* dst = lean_sarray_cptr(arr);
        memcpy(dst, data, len);
    }
    return arr;
}

// Decrement reference count
static inline void go_lean_dec(lean_object* o) {
    lean_dec(o);
}
*/
import "C"
