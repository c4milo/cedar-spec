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
#include <lean/lean.h>

// Lean runtime initialization functions - not declared in lean.h but exported from libleanshared
extern void lean_initialize_runtime_module(void);
extern void lean_initialize_thread(void);
extern void lean_finalize_thread(void);
extern void lean_io_mark_end_initialization(void);

// CedarFFI initialization function
// As of Lean 4.27.0 / Lake, the init symbol is prefixed with the package name
extern lean_object* initialize_Cedar_CedarFFI_Main(uint8_t builtin, lean_object* ob);
*/
import "C"

import (
	"fmt"
	"runtime"
	"sync"
)

var (
	// initOnce ensures the Lean runtime is initialized exactly once.
	initOnce sync.Once

	// initErr stores any error from Lean runtime initialization.
	initErr error
)

// Initialize initializes the Lean runtime. This must be called before any
// other Lean FFI functions. It is safe to call multiple times; initialization
// only happens once per process.
//
// The function initializes:
//   - The Lean runtime module
//   - The CedarFFI Lean library
//   - Lean's panic behavior (exit on panic)
//
// Returns an error if initialization fails. Once initialization succeeds,
// subsequent calls return nil immediately.
//
// Example:
//
//	if err := lean.Initialize(); err != nil {
//	    log.Fatalf("Failed to initialize Lean: %v", err)
//	}
func Initialize() error {
	initOnce.Do(func() {
		// Lock to OS thread during initialization
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		// Initialize Lean runtime
		C.lean_initialize_runtime_module()

		// Initialize CedarFFI module
		// builtin=1 indicates this is a builtin module initialization
		world := C.lean_io_mk_world()
		res := C.initialize_Cedar_CedarFFI_Main(1, world)

		if C.lean_io_result_is_ok(res) {
			C.lean_dec_ref(res)
		} else {
			C.lean_io_result_show_error(res)
			C.lean_dec(res)
			initErr = fmt.Errorf("failed to initialize Lean CedarFFI module")
			return
		}

		// Mark end of initialization phase
		C.lean_io_mark_end_initialization()

		// Configure Lean to exit on panic rather than continuing
		C.lean_set_exit_on_panic(true)
	})

	return initErr
}

// LeanThread represents a Lean execution context bound to an OS thread.
// All Lean FFI calls must be made from within a LeanThread context.
//
// Lean uses thread-local state for memory management and garbage collection.
// Each goroutine that calls Lean functions must:
//  1. Be locked to an OS thread (runtime.LockOSThread)
//  2. Initialize a Lean thread context (NewLeanThread)
//  3. Finalize the context when done (Close)
//
// Use [WithLeanThread] for automatic management, or create threads manually
// for multiple operations in the same context.
type LeanThread struct {
	initialized bool
}

// NewLeanThread creates a new Lean thread context. The caller must be
// locked to the current OS thread (runtime.LockOSThread) before calling this.
//
// The returned LeanThread must be closed when no longer needed by calling
// Close, typically via defer:
//
//	runtime.LockOSThread()
//	defer runtime.UnlockOSThread()
//
//	lt, err := lean.NewLeanThread()
//	if err != nil {
//	    return err
//	}
//	defer lt.Close()
//
//	// Now safe to call Lean FFI functions
//	resp, err := lean.IsAuthorized(protoBytes)
//
// Returns an error if Lean runtime initialization fails.
func NewLeanThread() (*LeanThread, error) {
	if err := Initialize(); err != nil {
		return nil, err
	}

	C.lean_initialize_thread()

	return &LeanThread{initialized: true}, nil
}

// Close finalizes the Lean thread context, releasing thread-local resources.
// This must be called when done with the thread, typically via defer.
//
// After Close is called, no further Lean FFI calls should be made from
// this thread context. It is safe to call Close multiple times.
func (lt *LeanThread) Close() {
	if lt.initialized {
		C.lean_finalize_thread()
		lt.initialized = false
	}
}

// WithLeanThread executes a function within a Lean thread context.
// It handles OS thread locking and Lean thread initialization/finalization
// automatically.
//
// This is the simplest way to call Lean FFI functions:
//
//	err := lean.WithLeanThread(func() error {
//	    resp, err := lean.IsAuthorized(protoBytes)
//	    if err != nil {
//	        return err
//	    }
//	    fmt.Printf("Decision: %s\n", resp.Decision)
//	    return nil
//	})
//
// The function locks the calling goroutine to an OS thread for the duration
// of fn. If you need to make multiple Lean calls, they will all execute on
// the same thread within the same context.
//
// Returns any error from Lean initialization or from the provided function.
func WithLeanThread(fn func() error) error {
	// Lock to OS thread - Lean requires thread affinity
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	lt, err := NewLeanThread()
	if err != nil {
		return err
	}
	defer lt.Close()

	return fn()
}

// RunSafe executes multiple FFI operations in a single locked thread context.
// This is more efficient than calling [WithLeanThread] for each operation
// when you need to perform several Lean calls.
//
// The LeanThread passed to fn is already initialized and will be closed
// automatically after fn returns.
//
// Example:
//
//	err := lean.RunSafe(func(lt *lean.LeanThread) error {
//	    resp1, err := lean.IsAuthorized(req1)
//	    if err != nil {
//	        return err
//	    }
//	    resp2, err := lean.Validate(req2)
//	    if err != nil {
//	        return err
//	    }
//	    // Process responses...
//	    return nil
//	})
func RunSafe(fn func(*LeanThread) error) error {
	return WithLeanThread(func() error {
		lt := &LeanThread{initialized: true}
		return fn(lt)
	})
}
