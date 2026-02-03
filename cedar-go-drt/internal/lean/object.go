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
#include <stdlib.h>
#include <string.h>

// go_create_byte_array creates a Lean byte array from a buffer.
// The data is copied into Lean-managed memory.
static inline lean_object* go_create_byte_array(const uint8_t* data, size_t len) {
    lean_object* arr = lean_alloc_sarray(1, len, len);
    if (arr != NULL && data != NULL && len > 0) {
        uint8_t* dst = lean_sarray_cptr(arr);
        memcpy(dst, data, len);
    }
    return arr;
}
*/
import "C"

import (
	"errors"
	"runtime"
	"unsafe"
)

// LeanObject wraps a Lean object pointer with automatic memory management.
// When the Go object is garbage collected, it will decrement the Lean
// object's reference count via a Go finalizer.
//
// LeanObject handles the impedance mismatch between Go's garbage collector
// and Lean's reference counting. You generally don't need to create these
// directly; use [NewLeanObjectFromBytes] or the FFI functions that return
// parsed responses.
//
// Thread Safety: LeanObject instances are not safe for concurrent use.
// Each LeanObject should only be accessed from the goroutine that created it.
type LeanObject struct {
	ptr *C.lean_object
}

// NewLeanObjectFromBytes creates a Lean byte array from Go bytes.
// The returned object owns the memory and will release it when garbage collected.
//
// This is used internally to pass protobuf-encoded requests to Lean FFI
// functions. The bytes are copied into Lean-managed memory, so the input
// slice can be modified or freed after this call.
//
// Example:
//
//	obj := lean.NewLeanObjectFromBytes(protoBytes)
//	// obj.ptr can be passed to Lean FFI functions
func NewLeanObjectFromBytes(data []byte) *LeanObject {
	var ptr *C.uint8_t
	if len(data) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&data[0]))
	}

	obj := &LeanObject{
		ptr: C.go_create_byte_array(ptr, C.size_t(len(data))),
	}

	runtime.SetFinalizer(obj, (*LeanObject).release)
	return obj
}

// newLeanObjectOwned wraps a Lean object pointer that the caller owns.
// The object will be released (reference count decremented) when the
// Go wrapper is garbage collected.
//
// This is used internally when receiving results from Lean FFI functions.
// The caller must own the reference (i.e., must eventually decrement it).
func newLeanObjectOwned(ptr *C.lean_object) *LeanObject {
	if ptr == nil {
		return nil
	}

	obj := &LeanObject{ptr: ptr}
	runtime.SetFinalizer(obj, (*LeanObject).release)
	return obj
}

// release decrements the reference count on the Lean object.
// Called automatically by the Go garbage collector via finalizer.
func (o *LeanObject) release() {
	if o.ptr != nil {
		C.lean_dec(o.ptr)
		o.ptr = nil
	}
}

// Ptr returns the underlying Lean object pointer.
// The caller must not store this pointer beyond the lifetime of the LeanObject.
//
// This is used internally when passing objects to Lean FFI functions.
func (o *LeanObject) Ptr() *C.lean_object {
	return o.ptr
}

// IsNil returns true if the object pointer is nil.
// A nil object represents an invalid or uninitialized Lean value.
func (o *LeanObject) IsNil() bool {
	return o == nil || o.ptr == nil
}

// Tag returns the constructor tag of the Lean object.
// For inductive types, the tag identifies which constructor was used.
//
// For example, Lean's Except type has:
//   - Tag 0: Error constructor
//   - Tag 1: Ok constructor
func (o *LeanObject) Tag() uint {
	if o.IsNil() {
		return 0
	}
	return uint(C.lean_ptr_tag(o.ptr))
}

// IsCtor returns true if the object is a constructor (inductive type).
// Constructor objects have fields that can be accessed with [GetCtorField].
func (o *LeanObject) IsCtor() bool {
	if o.IsNil() {
		return false
	}
	return bool(C.lean_is_ctor(o.ptr))
}

// GetCtorField returns the field at the given index from a constructor object.
// Returns nil if the object is not a constructor or index is out of bounds.
//
// The returned object is a new reference with its own finalizer; the caller
// does not need to manage its lifetime manually.
//
// Example:
//
//	// For an Except type, field 0 contains the value
//	field := obj.GetCtorField(0)
//	if field != nil {
//	    str, _ := field.AsString()
//	    fmt.Println(str)
//	}
func (o *LeanObject) GetCtorField(idx uint) *LeanObject {
	if !o.IsCtor() {
		return nil
	}

	field := C.lean_ctor_get(o.ptr, C.uint(idx))
	if field == nil {
		return nil
	}

	// Increment ref count since we're creating a new reference
	C.lean_inc(field)
	return newLeanObjectOwned(field)
}

// AsString extracts a Go string from a Lean string object.
// Returns an error if the object is not a Lean string.
//
// The returned string is a copy; it remains valid after the LeanObject
// is garbage collected.
func (o *LeanObject) AsString() (string, error) {
	if o.IsNil() {
		return "", errors.New("cannot convert nil Lean object to string")
	}

	if !C.lean_is_string(o.ptr) {
		return "", errors.New("lean object is not a string")
	}

	cstr := C.lean_string_cstr(o.ptr)
	return C.GoString(cstr), nil
}

// AsResult interprets the object as a Lean Except type.
// Lean's Except is equivalent to Go's Result pattern.
//
// Returns:
//   - (okValue, nil, nil) for Ok(value)
//   - (nil, errValue, nil) for Error(errValue)
//   - (nil, nil, error) if the object is not a valid Except
//
// Both okValue and errValue are new references that will be automatically
// cleaned up by the garbage collector.
//
// Example:
//
//	ok, err, parseErr := obj.AsResult()
//	if parseErr != nil {
//	    return parseErr
//	}
//	if err != nil {
//	    errMsg, _ := err.AsString()
//	    return fmt.Errorf("lean error: %s", errMsg)
//	}
//	// Use ok value...
func (o *LeanObject) AsResult() (*LeanObject, *LeanObject, error) {
	if !o.IsCtor() {
		return nil, nil, errors.New("lean object is not a constructor (expected Except)")
	}

	tag := o.Tag()
	field := o.GetCtorField(0)
	if field == nil {
		return nil, nil, errors.New("failed to get Except field")
	}

	switch tag {
	case 0: // Error
		return nil, field, nil
	case 1: // Ok
		return field, nil, nil
	default:
		field.release()
		return nil, nil, errors.New("unexpected Except constructor tag")
	}
}

// ForgetOwnership removes the finalizer from this object, transferring
// ownership to the caller. After calling this, the LeanObject wrapper
// becomes invalid and should not be used.
//
// This is used when passing objects to Lean FFI functions that take
// ownership of their arguments (indicated by lean_obj_arg in Lean).
// The Lean function will be responsible for decrementing the reference.
//
// Returns the raw Lean object pointer for passing to C functions.
func (o *LeanObject) ForgetOwnership() *C.lean_object {
	if o == nil {
		return nil
	}
	runtime.SetFinalizer(o, nil)
	ptr := o.ptr
	o.ptr = nil
	return ptr
}
