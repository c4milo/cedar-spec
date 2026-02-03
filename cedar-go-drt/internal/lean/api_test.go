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

import "testing"

// TestAPIExports verifies that exported API functions exist and are callable.
// These functions are intentionally kept for library users even if not used internally.
func TestAPIExports(t *testing.T) {
	// Test WithLeanThread - executes the callback in a Lean thread context
	err := WithLeanThread(func() error {
		// Just verify we can enter and exit a Lean thread
		return nil
	})
	if err != nil {
		t.Logf("WithLeanThread error (expected if Lean not initialized): %v", err)
	}

	// Test RunSafe - similar but passes the LeanThread handle
	err = RunSafe(func(lt *LeanThread) error {
		// Verify we receive a valid LeanThread
		if lt == nil {
			t.Error("RunSafe passed nil LeanThread")
		}
		return nil
	})
	if err != nil {
		t.Logf("RunSafe error (expected if Lean not initialized): %v", err)
	}
}
