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

package typegen

import (
	"encoding/binary"
	"math/rand/v2"
)

// Rand wraps a random source for generation.
// It consumes bytes from the fuzzer input to make deterministic choices.
type Rand struct {
	data []byte
	pos  int
	rng  *rand.Rand
}

// NewRand creates a new Rand from fuzzer input bytes.
func NewRand(data []byte) *Rand {
	// Use first 8 bytes as seed if available
	var seed uint64
	if len(data) >= 8 {
		seed = binary.LittleEndian.Uint64(data[:8])
	}
	return &Rand{
		data: data,
		pos:  8,
		rng:  rand.New(rand.NewPCG(seed, seed^0xdeadbeef)), //nolint:gosec // Intentionally using weak random for deterministic fuzzing
	}
}

// Byte returns a random byte.
func (r *Rand) Byte() byte {
	if r.pos < len(r.data) {
		b := r.data[r.pos]
		r.pos++
		return b
	}
	return byte(r.rng.IntN(256))
}

// Intn returns a random int in [0, n).
func (r *Rand) Intn(n int) int {
	if n <= 0 {
		return 0
	}
	if r.pos < len(r.data) {
		b := r.Byte()
		return int(b) % n
	}
	return r.rng.IntN(n)
}

// Bool returns a random boolean.
func (r *Rand) Bool() bool {
	return r.Byte()&1 == 1
}

// Float64 returns a random float64 in [0.0, 1.0).
func (r *Rand) Float64() float64 {
	return r.rng.Float64()
}

// IntRange returns a random int in [min, max].
func (r *Rand) IntRange(min, max int) int {
	if min >= max {
		return min
	}
	return min + r.Intn(max-min+1)
}

// Choose returns a random element from the slice.
func Choose[T any](r *Rand, items []T) T {
	if len(items) == 0 {
		var zero T
		return zero
	}
	return items[r.Intn(len(items))]
}

// ChooseN returns n random elements from the slice (with replacement).
func ChooseN[T any](r *Rand, items []T, n int) []T {
	result := make([]T, n)
	for i := range n {
		result[i] = Choose(r, items)
	}
	return result
}

// Shuffle randomly reorders the slice in place.
func Shuffle[T any](r *Rand, items []T) {
	for i := len(items) - 1; i > 0; i-- {
		j := r.Intn(i + 1)
		items[i], items[j] = items[j], items[i]
	}
}

// String generates a random identifier-like string.
func (r *Rand) String(maxLen int) string {
	if maxLen <= 0 {
		maxLen = 8
	}
	length := r.IntRange(1, maxLen)
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	result := make([]byte, length)
	// First char must be letter
	result[0] = chars[r.Intn(len(chars))]
	chars += "0123456789_"
	for i := 1; i < length; i++ {
		result[i] = chars[r.Intn(len(chars))]
	}
	return string(result)
}

// Identifier generates a random Cedar identifier.
func (r *Rand) Identifier() string {
	return r.String(12)
}
