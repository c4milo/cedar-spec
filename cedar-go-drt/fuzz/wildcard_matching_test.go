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

package fuzz

import (
	"regexp"
	"testing"

	"github.com/cedar-policy/cedar-go/types"

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/typegen"
)

// FuzzWildcardMatching tests Cedar's wildcard pattern matching against a
// regex-based reference implementation. This ensures the `like` operator
// behaves correctly for all valid Unicode inputs.
//
// The test generates random patterns (with literal characters and wildcards)
// and strings, then verifies that Cedar's Pattern.Match produces the same
// result as an equivalent regex match.
func FuzzWildcardMatching(f *testing.F) {
	// Add seed patterns and strings
	f.Add([]byte("pattern-test-1"))
	f.Add([]byte("*hello*world*"))
	f.Add([]byte("abc"))
	f.Add(make([]byte, 32))
	f.Add(make([]byte, 64))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 4 {
			return
		}

		r := typegen.NewRand(data)

		// Generate a pattern
		pattern := generatePattern(r)

		// Generate a string that might match the pattern
		testString := generateTestString(r, pattern)

		// Test with Cedar's Pattern.Match
		cedarPattern := buildCedarPattern(pattern)
		cedarResult := cedarPattern.Match(types.String(testString))

		// Test with regex reference implementation
		regexResult := matchWithRegex(pattern, testString)

		// Compare results
		if cedarResult != regexResult {
			t.Errorf("Wildcard matching divergence!\n"+
				"Pattern: %v\n"+
				"String: %q\n"+
				"Cedar result: %v\n"+
				"Regex result: %v",
				pattern, testString, cedarResult, regexResult)
		}
	})
}

// PatternElem represents an element in a wildcard pattern.
type PatternElem struct {
	IsWildcard bool
	Char       rune
}

// generatePattern creates a random pattern with wildcards and literal characters.
func generatePattern(r *typegen.Rand) []PatternElem {
	length := r.IntRange(0, 10)
	pattern := make([]PatternElem, 0, length)

	for range length {
		if r.IntRange(0, 4) == 0 { // 25% chance of wildcard
			pattern = append(pattern, PatternElem{IsWildcard: true})
		} else {
			// Generate a valid character
			ch := generateValidChar(r)
			pattern = append(pattern, PatternElem{IsWildcard: false, Char: ch})
		}
	}

	return pattern
}

// generateValidChar generates a valid Unicode character in the BMP.
// Excludes surrogate code points (U+D800–U+DFFF).
func generateValidChar(r *typegen.Rand) rune {
	// Generate a value in the BMP, excluding surrogates
	for {
		v := r.IntRange(0, 0xFFFF)
		if v < 0xD800 || v > 0xDFFF {
			return rune(v)
		}
	}
}

// generateTestString creates a string that may or may not match the pattern.
func generateTestString(r *typegen.Rand, pattern []PatternElem) string {
	var result []rune

	for _, elem := range pattern {
		if elem.IsWildcard {
			// For wildcards, generate 0-3 random characters
			count := r.IntRange(0, 3)
			for range count {
				result = append(result, generateValidChar(r))
			}
		} else {
			// For literal chars, sometimes keep, sometimes drop, sometimes replace
			choice := r.IntRange(0, 3)
			switch choice {
			case 0, 1, 2: // 75% - keep the character
				result = append(result, elem.Char)
			case 3: // 25% - replace with random char
				result = append(result, generateValidChar(r))
			}
		}
	}

	return string(result)
}

// buildCedarPattern converts our pattern representation to a Cedar Pattern.
func buildCedarPattern(pattern []PatternElem) types.Pattern {
	components := make([]any, 0, len(pattern))

	for _, elem := range pattern {
		if elem.IsWildcard {
			components = append(components, types.Wildcard{})
		} else {
			// Cedar patterns expect individual characters or strings
			components = append(components, string(elem.Char))
		}
	}

	return types.NewPattern(components...)
}

// matchWithRegex implements pattern matching using regex as a reference.
func matchWithRegex(pattern []PatternElem, text string) bool {
	// Build regex pattern
	var regexPattern string
	regexPattern = "^"

	for _, elem := range pattern {
		if elem.IsWildcard {
			// Wildcard matches any sequence including newlines
			regexPattern += "(?s:.)*"
		} else {
			// Escape the character for regex
			regexPattern += regexp.QuoteMeta(string(elem.Char))
		}
	}

	regexPattern += "$"

	re, err := regexp.Compile(regexPattern)
	if err != nil {
		// If regex compilation fails, return false
		return false
	}

	return re.MatchString(text)
}

// TestWildcardMatchingBasic tests basic wildcard matching scenarios.
func TestWildcardMatchingBasic(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		text     string
		expected bool
	}{
		{"exact match", "hello", "hello", true},
		{"exact mismatch", "hello", "world", false},
		{"wildcard any", "*", "anything", true},
		{"wildcard empty", "*", "", true},
		{"wildcard prefix", "hello*", "hello world", true},
		{"wildcard suffix", "*world", "hello world", true},
		{"wildcard middle", "h*d", "hello world", true},
		{"multiple wildcards", "*e*o*", "hello", true},
		{"no match", "abc", "def", false},
		{"partial match", "abc", "ab", false},
		{"longer text", "ab", "abc", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pattern := parsePatternString(tc.pattern)
			cedarPattern := buildCedarPattern(pattern)
			result := cedarPattern.Match(types.String(tc.text))

			if result != tc.expected {
				t.Errorf("Pattern %q, text %q: got %v, want %v",
					tc.pattern, tc.text, result, tc.expected)
			}

			// Also verify regex reference matches
			regexResult := matchWithRegex(pattern, tc.text)
			if regexResult != tc.expected {
				t.Errorf("Regex reference for pattern %q, text %q: got %v, want %v",
					tc.pattern, tc.text, regexResult, tc.expected)
			}
		})
	}
}

// parsePatternString converts a simple pattern string to PatternElem slice.
// '*' represents wildcard, other characters are literals.
func parsePatternString(s string) []PatternElem {
	var pattern []PatternElem
	for _, ch := range s {
		if ch == '*' {
			pattern = append(pattern, PatternElem{IsWildcard: true})
		} else {
			pattern = append(pattern, PatternElem{IsWildcard: false, Char: ch})
		}
	}
	return pattern
}

// TestWildcardMatchingUnicode tests wildcard matching with Unicode characters.
func TestWildcardMatchingUnicode(t *testing.T) {
	tests := []struct {
		name     string
		pattern  []PatternElem
		text     string
		expected bool
	}{
		{
			name: "unicode literal match",
			pattern: []PatternElem{
				{Char: '日'},
				{Char: '本'},
				{Char: '語'},
			},
			text:     "日本語",
			expected: true,
		},
		{
			name: "unicode with wildcard",
			pattern: []PatternElem{
				{Char: '日'},
				{IsWildcard: true},
				{Char: '語'},
			},
			text:     "日本語",
			expected: true,
		},
		{
			name: "emoji pattern",
			pattern: []PatternElem{
				{Char: '👋'},
				{IsWildcard: true},
			},
			text:     "👋🌍",
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cedarPattern := buildCedarPattern(tc.pattern)
			result := cedarPattern.Match(types.String(tc.text))

			if result != tc.expected {
				t.Errorf("got %v, want %v", result, tc.expected)
			}
		})
	}
}

