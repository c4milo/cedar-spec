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

// Package typegen provides type-directed test input generation for Cedar DRT.
// It generates schemas, entities, policies, and requests that are well-typed
// according to the schema, improving fuzzing effectiveness.
package typegen

// Settings controls the generation of schemas, entities, policies, and requests.
type Settings struct {
	// MaxDepth is the maximum nesting depth for types (sets, records).
	MaxDepth int

	// MaxWidth is the maximum number of elements in sets/records.
	MaxWidth int

	// MaxEntityTypes is the maximum number of entity types in a schema.
	MaxEntityTypes int

	// MaxActions is the maximum number of actions in a schema.
	MaxActions int

	// MaxAttributes is the maximum number of attributes per entity type.
	MaxAttributes int

	// MaxEntitiesPerType is the maximum number of entities per type.
	MaxEntitiesPerType int

	// EnableExtensions enables generation of extension types (decimal, ipaddr, etc.).
	EnableExtensions bool

	// MatchTypes ensures generated values match their declared types.
	MatchTypes bool
}

// DefaultSettings returns the default generation settings.
func DefaultSettings() Settings {
	return Settings{
		MaxDepth:           3,
		MaxWidth:           5,
		MaxEntityTypes:     4,
		MaxActions:         3,
		MaxAttributes:      4,
		MaxEntitiesPerType: 3,
		EnableExtensions:   true,
		MatchTypes:         true,
	}
}

// TypeDirectedSettings returns settings optimized for type-directed fuzzing.
func TypeDirectedSettings() Settings {
	return Settings{
		MaxDepth:           4,
		MaxWidth:           4,
		MaxEntityTypes:     5,
		MaxActions:         4,
		MaxAttributes:      5,
		MaxEntitiesPerType: 4,
		EnableExtensions:   true,
		MatchTypes:         true,
	}
}

// MinimalSettings returns minimal settings for quick generation.
func MinimalSettings() Settings {
	return Settings{
		MaxDepth:           2,
		MaxWidth:           3,
		MaxEntityTypes:     2,
		MaxActions:         2,
		MaxAttributes:      2,
		MaxEntitiesPerType: 2,
		EnableExtensions:   false,
		MatchTypes:         true,
	}
}
