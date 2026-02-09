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
//
// Unlike random byte mutation, type-directed generation produces inputs that
// are well-typed according to a generated schema, significantly improving
// fuzzing effectiveness by reaching deeper program states.
//
// # Generation Pipeline
//
// The generator follows a structured pipeline:
//
//  1. Schema generation — random entity types, actions, common types,
//     and attribute definitions with configurable hierarchy depth
//  2. Entity generation — entity instances conforming to the schema's
//     entity type definitions and membership constraints
//  3. Policy generation — Cedar policies referencing valid entity types,
//     actions, and attributes from the schema
//  4. Request generation — authorization requests with principal, action,
//     resource, and context matching schema expectations
//
// # Configuration
//
// Generation behavior is controlled by [Settings], which specifies bounds
// such as maximum entity types, actions, hierarchy depth, and attribute
// count. Use [DefaultSettings] for reasonable defaults or customize
// individual fields for targeted testing scenarios.
//
// # Entry Point
//
// The primary entry point is [TypeDirectedInputGenerator], which accepts
// a [*rand.Rand] source and [Settings], returning a complete set of
// well-typed Cedar inputs (schema, entities, policies, and requests)
// suitable for DRT corpus seeding.
package typegen
