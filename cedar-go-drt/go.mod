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

module github.com/cedar-policy/cedar-spec/cedar-go-drt

go 1.24

require (
	github.com/cedar-policy/cedar-go v1.4.1
	google.golang.org/protobuf v1.36.11
)

require golang.org/x/exp v0.0.0-20240222234643-814bf88cf225 // indirect

// Use local fork of cedar-go with validator package
replace github.com/cedar-policy/cedar-go => /Users/camiloaguilar/Projects/c4milo/cedar-go
