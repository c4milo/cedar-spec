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

// Command init-corpus initializes the Go fuzz corpus from cedar-policy test data.
//
// This tool loads test cases from multiple sources similar to Rust DRT:
// - Cedar sandbox directories (tiny_sandboxes)
// - Raw .cedar policy files from the cedar repository
// - Cedar integration test suites
// - Synthesized test outputs from Rust DRT
//
// Usage:
//
//	# Basic usage - loads from cedar-policy repo
//	go run ./cmd/init-corpus -cedar-repo=/path/to/cedar
//
//	# Load from Rust DRT synthesized tests
//	# First run: cd ../cedar-drt && ./create_corpus.sh
//	go run ./cmd/init-corpus -synthesized=../cedar-drt/corpus-tests
//
//	# Load from all sources
//	go run ./cmd/init-corpus -cedar-repo=../cedar \
//	    -integration-tests=../cedar-integration-tests \
//	    -synthesized=../cedar-drt/corpus-tests
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cedar-policy/cedar-spec/cedar-go-drt/internal/corpus"
)

type config struct {
	cedarRepo           string
	integrationTestRepo string
	synthesizedTestDir  string
	outputDir           string
	validation          bool
	generateCount       int
	edgeCases           bool
	verbose             bool
}

func main() {
	cfg := parseFlags()
	if cfg.validation {
		runValidationCorpus(cfg)
	} else {
		runAuthorizationCorpus(cfg)
	}
}

func parseFlags() config {
	var (
		cedarRepo           = flag.String("cedar-repo", "", "Path to cedar-policy repo")
		integrationTestRepo = flag.String("integration-tests", "", "Path to cedar-integration-tests repo")
		synthesizedTestDir  = flag.String("synthesized", "", "Path to Rust DRT synthesized test output (corpus-tests/)")
		outputDir           = flag.String("output", "", "Output corpus directory (default: fuzz/testdata/fuzz/FuzzAuthorization)")
		validation          = flag.Bool("validation", false, "Generate validation corpus (schema+policies) instead of authorization")
		generateCount       = flag.Int("generate", 0, "Number of type-directed test cases to generate (0 = none)")
		edgeCases           = flag.Bool("edge-cases", false, "Include manually crafted edge case test cases")
		verbose             = flag.Bool("v", false, "Verbose output")
		help                = flag.Bool("help", false, "Show help")
	)
	flag.Parse()

	if *help {
		printUsage()
		os.Exit(0)
	}

	cfg := config{
		cedarRepo:           *cedarRepo,
		integrationTestRepo: *integrationTestRepo,
		synthesizedTestDir:  *synthesizedTestDir,
		outputDir:           *outputDir,
		validation:          *validation,
		generateCount:       *generateCount,
		edgeCases:           *edgeCases,
		verbose:             *verbose,
	}

	// Auto-detect paths
	cfg.autoDetectPaths()
	return cfg
}

func (c *config) autoDetectPaths() {
	if c.cedarRepo == "" {
		c.cedarRepo = autoDetectCedarRepo(c.verbose)
	}
	if c.integrationTestRepo == "" {
		c.integrationTestRepo = autoDetectIntegrationTestRepo(c.verbose)
	}
	if c.synthesizedTestDir == "" {
		c.synthesizedTestDir = autoDetectSynthesizedTestDir(c.verbose)
	}
	if c.outputDir == "" {
		if c.validation {
			c.outputDir = defaultValidationOutputDir()
		} else {
			c.outputDir = defaultOutputDir()
		}
	}
}

func (c *config) toLoadConfig() corpus.LoadConfig {
	return corpus.LoadConfig{
		CedarRepo:           c.cedarRepo,
		IntegrationTestRepo: c.integrationTestRepo,
		SynthesizedTestDir:  c.synthesizedTestDir,
		Verbose:             c.verbose,
	}
}

func runValidationCorpus(cfg config) {
	valCases, err := corpus.LoadAllValidationTests(cfg.toLoadConfig())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading validation tests: %v\n", err)
		os.Exit(1)
	}

	if cfg.generateCount > 0 {
		generated := corpus.GenerateValidationCases(cfg.generateCount, cfg.verbose)
		valCases = append(valCases, generated...)
	}

	if err := corpus.WriteValidationCorpus(valCases, cfg.outputDir); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing validation corpus: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Wrote %d validation corpus entries to %s\n", len(valCases), cfg.outputDir)
}

func runAuthorizationCorpus(cfg config) {
	cases := loadAndMergeCorpus(cfg.toLoadConfig(), cfg.outputDir, cfg.verbose)

	if cfg.generateCount > 0 {
		generated := corpus.GenerateTypeDirectedCases(cfg.generateCount, cfg.verbose)
		cases = append(cases, generated...)
	}

	if cfg.edgeCases {
		edgeCaseList := corpus.GenerateEdgeCases()
		if cfg.verbose {
			fmt.Printf("Added %d edge case test cases\n", len(edgeCaseList))
		}
		cases = append(cases, edgeCaseList...)
	}

	if err := corpus.WriteCorpus(cases, cfg.outputDir); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing corpus: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Wrote %d corpus entries to %s\n", len(cases), cfg.outputDir)
}

// autoDetectCedarRepo tries to find the cedar-policy repo in common locations.
func autoDetectCedarRepo(verbose bool) string {
	candidates := []string{
		"/tmp/cedar-policy",
		"../cedar",
		"../../cedar",
		filepath.Join(os.Getenv("HOME"), "cedar"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(filepath.Join(c, "cedar-policy")); err == nil {
			if verbose {
				fmt.Printf("Auto-detected cedar repo at: %s\n", c)
			}
			return c
		}
	}
	fmt.Fprintf(os.Stderr, "Warning: Could not find cedar-policy repo. Use -cedar-repo to specify.\n")
	return ""
}

// autoDetectIntegrationTestRepo tries to find the cedar-integration-tests repo.
func autoDetectIntegrationTestRepo(verbose bool) string {
	candidates := []string{
		"../cedar-integration-tests",
		"../../cedar-integration-tests",
		filepath.Join(os.Getenv("HOME"), "cedar-integration-tests"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(filepath.Join(c, "tests")); err == nil {
			if verbose {
				fmt.Printf("Auto-detected integration tests at: %s\n", c)
			}
			return c
		}
	}
	return ""
}

// autoDetectSynthesizedTestDir tries to find the Rust DRT synthesized test output.
func autoDetectSynthesizedTestDir(verbose bool) string {
	candidates := []string{
		"../cedar-drt/corpus-tests",
		"../../cedar-drt/corpus-tests",
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			if verbose {
				fmt.Printf("Auto-detected synthesized tests at: %s\n", c)
			}
			return c
		}
	}
	return ""
}

// defaultOutputDir returns the default output directory for the authorization corpus.
func defaultOutputDir() string {
	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting working directory: %v\n", err)
		os.Exit(1)
	}
	return filepath.Join(wd, "fuzz", "testdata", "fuzz", "FuzzAuthorization")
}

// defaultValidationOutputDir returns the default output directory for the validation corpus.
func defaultValidationOutputDir() string {
	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting working directory: %v\n", err)
		os.Exit(1)
	}
	return filepath.Join(wd, "fuzz", "testdata", "fuzz", "FuzzValidation")
}

// loadAndMergeCorpus loads test cases from all sources and merges with existing seeds.
func loadAndMergeCorpus(cfg corpus.LoadConfig, outputDir string, verbose bool) []corpus.TestCase {
	if verbose {
		fmt.Println("Loading test cases from all sources...")
	}

	cases, err := corpus.LoadAll(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading test cases: %v\n", err)
		os.Exit(1)
	}

	if verbose {
		fmt.Printf("Total test cases loaded: %d\n", len(cases))
	}

	existingSeeds := loadExistingSeeds(filepath.Dir(outputDir))
	if verbose && len(existingSeeds) > 0 {
		fmt.Printf("Found %d existing seed files\n", len(existingSeeds))
	}

	return append(cases, existingSeeds...)
}

func loadExistingSeeds(testdataDir string) []corpus.TestCase {
	pattern := filepath.Join(testdataDir, "seed_*.json")
	files, _ := filepath.Glob(pattern)

	var cases []corpus.TestCase
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}

		var tc corpus.TestCase
		if err := json.Unmarshal(data, &tc); err != nil {
			continue
		}
		cases = append(cases, tc)
	}
	return cases
}

func printUsage() {
	fmt.Println(`init-corpus - Initialize Go fuzz corpus from Cedar test data

DESCRIPTION
    Loads test cases from multiple sources and converts them to Go's native
    fuzz corpus format. The corpus is used by 'go test -fuzz' to seed the
    fuzzer with valid Cedar inputs.

SOURCES
    The tool can load test cases from:

    1. Cedar sandbox directories (tiny_sandboxes)
       Located at: {cedar-repo}/cedar-policy-cli/sample-data/tiny_sandboxes

    2. Raw .cedar policy files
       All .cedar files found recursively in the cedar-policy repo

    3. Cedar integration test suites
       Located at: {integration-tests}/tests

    4. Rust DRT synthesized tests
       Generated by: cd ../cedar-drt && ./create_corpus.sh
       Output at: ../cedar-drt/corpus-tests/

USAGE
    # Basic - load from cedar-policy repo
    go run ./cmd/init-corpus -cedar-repo=../cedar -v

    # Include Rust DRT corpus (run create_corpus.sh first)
    go run ./cmd/init-corpus -synthesized=../cedar-drt/corpus-tests -v

    # All sources
    go run ./cmd/init-corpus \
        -cedar-repo=../cedar \
        -integration-tests=../cedar-integration-tests \
        -synthesized=../cedar-drt/corpus-tests \
        -v

    # Or use Makefile targets
    make corpus           # Basic corpus
    make corpus-from-drt  # Include Rust DRT
    make corpus-full      # All sources

FLAGS`)
	flag.PrintDefaults()
}
