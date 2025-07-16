package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype"
	v6dist "github.com/anchore/grype/grype/db/v6/distribution"
	v6inst "github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/models"
)

func main() {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		log.Fatalf("Failed to get current file path using runtime.Caller(0).")
	}

	sourceFileDir := filepath.Dir(filename)

	inputDir := filepath.Join(sourceFileDir, "..", "inputs")
	outputDir := filepath.Join(sourceFileDir, "latest")

	if _, err := os.Stat(inputDir); os.IsNotExist(err) {
		log.Fatalf("Input directory does not exist: %s.", inputDir)
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory %s: %v", outputDir, err)
	}

	distCfg := v6dist.DefaultConfig()
	instCfg := v6inst.DefaultConfig(clio.Identification{Name: "grype-bench", Version: "dev"})
	vp, _, err := grype.LoadVulnerabilityDB(distCfg, instCfg, true)
	if err != nil {
		log.Fatalf("failed to load vulnerability DB: %v", err)
	}

	matchers := matcher.NewDefaultMatchers(matcher.Config{})

	dirEntries, err := os.ReadDir(inputDir)
	if err != nil {
		log.Fatalf("failed to read inputs directory: %v", err)
	}

	for _, entry := range dirEntries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name == "README.md" || !strings.HasSuffix(name, ".json") {
			continue
		}
		inputPath := filepath.Join(inputDir, name)
		outputPath := filepath.Join(outputDir, name+".vulns.json")

		pkgs, ctx, _, err := pkg.Provide(inputPath, pkg.ProviderConfig{})
		if err != nil {
			log.Printf("failed to load SBOM %s: %v", name, err)
			continue
		}

		runner := grype.VulnerabilityMatcher{
			VulnerabilityProvider: vp,
			Matchers:              matchers,
		}
		matches, _, err := runner.FindMatches(pkgs, ctx)
		if err != nil {
			log.Printf("failed to match vulnerabilities for %s: %v", name, err)
			continue
		}

		doc, err := models.NewDocument(
			clio.Identification{Name: "grype", Version: "[not provided]"},
			pkgs, ctx, *matches, nil, models.NewMetadataMock(), nil, nil, models.SortByPackage,
		)
		if err != nil {
			log.Printf("failed to create document for %s: %v", name, err)
			continue
		}

		output, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			log.Printf("failed to marshal document for %s: %v", name, err)
			continue
		}

		if err := os.WriteFile(outputPath, output, 0o644); err != nil {
			log.Printf("failed to write output for %s: %v", name, err)
			continue
		}
		log.Printf("Wrote: %s", outputPath)
	}
}
