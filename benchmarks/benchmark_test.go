package benchmarks

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype"
	v6dist "github.com/anchore/grype/grype/db/v6/distribution"
	v6inst "github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/stretchr/testify/assert"
)

var timestampRegexp = regexp.MustCompile(`"timestamp":\s*"[^"]+"`)

func redact(content []byte) []byte {
	return timestampRegexp.ReplaceAll(content, []byte(`"timestamp":""`))
}

func extractAndSortVulnerabilityIDs(docBytes []byte) ([]string, error) {
	var doc map[string]any
	if err := json.Unmarshal(docBytes, &doc); err != nil {
		return nil, err
	}
	matches, ok := doc["matches"].([]any)
	if !ok {
		return nil, nil // no matches
	}
	ids := make([]string, 0, len(matches))
	for _, m := range matches {
		matchObj, ok := m.(map[string]any)
		if !ok {
			continue
		}
		vuln, ok := matchObj["vulnerability"].(map[string]any)
		if !ok {
			continue
		}
		id, ok := vuln["id"].(string)
		if !ok {
			continue
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}

// benchmarkResults stores results for each SBOM
type benchmarkResult struct {
	vulnCount int
	avgTime   time.Duration
}

var benchmarkResults = make(map[string]benchmarkResult)

// BenchmarkEndToEndRealSBOMs runs end-to-end scans using all SBOMs in benchmarks/inputs/.
func BenchmarkEndToEndRealSBOMs(b *testing.B) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		b.Fatalf("Failed to get current file path using runtime.Caller(0).")
	}

	sourceFileDir := filepath.Dir(filename)
	inputDir := filepath.Join(sourceFileDir, "inputs")
	goldenDir := filepath.Join(sourceFileDir, "golden", "latest")

	files, err := filepath.Glob(filepath.Join(inputDir, "*.cdx.json"))
	if err != nil || len(files) == 0 {
		b.Skipf("No SBOM files found in benchmarks/inputs/: %v", err)
	}

	// Ensure the vulnerability DB is present (download if needed)
	distCfg := v6dist.DefaultConfig()
	instCfg := v6inst.DefaultConfig(clio.Identification{Name: "grype-bench", Version: "dev"})
	vp, _, err := grype.LoadVulnerabilityDB(distCfg, instCfg, true)
	if err != nil {
		b.Fatalf("failed to load vulnerability DB: %v", err)
	}

	matchers := matcher.NewDefaultMatchers(matcher.Config{})

	for _, sbomPath := range files {
		b.Run(filepath.Base(sbomPath), func(b *testing.B) {
			var totalTime time.Duration
			var vulnCount int
			b.ResetTimer()
			for i := 0; b.Loop(); i++ {
				start := time.Now()
				pkgs, ctx, _, err := pkg.Provide(sbomPath, pkg.ProviderConfig{})
				if err != nil {
					b.Fatalf("failed to load SBOM %s: %v", sbomPath, err)
				}

				runner := grype.VulnerabilityMatcher{
					VulnerabilityProvider: vp,
					Matchers:              matchers,
				}
				matches, _, err := runner.FindMatches(pkgs, ctx)
				if err != nil {
					b.Fatalf("failed to match vulnerabilities for %s: %v", sbomPath, err)
				}

				totalTime += time.Since(start)

				// Compare to golden file
				doc, err := models.NewDocument(
					clio.Identification{Name: "grype", Version: "[not provided]"},
					pkgs, ctx, *matches, nil, models.NewMetadataMock(), nil, nil, models.SortByPackage,
				)
				if err != nil {
					b.Fatalf("failed to create document: %v", err)
				}

				actual, err := json.MarshalIndent(doc, "", "  ")
				if err != nil {
					b.Fatalf("failed to marshal actual document: %v", err)
				}
				actual = redact(actual)

				goldenPath := filepath.Join(goldenDir, filepath.Base(sbomPath)+".vulns.json")
				expected, err := os.ReadFile(goldenPath)
				if err != nil {
					b.Fatalf("failed to read golden file %s: %v", goldenPath, err)
				}
				expected = redact(expected)

				// Only compare the set of vulnerability IDs
				actualIDs, err := extractAndSortVulnerabilityIDs(actual)
				if err != nil {
					b.Fatalf("failed to extract actual vulnerability IDs: %v", err)
				}
				expectedIDs, err := extractAndSortVulnerabilityIDs(expected)
				if err != nil {
					b.Fatalf("failed to extract expected vulnerability IDs: %v", err)
				}

				// Store results for summary table (only on first iteration)
				if i == 0 {
					vulnCount = len(actualIDs)
				}

				if !assert.ObjectsAreEqual(expectedIDs, actualIDs) {
					goldenOnly := difference(expectedIDs, actualIDs)
					actualOnly := difference(actualIDs, expectedIDs)
					if len(goldenOnly) > 0 {
						b.Logf("IDs only in golden:   %v", goldenOnly)
					}
					if len(actualOnly) > 0 {
						b.Logf("IDs only in benchmark: %v", actualOnly)
					}
					b.Fatalf("vulnerability IDs do not match for %s", sbomPath)
				}
			}

			// Store benchmark results
			benchmarkResults[filepath.Base(sbomPath)] = benchmarkResult{
				vulnCount: vulnCount,
				avgTime:   totalTime / time.Duration(b.N),
			}
		})
	}

	// Print summary table in verbose mode
	if testing.Verbose() {
		printVulnerabilitySummaryTable(b)
	}
}

func printVulnerabilitySummaryTable(b *testing.B) {
	if len(benchmarkResults) == 0 {
		return
	}

	// Sort files by name for consistent output
	var files []string
	for file := range benchmarkResults {
		files = append(files, file)
	}
	sort.Strings(files)

	// Calculate column widths
	maxFileWidth := 0
	for _, file := range files {
		if len(file) > maxFileWidth {
			maxFileWidth = len(file)
		}
	}
	// Ensure minimum width for "SBOM File" header
	if maxFileWidth < 9 {
		maxFileWidth = 9
	}

	// Print table header
	b.Logf("")
	b.Logf("Benchmark Summary:")
	b.Logf("┌─%s─┬─────────────────┬─────────────────┐", strings.Repeat("─", maxFileWidth))
	b.Logf("│ %-*s │ Vulnerabilities │   Avg Time/Op   │", maxFileWidth, "SBOM File")
	b.Logf("├─%s─┼─────────────────┼─────────────────┤", strings.Repeat("─", maxFileWidth))

	// Print table rows
	for _, file := range files {
		result := benchmarkResults[file]
		b.Logf("│ %-*s │ %15d │ %15s │", maxFileWidth, file, result.vulnCount, formatDuration(result.avgTime))
	}

	// Print table footer
	b.Logf("└─%s─┴─────────────────┴─────────────────┘", strings.Repeat("─", maxFileWidth))
}

func formatDuration(d time.Duration) string {
	if d >= time.Second {
		return fmt.Sprintf("%.2fs", d.Seconds())
	} else if d >= time.Millisecond {
		return fmt.Sprintf("%.1fms", float64(d.Nanoseconds())/1e6)
	} else if d >= time.Microsecond {
		return fmt.Sprintf("%.1fµs", float64(d.Nanoseconds())/1e3)
	} else {
		return fmt.Sprintf("%dns", d.Nanoseconds())
	}
}

func difference(a, b []string) []string {
	mb := make(map[string]struct{}, len(b))
	for _, x := range b {
		mb[x] = struct{}{}
	}
	var diff []string
	for _, x := range a {
		if _, found := mb[x]; !found {
			diff = append(diff, x)
		}
	}
	return diff
}
