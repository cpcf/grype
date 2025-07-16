# Benchmarks & Golden Files

- `inputs/`: Representative SBOMs for benchmarking.
- `golden/`: Expectations for vuln results.

## Usage
- Add SBOMs generated with `github.com/anchore/syft` to `inputs/`.
- Run `go run ./benchmarks/golden/golden_gen.go` on a known good version of Grype to generate expectations for vuln results.
- Apply changes to Grype/update to latest version.
- Run `go test -v -bench=^BenchmarkEndToEndRealSBOMs$ ./benchmarks`
  - Benchmarks performance against SBOMs
  - Compares vuln results to expectations in `./benchmarks/golden/latest`


## TODO:
- Version golden snapshots
- Add more SBOMs
- Add benchmarking for individual parts of the system
