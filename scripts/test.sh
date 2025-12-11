#!/bin/bash
set -o nounset -o pipefail

# Run go tests for all packages except cmd/l2discovery (requires Linux headers for CGO)
# shellcheck disable=SC2046
go test $(go list ./... | grep -v cmd/l2discovery)

# Build all commands to verify they compile (except l2discovery which is Linux-only)
echo "Building cmd/graphsolver-minimal..."
go build -o /dev/null ./cmd/graphsolver-minimal

echo "Building cmd/graphsolver-example..."
go build -o /dev/null ./cmd/graphsolver-example

echo "Building cmd/l2dump..."
go build -o /dev/null ./cmd/l2dump

echo "All builds successful!"
