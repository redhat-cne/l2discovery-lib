#!/bin/bash
set -o nounset -o pipefail

# CD in the examples repo
cd examples || exit

# Get latest changes
echo "replace github.com/redhat-cne/l2discovery-lib => .." >>go.mod
go mod tidy
go mod vendor

# Test them in examples repository
make test
