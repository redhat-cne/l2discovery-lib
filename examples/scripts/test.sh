#!/bin/bash
set -o nounset -o pipefail

cd "$(dirname "$0")/.." || exit 1

# Creates kind cluster
cat >kind-config.yaml <<EOF
# three node (two workers) cluster config
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
- role: worker
- role: worker
EOF

go build ./...
go test ./...

kind delete cluster --name test-cluster || true
kind create cluster --name test-cluster --config kind-config.yaml

export KUBECONFIG=~/.kube/config

go run ./simplegraphsolver
