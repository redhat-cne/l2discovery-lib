# L2 discovery graph solver examples

Example programs that run the graph solver against L2 discovery data.

- `simplegraphsolver` connects to a cluster with the PTP operator test client,
  collects L2 discovery information, and solves an OC problem for interfaces
  connected via a LAN.
- `basic` runs the same solver against a synthetic two-interface graph and needs
  no cluster.

Build and vet everything:

```sh
go build ./...
go vet ./...
```

Run the synthetic example:

```sh
go run ./basic
```

Run the cluster example (requires a reachable cluster and PTP-capable nodes):

```sh
go run ./simplegraphsolver
```

`scripts/test.sh` creates a three-node kind cluster and runs `simplegraphsolver`
against it.
