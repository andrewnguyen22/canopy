# Takusen native module

This branch customizes the Go plugin as Takusen's Canopy-native state machine. It adds validator-quorum enclave registration, bonded servicers, Base authorization observations, deterministic model assignments, signed execution receipts, settlement records, and Base finalization observations.

The core/plugin begin-block request includes the previous finalized block hash. Takusen uses that trusted value with the request input hash and model identifier to derive assignments.

Run the two-validator development network from the Canopy repository root:

```sh
docker compose -f plugin/go/compose.yaml up -d --build
```

The query RPC is at `http://localhost:50002`; the Takusen plugin RPC is at `http://localhost:50010`. The second node exposes query RPC `40002` and plugin RPC `50011`.

Run the native consensus integration test after both nodes are healthy:

```sh
cd plugin/go
TAKUSEN_E2E=1 go test -run TestTakusenConsensusE2E -v -count=1 -timeout=5m
```

The test commits the complete registration → bonding → authorization → assignment → execution → settlement → finalization lifecycle through both validators. The local validator keys are fixture keys from `.docker/volumes`; production validator observers must run independently and must not expose their keys to an application process.
