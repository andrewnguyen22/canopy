# Takusen native module

This branch customizes the Go plugin as Takusen's Canopy-native state machine. It adds validator-quorum enclave registration, bonded servicers, Base authorization observations, deterministic model assignments, signed execution receipts, settlement records, and Base finalization observations.

## Base BDN proof export

`takusenSubmitQuorumSignature` carries an active validator's second BDN signature over the exact 32-byte, domain-separated Base contract digest. The transaction itself is independently authenticated by Canopy. Once active signer stake is strictly greater than two thirds, the plugin stores a `QuorumProof` under `/v1/takusen/quorum-proofs/{proof-id}`.

The roster is sorted by compressed G1 public key. Bitmap bit `i` (least-significant bit first) selects roster member `i`. Each proof exports compressed Canopy keys/signature and EIP-2537 encodings: G1 is `x || y` and G2 is `x.c0 || x.c1 || y.c0 || y.c1`, with every 48-byte field element left-padded to 64 bytes. `weighted_public_key_eip2537` already includes the BDN roster coefficient; Base therefore aggregates selected keys with G1 addition before the pairing check. `validator_set_hash` commits to the ordered addresses, compressed public keys, and weights.

The Base proof argument is `abi.encode(bytes aggregateSignatureEIP2537, bytes signerBitmap)`. `plugin/go/contract/quorum_vector_test.go` and Takusen's `contracts/test/BDNQuorumVerifier.t.sol` share a fixed cross-language vector.

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
