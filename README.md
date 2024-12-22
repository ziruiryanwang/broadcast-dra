# Credible, Optimal Auctions via Public Broadcast

This repository implements the deferred revelation auction with public broadcast from the paper *Credible, Optimal Auctions via Public Broadcast*. It models the commit, reveal, and resolution phases, including collateral and validation rules derived from the paper.


## High-level design
- `commitment`: programmable commitments (SHA-256 baseline, Pedersen/Ristretto, and a Fischlin–Fischlin-style non-malleable construction following [Fischlin & Fischlin, CRYPTO 2000](https://link.springer.com/chapter/10.1007/3-540-44598-6_25)).
  An audited variant logs commitments to an append-only ledger and hands out receipts verified during audits.
- `distribution`: value distribution traits and a few concrete examples (exponential, uniform, equal-revenue, etc.), plus virtual value and reserve price helpers.
- `collateral`: collateral function `f(n, D, α)` from the paper.
- `auction`: public-broadcast DRA implementation with support for false bids, reveal validation, tie-breaking, and collateral flows.
- `bin/demo`: example runner that simulates a round.
- `centralized`: centralized protocol driver plus selective-delivery channel/logs for Example 1 and Definition 23.

### Commitment provenance
- **Bulletproofs backend** (`--backend bulletproofs`): Powered by the [zkcrypto/bulletproofs](https://github.com/zkcrypto/bulletproofs) crate v5.0.0 (MIT) implementing the short range proofs from Bünz et al., *Bulletproofs: Short Proofs for Confidential Transactions and More*, IEEE S&P 2018. The downloaded crate archive has SHA-256 digest `012e2e5f88332083bd4235d445ae78081c00b2558443821a9ca5adfe1070073d`, recorded for provenance. The audited backend wraps this construction with the append-only receipt ledger described in Definition 5.

## CLI input/output
`cargo run -- --input input.json` or `echo '{...}' | cargo run --`

Input JSON shape:
```json
{
  "distribution": { "type": "uniform", "low": 0, "high": 10 },
  "valuations": [3, 5, 7],
  "false_bids": [{ "bid": 20, "reveal": false }],
  "alpha": 1.0,
  "rng_seed": 42,
  "commitment_backend": "pedersen"
}
```
Supported distributions: `exponential {lambda}`, `uniform {low, high}`, `pareto {scale, shape}`, `lognormal {mu, sigma}`, `equal_revenue {scale}`.
Commitment backends: `sha` (default), `pedersen`, `audited` (ledger-backed bulletproof commitments), `fischlin` (a non-malleable scheme mirroring Fischlin–Fischlin with Schnorr proofs over Ristretto), or `bulletproofs` (standalone zk-SNARK backed commitments).

Output JSON shape:
```json
{
  "reserve": 5.0,
  "collateral": 5.0,
  "winner": "Real(2)",
  "winning_bid": 7.0,
  "payment": 5.0,
  "transferred_collateral": 0.0,
  "forfeited_to_auctioneer": 0.0,
  "valid_bids": [["Real(0)", 3.0], ["Real(1)", 5.0], ["Real(2)", 7.0]]
}
```

Flags:
- `--backend {sha|pedersen|fischlin|audited|bulletproofs}` overrides the JSON backend.
- `--simulate --trials N` runs Monte Carlo using the provided distribution, alpha, backend, buyer count inferred from `valuations.len()`, and deviation given by `false_bids`, outputting simulation summary JSON.
- `--scenario {example1|adaptive|counterexample}` prints the reproducible Example 1/Definition 23/Theorem 25 scripts.

### Scenario runbook
```
cargo run -- --scenario example1
cargo run -- --scenario adaptive
cargo run -- --scenario counterexample
```

### Audit/provenance
`cargo run --bin audit` prints the recorded SHA256 digests for the bulletproofs crate (v5.0.0) and the provided TeX source (`reference_material/Credible_Optimal_Auctions_public_broadcast_full.tex`).

### Programmatic timed simulations
The library now exposes `simulate_timed_protocol` and its `TimedSimulationReport`, which drive the full `ProtocolSession` with explicit commit/reveal deadlines, emit broadcast logs, and surface aggregate revenue plus deadline failures under the safe deviations described in the paper. These runs exercise the real-time auditing path and penalty logic.

### Safe-deviation verification
Use simulate_safe_deviation_bound to empirically confirm Lemmas 18-21: it compares the auctioneer's revenue under a specified deviation (e.g., withheld false bids above the collateral) against the Myerson-optimal baseline and reports any violation margin. centralized::adaptive_reserve_deviation reproduces the adaptive-reserve attack from Definition 23 to show the centralized auction is not credible, while the broadcast simulations remain bounded. Property tests in simulation.rs (proptest powered) cover Uniform, Exponential, and Pareto (alpha>0) families to statistically validate these lemmas.

### Paper-to-code map
- **Theorem 21** -> collateral::collateral_requirement, simulation::tests::safe_deviation_bound_holds_for_exponential.
- **Definition 8** -> auction::audit_transcript.
- **Definition 23 / Theorem 22** -> centralized::scripted_adaptive_reserve_run and centralized::tests::adaptive_reserve_driver_exceeds_baseline_only_when_censored.
- **Example 1** -> centralized::tests::example_one_censors_commitment.
- **Theorem 25** -> distribution::EqualRevenue plus simulation::tests::equal_revenue_distribution_breaks_single_buyer_bound.
- **Lemmas 18-20** -> simulation::simulate_safe_deviation_bound and the three proptest! suites in simulation.rs.

## Running
```
cargo run --bin demo
```

## Testing
```
cargo test
```


