# Credible, Optimal Auctions via Public Broadcast

This repository implements the deferred revelation auction with public broadcast from the paper *Credible, Optimal Auctions via Public Broadcast*. It models the commit, reveal, and resolution phases, including collateral and validation rules derived from the paper.


## High-level design
- `commitment`: programmable commitments (perfectly hiding/binding/non-malleable are modelled via SHA-256 placeholders).
- `distribution`: value distribution traits and a few concrete examples (exponential, uniform), plus virtual value and reserve price helpers.
- `collateral`: collateral function `f(n, D, α)` from the paper.
- `auction`: public-broadcast DRA implementation with support for false bids, reveal validation, tie-breaking, and collateral flows.
- `bin/demo`: example runner that simulates a round.

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
Supported distributions: `exponential {lambda}`, `uniform {low, high}`, `pareto {scale, shape}`, `lognormal {mu, sigma}`.
Commitment backends: `sha` (default) or `pedersen`.

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

## Running
```
cargo run --bin demo
```

## Testing
```
cargo test
```
