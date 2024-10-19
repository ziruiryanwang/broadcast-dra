# Credible, Optimal Auctions via Public Broadcast

This repository implements the deferred revelation auction with public broadcast from the paper *Credible, Optimal Auctions via Public Broadcast*. It models the commit, reveal, and resolution phases, including collateral and validation rules derived from the paper.


## High-level design
- `commitment`: programmable commitments (perfectly hiding/binding/non-malleable are modelled via SHA-256 placeholders).
- `distribution`: value distribution traits and a few concrete examples (exponential, uniform), plus virtual value and reserve price helpers.
- `collateral`: collateral function `f(n, D, α)` from the paper.
- `auction`: public-broadcast DRA implementation with support for false bids, reveal validation, tie-breaking, and collateral flows.
- `bin/demo`: example runner that simulates a round.

## Running
```
cargo run --bin demo
```

## Testing
```
cargo test
```
