use std::fs::File;
use std::io::{self, Read};
use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};

use broadcast_dra::{
    FalseBid, LogNormal, Pareto, PublicBroadcastDRA, Uniform, ValueDistribution, Exponential,
    NonMalleableShaCommitment, PedersenRistrettoCommitment, AuditedNonMalleableCommitment,
    simulate_deviation_with_scheme, DeviationModel, SimulationResult,
};

#[derive(Parser, Debug)]
#[command(name = "broadcast-dra")]
#[command(about = "Run the public broadcast DRA from JSON input", long_about = None)]
struct CliArgs {
    /// Path to a JSON input file. If omitted, reads from stdin.
    #[arg(short, long)]
    input: Option<PathBuf>,

    /// Override the commitment backend (overrides JSON).
    #[arg(long, value_enum)]
    backend: Option<CommitmentBackendSpec>,

    /// If set, run a simulation instead of a single auction.
    #[arg(long)]
    simulate: bool,

    /// Number of trials for simulation mode.
    #[arg(long, default_value_t = 500)]
    trials: usize,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum DistributionSpec {
    Exponential { lambda: f64 },
    Uniform { low: f64, high: f64 },
    Pareto { scale: f64, shape: f64 },
    Lognormal { mu: f64, sigma: f64 },
}

#[derive(Debug, Deserialize)]
struct FalseBidSpec {
    bid: f64,
    #[serde(default)]
    reveal: bool,
}

#[derive(Debug, Deserialize)]
struct AuctionRequest {
    distribution: DistributionSpec,
    valuations: Vec<f64>,
    #[serde(default)]
    false_bids: Vec<FalseBidSpec>,
    alpha: Option<f64>,
    rng_seed: Option<u64>,
    #[serde(default = "default_backend")]
    commitment_backend: CommitmentBackendSpec,
}

#[derive(Clone, Debug, Deserialize, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
enum CommitmentBackendSpec {
    Sha,
    Pedersen,
    Audited,
}

fn default_backend() -> CommitmentBackendSpec {
    CommitmentBackendSpec::Sha
}

#[derive(Debug, Serialize)]
struct AuctionResponse {
    reserve: f64,
    collateral: f64,
    winner: Option<String>,
    winning_bid: f64,
    payment: f64,
    transferred_collateral: f64,
    forfeited_to_auctioneer: f64,
    valid_bids: Vec<(String, f64)>,
}

type Backend = broadcast_dra::Backend;

fn main() -> io::Result<()> {
    let args = CliArgs::parse();
    let mut input = String::new();
    match args.input {
        Some(path) => {
            let mut file = File::open(path)?;
            file.read_to_string(&mut input)?;
        }
        None => {
            io::stdin().read_to_string(&mut input)?;
        }
    }
    let mut req: AuctionRequest =
        serde_json::from_str(&input).expect("Invalid JSON input for auction");
    if let Some(b) = args.backend {
        req.commitment_backend = b;
    }

    if args.simulate {
        run_simulation(req, args.trials)
    } else {
        match req.distribution {
            DistributionSpec::Exponential { lambda } => run_with_dist(Exponential::new(lambda), req),
            DistributionSpec::Uniform { low, high } => run_with_dist(Uniform::new(low, high), req),
            DistributionSpec::Pareto { scale, shape } => run_with_dist(Pareto::new(scale, shape), req),
            DistributionSpec::Lognormal { mu, sigma } => run_with_dist(LogNormal::new(mu, sigma), req),
        }
    }
}

fn run_with_dist<D: ValueDistribution + 'static>(dist: D, req: AuctionRequest) -> io::Result<()> {
    let alpha = req
        .alpha
        .or_else(|| dist.strong_regular_alpha())
        .unwrap_or(1.0);
    let dra = PublicBroadcastDRA::new(dist, alpha);
    let mut backend = match req.commitment_backend {
        CommitmentBackendSpec::Sha => Backend::Sha(NonMalleableShaCommitment),
        CommitmentBackendSpec::Pedersen => Backend::Pedersen(PedersenRistrettoCommitment),
        CommitmentBackendSpec::Audited => Backend::Audited(AuditedNonMalleableCommitment),
    };
    let fbs: Vec<FalseBid> = req
        .false_bids
        .iter()
        .map(|fb| FalseBid {
            bid: fb.bid,
            reveal: fb.reveal,
        })
        .collect();
    let outcome = match &mut backend {
        Backend::Sha(s) => dra.run_with_false_bids_using_scheme(&req.valuations, &fbs, req.rng_seed, s),
        Backend::Pedersen(p) => dra.run_with_false_bids_using_scheme(&req.valuations, &fbs, req.rng_seed, p),
        Backend::Audited(a) => dra.run_with_false_bids_using_scheme(&req.valuations, &fbs, req.rng_seed, a),
    };

    let resp = AuctionResponse {
        reserve: outcome.reserve,
        collateral: outcome.collateral,
        winner: outcome.winner.as_ref().map(|w| format!("{:?}", w)),
        winning_bid: outcome.winning_bid,
        payment: outcome.payment,
        transferred_collateral: outcome.transferred_collateral,
        forfeited_to_auctioneer: outcome.forfeited_to_auctioneer,
        valid_bids: outcome
            .valid_bids
            .iter()
            .map(|(id, b)| (format!("{:?}", id), *b))
            .collect(),
    };

    serde_json::to_writer_pretty(io::stdout(), &resp)?;
    println!();
    Ok(())
}

fn run_simulation(req: AuctionRequest, trials: usize) -> io::Result<()> {
    let buyers = req.valuations.len();
    if buyers == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "valuations must be non-empty to infer buyer count for simulation",
        ));
    }
    let alpha = req.alpha.unwrap_or(1.0);
    let backend = match req.commitment_backend {
        CommitmentBackendSpec::Sha => Backend::Sha(NonMalleableShaCommitment),
        CommitmentBackendSpec::Pedersen => Backend::Pedersen(PedersenRistrettoCommitment),
        CommitmentBackendSpec::Audited => Backend::Audited(AuditedNonMalleableCommitment),
    };
    let deviation = if req.false_bids.len() > 1 {
        DeviationModel::Multiple(
            req.false_bids
                .iter()
                .map(|fb| FalseBid {
                    bid: fb.bid,
                    reveal: fb.reveal,
                })
                .collect(),
        )
    } else if let Some(fb) = req.false_bids.first() {
        DeviationModel::Fixed(FalseBid {
            bid: fb.bid,
            reveal: fb.reveal,
        })
    } else {
        DeviationModel::Fixed(FalseBid { bid: 0.0, reveal: true })
    };

    let sims: SimulationResult = match req.distribution {
        DistributionSpec::Exponential { lambda } => simulate_deviation_with_scheme(
            Exponential::new(lambda),
            alpha,
            buyers,
            trials,
            deviation,
            req.rng_seed.unwrap_or(1),
            backend,
        ),
        DistributionSpec::Uniform { low, high } => simulate_deviation_with_scheme(
            Uniform::new(low, high),
            alpha,
            buyers,
            trials,
            deviation,
            req.rng_seed.unwrap_or(1),
            backend,
        ),
        DistributionSpec::Pareto { scale, shape } => simulate_deviation_with_scheme(
            Pareto::new(scale, shape),
            alpha,
            buyers,
            trials,
            deviation,
            req.rng_seed.unwrap_or(1),
            backend,
        ),
        DistributionSpec::Lognormal { mu, sigma } => simulate_deviation_with_scheme(
            LogNormal::new(mu, sigma),
            alpha,
            buyers,
            trials,
            deviation,
            req.rng_seed.unwrap_or(1),
            backend,
        ),
    };

    serde_json::to_writer_pretty(io::stdout(), &sims)?;
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_with_dist_executes() {
        let req = AuctionRequest {
            distribution: DistributionSpec::Uniform { low: 0.0, high: 10.0 },
            valuations: vec![3.0, 5.0],
            false_bids: vec![],
            alpha: None,
            rng_seed: Some(7),
            commitment_backend: CommitmentBackendSpec::Sha,
        };
        run_with_dist(Uniform::new(0.0, 10.0), req).expect("cli run");
    }

    #[test]
    fn run_simulation_executes() {
        let req = AuctionRequest {
            distribution: DistributionSpec::Uniform { low: 0.0, high: 10.0 },
            valuations: vec![0.0, 0.0, 0.0],
            false_bids: vec![FalseBidSpec { bid: 4.0, reveal: true }],
            alpha: Some(1.0),
            rng_seed: Some(3),
            commitment_backend: CommitmentBackendSpec::Pedersen,
        };
        run_simulation(req, 10).expect("simulation run");
    }
}
