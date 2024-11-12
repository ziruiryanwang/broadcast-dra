use rand::rngs::StdRng;
use rand::SeedableRng;

use crate::auction::{AuctionOutcome, PublicBroadcastDRA};
use crate::commitment::{NonMalleableShaCommitment, PedersenRistrettoCommitment};
use crate::distribution::ValueDistribution;
use crate::FalseBid;

#[derive(Clone, Debug)]
pub struct RevenueStats {
    pub baseline: f64,
    pub deviated: f64,
}

#[derive(Clone, Debug)]
pub enum DeviationModel {
    Fixed(FalseBid),
    Multiple(Vec<FalseBid>),
    ThresholdReveal {
        bid: f64,
        reveal_if_top_at_least: f64,
    },
}

#[derive(Clone, Debug)]
pub struct SimulationResult {
    pub baseline_revenue: f64,
    pub deviated_revenue: f64,
    pub allocation_change_rate: f64,
}

#[derive(Clone, Debug)]
pub enum Backend {
    Sha(NonMalleableShaCommitment),
    Pedersen(PedersenRistrettoCommitment),
}

fn auctioneer_revenue(outcome: &AuctionOutcome) -> f64 {
    outcome.payment + outcome.forfeited_to_auctioneer
}

fn false_bids_from_model(model: &DeviationModel, top_real_bid: f64) -> Vec<FalseBid> {
    match model {
        DeviationModel::Fixed(fb) => vec![fb.clone()],
        DeviationModel::Multiple(fbs) => fbs.clone(),
        DeviationModel::ThresholdReveal {
            bid,
            reveal_if_top_at_least,
        } => vec![FalseBid {
            bid: *bid,
            reveal: top_real_bid >= *reveal_if_top_at_least,
        }],
    }
}

/// Monte Carlo compare baseline revenue vs. revenue under a fixed false-bid deviation.
pub fn simulate_false_bid_impact<D: ValueDistribution + Clone>(
    dist: D,
    alpha: f64,
    buyers: usize,
    trials: usize,
    false_bid: FalseBid,
    seed: u64,
) -> RevenueStats {
    let result = simulate_deviation(dist, alpha, buyers, trials, DeviationModel::Fixed(false_bid), seed);
    RevenueStats {
        baseline: result.baseline_revenue,
        deviated: result.deviated_revenue,
    }
}

/// Monte Carlo compare baseline vs. an arbitrary deviation model.
pub fn simulate_deviation<D: ValueDistribution + Clone>(
    dist: D,
    alpha: f64,
    buyers: usize,
    trials: usize,
    deviation: DeviationModel,
    seed: u64,
) -> SimulationResult {
    simulate_deviation_with_scheme(
        dist,
        alpha,
        buyers,
        trials,
        deviation,
        seed,
        Backend::Sha(NonMalleableShaCommitment),
    )
}

pub fn simulate_deviation_with_scheme<D: ValueDistribution + Clone>(
    dist: D,
    alpha: f64,
    buyers: usize,
    trials: usize,
    deviation: DeviationModel,
    seed: u64,
    backend: Backend,
) -> SimulationResult {
    let dra = PublicBroadcastDRA::new(dist.clone(), alpha);
    let mut rng = StdRng::seed_from_u64(seed);

    let mut baseline_total = 0.0;
    let mut deviated_total = 0.0;
    let mut allocation_changes = 0usize;
    for _ in 0..trials {
        let mut vals = Vec::with_capacity(buyers);
        for _ in 0..buyers {
            vals.push(dist.sample(&mut rng));
        }
        let top_real = vals
            .iter()
            .cloned()
            .fold(0.0_f64, f64::max);
        let base_outcome = match &backend {
            Backend::Sha(s) => {
                let mut s = s.clone();
                dra.run_with_false_bids_using_scheme(&vals, &[], None, &mut s)
            }
            Backend::Pedersen(p) => {
                let mut p = p.clone();
                dra.run_with_false_bids_using_scheme(&vals, &[], None, &mut p)
            }
        };
        let false_bids = false_bids_from_model(&deviation, top_real);
        let dev_outcome = match &backend {
            Backend::Sha(s) => {
                let mut s = s.clone();
                dra.run_with_false_bids_using_scheme(&vals, &false_bids, None, &mut s)
            }
            Backend::Pedersen(p) => {
                let mut p = p.clone();
                dra.run_with_false_bids_using_scheme(&vals, &false_bids, None, &mut p)
            }
        };

        baseline_total += auctioneer_revenue(&base_outcome);
        deviated_total += auctioneer_revenue(&dev_outcome);
        if dev_outcome.winner != base_outcome.winner {
            allocation_changes += 1;
        }
    }

    let n = trials as f64;
    SimulationResult {
        baseline_revenue: baseline_total / n,
        deviated_revenue: deviated_total / n,
        allocation_change_rate: allocation_changes as f64 / n,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::distribution::Exponential;

    #[test]
    fn simulation_runs_and_returns_finite_values() {
        let dist = Exponential::new(1.0);
        let stats = simulate_false_bid_impact(
            dist.clone(),
            1.0,
            3,
            200,
            FalseBid { bid: 10.0, reveal: false },
            123,
        );
        assert!(stats.baseline.is_finite());
        assert!(stats.deviated.is_finite());

        let dev = simulate_deviation(
            dist,
            1.0,
            3,
            200,
            DeviationModel::ThresholdReveal { bid: 15.0, reveal_if_top_at_least: 8.0 },
            456,
        );
        assert!(dev.allocation_change_rate >= 0.0);
    }
}
