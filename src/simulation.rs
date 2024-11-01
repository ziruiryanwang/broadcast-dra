use rand::SeedableRng;
use rand::rngs::StdRng;

use crate::auction::PublicBroadcastDRA;
use crate::distribution::ValueDistribution;
use crate::FalseBid;

#[derive(Clone, Debug)]
pub struct RevenueStats {
    pub baseline: f64,
    pub deviated: f64,
}

fn auctioneer_revenue(outcome: &crate::auction::AuctionOutcome) -> f64 {
    outcome.payment + outcome.forfeited_to_auctioneer
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
    let dra = PublicBroadcastDRA::new(dist.clone(), alpha);
    let mut rng = StdRng::seed_from_u64(seed);

    let mut baseline_total = 0.0;
    let mut deviated_total = 0.0;
    for _ in 0..trials {
        let mut vals = Vec::with_capacity(buyers);
        for _ in 0..buyers {
            vals.push(dist.sample(&mut rng));
        }
        let base_outcome = dra.run_with_false_bids(&vals, &[], None);
        let dev_outcome = dra.run_with_false_bids(&vals, &[false_bid.clone()], None);

        baseline_total += auctioneer_revenue(&base_outcome);
        deviated_total += auctioneer_revenue(&dev_outcome);
    }

    RevenueStats {
        baseline: baseline_total / trials as f64,
        deviated: deviated_total / trials as f64,
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
            dist,
            1.0,
            3,
            200,
            FalseBid { bid: 10.0, reveal: false },
            123,
        );
        assert!(stats.baseline.is_finite());
        assert!(stats.deviated.is_finite());
    }
}
