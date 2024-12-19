use rand::RngCore;
use rand::SeedableRng;
use rand::rngs::StdRng;
use serde::Serialize;

use crate::FalseBid;
use crate::auction::{AuctionOutcome, ParticipantId, PhaseTimings, PublicBroadcastDRA};
use crate::commitment::{
    AuditedNonMalleableCommitment, BulletproofsCommitment, NonMalleableShaCommitment,
    PedersenRistrettoCommitment, RealNonMalleableCommitment,
};
use crate::distribution::ValueDistribution;
use crate::protocol::ProtocolSession;

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

#[derive(Clone, Debug, Serialize)]
pub struct SimulationResult {
    pub baseline_revenue: f64,
    pub deviated_revenue: f64,
    pub allocation_change_rate: f64,
}

#[derive(Clone, Debug, Serialize)]
pub struct TimedSimulationReport {
    pub successful_runs: usize,
    pub deadline_failures: usize,
    pub average_revenue: f64,
}

#[derive(Clone, Debug, Serialize)]
pub struct SafeDeviationStats {
    pub satisfied: bool,
    pub max_violation: f64,
}

#[derive(Clone, Debug)]
pub enum Backend {
    Sha(NonMalleableShaCommitment),
    Pedersen(PedersenRistrettoCommitment),
    Audited(AuditedNonMalleableCommitment),
    Fischlin(RealNonMalleableCommitment),
    Bulletproofs(BulletproofsCommitment),
}

fn auctioneer_revenue(outcome: &AuctionOutcome) -> f64 {
    outcome.payment + outcome.forfeited_to_auctioneer - outcome.auctioneer_penalty
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
    let result = simulate_deviation(
        dist,
        alpha,
        buyers,
        trials,
        DeviationModel::Fixed(false_bid),
        seed,
    );
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
        let top_real = vals.iter().cloned().fold(0.0_f64, f64::max);
        let base_outcome = match &backend {
            Backend::Sha(s) => {
                let mut s = s.clone();
                dra.run_with_false_bids_using_scheme(&vals, &[], None, &mut s)
            }
            Backend::Pedersen(p) => {
                let mut p = p.clone();
                dra.run_with_false_bids_using_scheme(&vals, &[], None, &mut p)
            }
            Backend::Audited(a) => {
                let mut a = a.clone();
                dra.run_with_false_bids_using_scheme(&vals, &[], None, &mut a)
            }
            Backend::Fischlin(f) => {
                let mut f = f.clone();
                dra.run_with_false_bids_using_scheme(&vals, &[], None, &mut f)
            }
            Backend::Bulletproofs(b) => {
                let mut b = b.clone();
                dra.run_with_false_bids_using_scheme(&vals, &[], None, &mut b)
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
            Backend::Audited(a) => {
                let mut a = a.clone();
                dra.run_with_false_bids_using_scheme(&vals, &false_bids, None, &mut a)
            }
            Backend::Fischlin(f) => {
                let mut f = f.clone();
                dra.run_with_false_bids_using_scheme(&vals, &false_bids, None, &mut f)
            }
            Backend::Bulletproofs(b) => {
                let mut b = b.clone();
                dra.run_with_false_bids_using_scheme(&vals, &false_bids, None, &mut b)
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

/// Drive the full ProtocolSession with explicit time slots and report audit outcomes.
pub fn simulate_timed_protocol<D: ValueDistribution + Clone>(
    dist: D,
    alpha: f64,
    buyers: usize,
    trials: usize,
    deviation: DeviationModel,
    schedule: PhaseTimings,
    seed: u64,
) -> TimedSimulationReport {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut successes = 0usize;
    let mut deadline_failures = 0usize;
    let mut revenue_sum = 0.0;
    for _ in 0..trials {
        let per_trial_dra = PublicBroadcastDRA::new(dist.clone(), alpha);
        let mut vals = Vec::with_capacity(buyers);
        for _ in 0..buyers {
            vals.push(dist.sample(&mut rng));
        }
        let top_real = vals.iter().cloned().fold(0.0_f64, f64::max);
        let false_bids = false_bids_from_model(&deviation, top_real);
        let collateral = per_trial_dra.collateral(buyers);
        let participants = (0..buyers).map(ParticipantId::Real).collect();
        let mut session = ProtocolSession::new(
            per_trial_dra,
            RealNonMalleableCommitment,
            rng.next_u64(),
            schedule.clone(),
            participants,
        );
        let mut now = 0u64;
        let mut failed = false;
        for (idx, bid) in vals.iter().enumerate() {
            if session.advance_to(now).is_err()
                || session.commit_real(idx, *bid, collateral).is_err()
            {
                failed = true;
                break;
            }
            now += 1;
        }
        if failed {
            deadline_failures += 1;
            continue;
        }
        for (idx, fb) in false_bids.iter().enumerate() {
            if session.advance_to(now).is_err()
                || session
                    .commit_false(idx, fb.bid, collateral, fb.reveal)
                    .is_err()
            {
                failed = true;
                break;
            }
            now += 1;
        }
        if failed || session.end_commit_phase().is_err() {
            deadline_failures += 1;
            continue;
        }
        now = schedule.commit_deadline;
        for idx in 0..buyers {
            if session.advance_to(now).is_err() || session.reveal(ParticipantId::Real(idx)).is_err()
            {
                failed = true;
                break;
            }
            now += 1;
        }
        if failed {
            deadline_failures += 1;
            continue;
        }
        for (idx, fb) in false_bids.iter().enumerate() {
            if fb.reveal {
                if session.advance_to(now).is_err()
                    || session.reveal(ParticipantId::False(idx)).is_err()
                {
                    failed = true;
                    break;
                }
                now += 1;
            }
        }
        if failed {
            deadline_failures += 1;
            continue;
        }
        if session.advance_to(schedule.reveal_deadline).is_err() {
            deadline_failures += 1;
            continue;
        }
        match session.end_reveal_and_resolve() {
            Ok((outcome, _, _)) => {
                revenue_sum += auctioneer_revenue(&outcome);
                successes += 1;
            }
            Err(_) => deadline_failures += 1,
        }
    }
    TimedSimulationReport {
        successful_runs: successes,
        deadline_failures,
        average_revenue: if successes > 0 {
            revenue_sum / successes as f64
        } else {
            0.0
        },
    }
}

/// Empirically verify the Lemma18/21 revenue bound by comparing deviation revenue against the optimal baseline.
pub fn simulate_safe_deviation_bound<D: ValueDistribution + Clone>(
    dist: D,
    alpha: f64,
    buyers: usize,
    trials: usize,
    false_bids: Vec<FalseBid>,
    seed: u64,
) -> SafeDeviationStats {
    let dra = PublicBroadcastDRA::new(dist.clone(), alpha);
    let mut rng = StdRng::seed_from_u64(seed);
    let mut max_violation = 0.0_f64;
    for _ in 0..trials {
        let mut vals = Vec::with_capacity(buyers);
        for _ in 0..buyers {
            vals.push(dist.sample(&mut rng));
        }
        let base_seed = rng.next_u64();
        let dev_seed = rng.next_u64();
        let baseline = dra.run_with_false_bids(&vals, &[], Some(base_seed));
        let deviated = dra.run_with_false_bids(&vals, &false_bids, Some(dev_seed));
        let base_rev = auctioneer_revenue(&baseline);
        let dev_rev = auctioneer_revenue(&deviated);
        if dev_rev > base_rev + 1e-9 {
            max_violation = max_violation.max(dev_rev - base_rev);
        }
    }
    SafeDeviationStats {
        satisfied: max_violation <= 1e-9,
        max_violation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::{
        AuditedNonMalleableCommitment, PedersenRistrettoCommitment, RealNonMalleableCommitment,
    };
    use crate::distribution::Exponential;

    #[test]
    fn simulation_runs_and_returns_finite_values() {
        let dist = Exponential::new(1.0);
        let stats = simulate_false_bid_impact(
            dist.clone(),
            1.0,
            3,
            200,
            FalseBid {
                bid: 10.0,
                reveal: false,
            },
            123,
        );
        assert!(stats.baseline.is_finite());
        assert!(stats.deviated.is_finite());

        let dev = simulate_deviation(
            dist,
            1.0,
            3,
            200,
            DeviationModel::ThresholdReveal {
                bid: 15.0,
                reveal_if_top_at_least: 8.0,
            },
            456,
        );
        assert!(dev.allocation_change_rate >= 0.0);
    }

    #[test]
    fn simulation_runs_with_pedersen_backend() {
        let dist = Exponential::new(1.0);
        let dev = simulate_deviation_with_scheme(
            dist,
            1.0,
            2,
            50,
            DeviationModel::Fixed(FalseBid {
                bid: 3.0,
                reveal: true,
            }),
            999,
            Backend::Pedersen(PedersenRistrettoCommitment),
        );
        assert!(dev.deviated_revenue.is_finite());
    }

    #[test]
    fn simulation_runs_with_fischlin_backend() {
        let dist = Exponential::new(1.0);
        let dev = simulate_deviation_with_scheme(
            dist,
            1.0,
            2,
            50,
            DeviationModel::Fixed(FalseBid {
                bid: 3.0,
                reveal: true,
            }),
            321,
            Backend::Fischlin(RealNonMalleableCommitment),
        );
        assert!(dev.deviated_revenue.is_finite());
    }

    #[test]
    fn simulation_runs_with_audited_backend() {
        let dist = Exponential::new(1.0);
        let dev = simulate_deviation_with_scheme(
            dist,
            1.0,
            2,
            50,
            DeviationModel::Fixed(FalseBid {
                bid: 3.0,
                reveal: true,
            }),
            222,
            Backend::Audited(AuditedNonMalleableCommitment::default()),
        );
        assert!(dev.deviated_revenue.is_finite());
    }

    #[test]
    fn timed_protocol_simulation_runs() {
        let dist = Exponential::new(1.0);
        let schedule = PhaseTimings {
            commit_deadline: 4,
            reveal_deadline: 10,
        };
        let report = simulate_timed_protocol(
            dist,
            1.0,
            2,
            3,
            DeviationModel::Fixed(FalseBid {
                bid: 5.0,
                reveal: false,
            }),
            schedule,
            2024,
        );
        assert!(report.successful_runs + report.deadline_failures > 0);
    }

    #[test]
    fn safe_deviation_bound_holds_for_exponential() {
        let dist = Exponential::new(1.0);
        let dra = PublicBroadcastDRA::new(dist.clone(), 1.0);
        let coll = dra.collateral(3);
        let stats = simulate_safe_deviation_bound(
            dist,
            1.0,
            3,
            200,
            vec![FalseBid {
                bid: coll * 2.0,
                reveal: false,
            }],
            1312,
        );
        assert!(
            stats.satisfied,
            "violation observed: {}",
            stats.max_violation
        );
    }
}
