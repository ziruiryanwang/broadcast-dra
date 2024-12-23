use crate::auction::{
    AuctionOutcome, FalseBid, ParticipantId, PhaseTimings, PublicBroadcastDRA, Transcript,
};
use crate::commitment::{CommitmentScheme, NonMalleableShaCommitment};
use crate::distribution::ValueDistribution;
use crate::network::{CentralizedChannel, MessagePayload};
use crate::protocol::Phase;
use serde::Serialize;

/// Mirrors ProtocolSession with a centralized forwarding channel to script Example 1 / Definition 23.
#[derive(Clone, Debug)]
pub struct CentralizedProtocolDriver<D: ValueDistribution, S: CommitmentScheme> {
    dra: PublicBroadcastDRA<D>,
    scheme: S,
    _schedule: PhaseTimings,
    valuations: Vec<Option<f64>>,
    real_reveals: Vec<bool>,
    false_bids: Vec<FalseBid>,
    channel: CentralizedChannel,
    buyers: usize,
}

impl<D: ValueDistribution, S: CommitmentScheme + Clone> CentralizedProtocolDriver<D, S> {
    pub fn new(
        dra: PublicBroadcastDRA<D>,
        scheme: S,
        buyer_count: usize,
        schedule: PhaseTimings,
    ) -> Self {
        let mut participants = vec![ParticipantId::Auctioneer];
        for i in 0..buyer_count {
            participants.push(ParticipantId::Real(i));
        }
        Self {
            dra,
            scheme,
            _schedule: schedule,
            valuations: vec![None; buyer_count],
            real_reveals: vec![true; buyer_count],
            false_bids: Vec::new(),
            channel: CentralizedChannel::new(participants),
            buyers: buyer_count,
        }
    }

    pub fn channel(&self) -> &CentralizedChannel {
        &self.channel
    }

    pub fn channel_mut(&mut self) -> &mut CentralizedChannel {
        &mut self.channel
    }

    pub fn collateral(&self) -> f64 {
        self.dra.collateral(self.buyers)
    }

    pub fn commit_real(&mut self, buyer_idx: usize, bid: f64) {
        assert!(
            buyer_idx < self.buyers,
            "buyer index {} >= {}",
            buyer_idx,
            self.buyers
        );
        self.valuations[buyer_idx] = Some(bid);
        self.real_reveals[buyer_idx] = true;
        self.channel.private_message(
            ParticipantId::Real(buyer_idx),
            ParticipantId::Auctioneer,
            Phase::Commit,
            MessagePayload::Commitment {
                from: ParticipantId::Real(buyer_idx),
            },
        );
    }

    pub fn commit_false(&mut self, idx: usize, bid: f64, reveal: bool) {
        self.false_bids.push(FalseBid { bid, reveal });
        let participant = ParticipantId::False(idx);
        self.channel.register(participant.clone());
        self.channel.private_message(
            participant.clone(),
            ParticipantId::Auctioneer,
            Phase::Commit,
            MessagePayload::Commitment { from: participant },
        );
    }

    pub fn forward_commit_to(&mut self, origin: ParticipantId, recipients: &[ParticipantId]) {
        self.channel.broadcast_subset(
            ParticipantId::Auctioneer,
            Phase::Commit,
            MessagePayload::Commitment { from: origin },
            recipients,
        );
    }

    pub fn announce_commit_end_to(&mut self, recipients: &[ParticipantId]) {
        self.channel.broadcast_subset(
            ParticipantId::Auctioneer,
            Phase::Commit,
            MessagePayload::EndPhase { phase: Phase::Commit },
            recipients,
        );
    }

    /// Send end-of-commit notices to disjoint subsets (models staggered delivery).
    pub fn announce_commit_end_staggered(
        &mut self,
        first_batch: &[ParticipantId],
        second_batch: &[ParticipantId],
    ) {
        self.announce_commit_end_to(first_batch);
        self.announce_commit_end_to(second_batch);
    }

    pub fn announce_reveal_end_to(&mut self, recipients: &[ParticipantId]) {
        self.channel.broadcast_subset(
            ParticipantId::Auctioneer,
            Phase::Reveal,
            MessagePayload::EndPhase {
                phase: Phase::Reveal,
            },
            recipients,
        );
    }

    pub fn notify_timeout(&mut self, target: ParticipantId, recipients: &[ParticipantId]) {
        self.channel.broadcast_subset(
            ParticipantId::Auctioneer,
            Phase::Reveal,
            MessagePayload::Timeout { target },
            recipients,
        );
    }

    pub fn publish_reveal_to(
        &mut self,
        origin: ParticipantId,
        recipients: &[ParticipantId],
        success: bool,
    ) {
        self.channel.broadcast_subset(
            origin.clone(),
            Phase::Reveal,
            MessagePayload::Reveal {
                from: origin,
                success,
            },
            recipients,
        );
    }

    pub fn withhold_real_reveal(&mut self, idx: usize) {
        assert!(idx < self.real_reveals.len());
        self.real_reveals[idx] = false;
    }

    pub fn set_false_bid_reveal(&mut self, idx: usize, reveal: bool) {
        if let Some(fb) = self.false_bids.get_mut(idx) {
            fb.reveal = reveal;
        }
    }

    pub fn resolve(
        mut self,
        rng_seed: Option<u64>,
    ) -> (AuctionOutcome, Transcript, CentralizedChannel) {
        let valuations: Vec<f64> = self
            .valuations
            .into_iter()
            .map(|opt| opt.expect("missing buyer valuation in centralized driver"))
            .collect();
        let (outcome, transcript) = self.dra.run_with_false_bids_using_scheme_with_transcript(
            &valuations,
            &self.false_bids,
            Some(&self.real_reveals),
            rng_seed,
            &mut self.scheme,
        );
        (outcome, transcript, self.channel)
    }
}

/// Outcome of the adaptive-reserve deviation used in Theorem 22.
#[derive(Clone, Debug)]
pub struct CentralizedDeviationResult {
    pub report: AdaptiveReserveDeviationReport,
    pub channel: CentralizedChannel,
}

/// Script Definition 23's adaptive-reserve deviation using the centralized driver.
pub fn scripted_adaptive_reserve_run<D: ValueDistribution + Clone>(
    dist: D,
    alpha: f64,
    buyer_a: f64,
    buyer_b: f64,
    threshold: f64,
) -> CentralizedDeviationResult {
    let baseline_dra = PublicBroadcastDRA::new(dist.clone(), alpha);
    let baseline = baseline_dra.run_with_false_bids(&[buyer_a, buyer_b], &[], Some(31));
    let baseline_revenue = baseline.payment + baseline.forfeited_to_auctioneer;
    let schedule = PhaseTimings {
        commit_deadline: 4,
        reveal_deadline: 8,
    };
    let mut driver = CentralizedProtocolDriver::new(
        PublicBroadcastDRA::new(dist, alpha),
        NonMalleableShaCommitment,
        2,
        schedule,
    );
    driver.commit_real(0, buyer_a);
    driver.commit_real(1, buyer_b);
    // Buyer A's commitment is never forwarded to buyer B.
    driver.forward_commit_to(ParticipantId::Real(1), &[ParticipantId::Real(0)]);
    driver.announce_commit_end_to(&[ParticipantId::Real(0)]);
    driver.publish_reveal_to(
        ParticipantId::Real(0),
        &[ParticipantId::Auctioneer],
        true,
    );
    if buyer_a >= threshold {
        let false_bid = buyer_a + driver.collateral();
        driver.commit_false(0, false_bid, true);
        driver.forward_commit_to(ParticipantId::False(0), &[ParticipantId::Real(1)]);
    }
    driver.announce_commit_end_to(&[ParticipantId::Real(1)]);
    driver.publish_reveal_to(
        ParticipantId::Real(1),
        &[ParticipantId::Auctioneer],
        true,
    );
    let (outcome, _, channel) = driver.resolve(Some(57));
    let deviation_revenue = outcome.payment + outcome.forfeited_to_auctioneer;
    CentralizedDeviationResult {
        report: AdaptiveReserveDeviationReport {
            baseline_revenue,
            deviation_revenue,
        },
        channel,
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct AdaptiveReserveDeviationReport {
    pub baseline_revenue: f64,
    pub deviation_revenue: f64,
}

/// Simulate Definition 23's adaptive-reserve deviation for two buyers in a centralized setting.
pub fn adaptive_reserve_deviation<D: ValueDistribution + Clone>(
    dist: D,
    alpha: f64,
    buyer_a: f64,
    buyer_b: f64,
    threshold: f64,
) -> AdaptiveReserveDeviationReport {
    let dra = PublicBroadcastDRA::new(dist.clone(), alpha);
    let baseline = dra.run_with_false_bids(&[buyer_a, buyer_b], &[], Some(11));
    let baseline_revenue = baseline.payment + baseline.forfeited_to_auctioneer;
    let reserve = dist.reserve_price();
    let collateral = dra.collateral(2);
    let deviation_revenue = adaptive_revenue(
        reserve,
        collateral,
        threshold,
        buyer_a,
        buyer_b,
        baseline_revenue,
    );
    AdaptiveReserveDeviationReport {
        baseline_revenue,
        deviation_revenue,
    }
}

fn adaptive_revenue(
    reserve: f64,
    collateral: f64,
    threshold: f64,
    buyer_a: f64,
    buyer_b: f64,
    baseline: f64,
) -> f64 {
    if buyer_a < threshold {
        return baseline;
    }
    if reserve >= buyer_a.max(buyer_b) {
        return 0.0;
    }
    if buyer_b < buyer_a && buyer_a > reserve {
        return reserve.max(buyer_b);
    }
    if buyer_b >= buyer_a && buyer_b <= buyer_a + collateral && buyer_b > reserve {
        return reserve.max(buyer_a);
    }
    if buyer_b > buyer_a + collateral {
        return buyer_a + collateral;
    }
    baseline
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auction::{PhaseTimings, PublicBroadcastDRA};
    use crate::commitment::NonMalleableShaCommitment;
    use crate::distribution::{Exponential, Uniform};
    use crate::network::MessagePayload;
    use crate::protocol::ProtocolSession;
    use crate::simulation::{DeviationModel, simulate_safe_deviation_bound};

    #[test]
    fn adaptive_reserve_attack_increases_revenue() {
        let dist = Exponential::new(0.01); // reserve = 100
        let threshold = 120.0;
        let report = adaptive_reserve_deviation(dist, 1.0, 150.0, 400.0, threshold);
        assert!(
            report.deviation_revenue > report.baseline_revenue,
            "expected revenue gain, saw baseline {} vs deviated {}",
            report.baseline_revenue,
            report.deviation_revenue
        );
    }

    #[test]
    fn adaptive_reserve_matches_baseline_when_threshold_not_met() {
        let dist = Exponential::new(0.01);
        let threshold = 200.0;
        let report = adaptive_reserve_deviation(dist, 1.0, 150.0, 400.0, threshold);
        assert!((report.deviation_revenue - report.baseline_revenue).abs() < 1e-9);
    }

    #[test]
    fn example_one_censors_commitment() {
        let dist = Uniform::new(0.0, 20.0);
        let driver_dra = PublicBroadcastDRA::new(dist.clone(), 1.0);
        let schedule = PhaseTimings {
            commit_deadline: 4,
            reveal_deadline: 8,
        };
        let mut driver =
            CentralizedProtocolDriver::new(driver_dra, NonMalleableShaCommitment, 2, schedule.clone());
        driver.commit_real(0, 10.0);
        driver.forward_commit_to(ParticipantId::Real(0), &[ParticipantId::Real(0)]);
        driver.commit_real(1, 5.0);
        driver.forward_commit_to(ParticipantId::Real(1), &[ParticipantId::Real(0)]);

        let omissions = driver
            .channel()
            .omitted_for(&ParticipantId::Real(1));
        assert!(
            omissions.iter().any(|entry| matches!(
                entry.payload,
                MessagePayload::Commitment {
                    from: ParticipantId::Real(0)
                }
            )),
            "buyer B should miss A's commitment in centralized channel"
        );

        let broadcast_dra = PublicBroadcastDRA::new(dist, 1.0);
        let collateral = broadcast_dra.collateral(2);
        let participants = vec![ParticipantId::Real(0), ParticipantId::Real(1)];
        let mut session = ProtocolSession::new(
            broadcast_dra,
            NonMalleableShaCommitment,
            42,
            schedule,
            participants,
        );
        session
            .commit_real(0, 10.0, collateral)
            .expect("commit buyer 0");
        session
            .commit_real(1, 5.0, collateral)
            .expect("commit buyer 1");
        let view = session
            .network_log()
            .per_recipient_view(&ParticipantId::Real(1));
        assert!(view.iter().any(|msg| matches!(
            msg.payload,
            MessagePayload::Commitment {
                from: ParticipantId::Real(0)
            }
        )));
    }

    #[test]
    fn staggered_commit_end_produces_asymmetric_views() {
        let dist = Uniform::new(0.0, 20.0);
        let driver_dra = PublicBroadcastDRA::new(dist, 1.0);
        let schedule = PhaseTimings {
            commit_deadline: 4,
            reveal_deadline: 8,
        };
        let mut driver =
            CentralizedProtocolDriver::new(driver_dra, NonMalleableShaCommitment, 2, schedule);
        driver.commit_real(0, 7.0);
        driver.commit_real(1, 6.0);
        driver.announce_commit_end_staggered(
            &[ParticipantId::Real(0)],
            &[ParticipantId::Real(1)],
        );
        let omissions_b = driver.channel().omitted_for(&ParticipantId::Real(1));
        let omissions_a = driver.channel().omitted_for(&ParticipantId::Real(0));
        assert!(
            omissions_b.iter().any(|o| matches!(o.payload, MessagePayload::EndPhase { phase: Phase::Commit })),
            "buyer B should miss early commit-end notice"
        );
        assert!(
            omissions_a.iter().any(|o| matches!(o.payload, MessagePayload::EndPhase { phase: Phase::Commit })),
            "buyer A should miss late commit-end notice"
        );
    }

    #[test]
    fn adaptive_reserve_driver_exceeds_baseline_only_when_censored() {
        let dist = Exponential::new(0.01);
        let threshold = 120.0;
        let result =
            scripted_adaptive_reserve_run(dist.clone(), 1.0, 150.0, 400.0, threshold);
        assert!(
            result.report.deviation_revenue > result.report.baseline_revenue,
            "centralized run should outperform baseline"
        );
        let coll = PublicBroadcastDRA::new(dist.clone(), 1.0).collateral(2);
        let safe = simulate_safe_deviation_bound(
            dist,
            1.0,
            2,
            250,
            DeviationModel::Multiple(vec![FalseBid {
                bid: coll,
                reveal: false,
            }]),
            5150,
        );
        assert!(
            safe.satisfied,
            "broadcast simulation should remain bounded: {}",
            safe.max_violation
        );
    }
}
