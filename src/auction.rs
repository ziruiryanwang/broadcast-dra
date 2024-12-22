use rand::{SeedableRng, rngs::StdRng};

use crate::collateral::collateral_requirement;
use crate::commitment::{Commitment, CommitmentScheme, NonMalleableShaCommitment, Opening};
use crate::distribution::ValueDistribution;
use crate::protocol::Phase;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ParticipantId {
    Auctioneer,
    Real(usize),
    False(usize),
}

impl ParticipantId {
    fn tie_rank(&self) -> u64 {
        match self {
            ParticipantId::Auctioneer => 0,
            ParticipantId::Real(i) => 1 + (*i as u64),
            ParticipantId::False(j) => 50_000 + (*j as u64),
        }
    }
}

#[derive(Clone, Debug)]
struct CommitmentRecord {
    id: ParticipantId,
    commitment: Commitment,
    opening: Opening,
    posted_collateral: f64,
    will_reveal: bool,
}

#[derive(Clone, Debug, Default)]
pub struct FalseBid {
    pub bid: f64,
    pub reveal: bool,
}

#[derive(Clone, Debug)]
pub struct AuctionOutcome {
    pub reserve: f64,
    pub collateral: f64,
    pub winner: Option<ParticipantId>,
    pub winning_bid: f64,
    pub payment: f64,
    pub transferred_collateral: f64,
    pub forfeited_to_auctioneer: f64,
    pub auctioneer_penalty: f64,
    pub valid_bids: Vec<(ParticipantId, f64)>,
}

#[derive(Clone, Debug)]
pub struct PublicBroadcastDRA<D: ValueDistribution> {
    distribution: D,
    alpha: f64,
}

impl<D: ValueDistribution> PublicBroadcastDRA<D> {
    pub fn new(distribution: D, alpha: f64) -> Self {
        assert!(alpha > 0.0, "alpha must be positive");
        Self {
            distribution,
            alpha,
        }
    }

    pub fn validate_inputs(&self, buyers: usize) -> Result<(), ValidationError> {
        if buyers == 0 {
            return Err(ValidationError::InsufficientBuyers);
        }
        if let Some(max_alpha) = self.distribution.strong_regular_alpha() {
            if self.alpha > max_alpha + f64::EPSILON {
                return Err(ValidationError::AlphaTooLarge {
                    requested: self.alpha,
                    supported: max_alpha,
                });
            }
        }
        Ok(())
    }

    pub fn collateral(&self, n_buyers: usize) -> f64 {
        collateral_requirement(n_buyers, &self.distribution, self.alpha)
    }

    /// Run the DRA with public broadcast. `valuations` are the honest buyers'
    /// values, and `false_bids` represents auctioneer-inserted bids.
    pub fn run_with_false_bids(
        &self,
        valuations: &[f64],
        false_bids: &[FalseBid],
        rng_seed: Option<u64>,
    ) -> AuctionOutcome {
        let mut scheme = NonMalleableShaCommitment::default();
        self.run_with_false_bids_using_scheme(valuations, false_bids, rng_seed, &mut scheme)
    }

    pub fn run_with_false_bids_with_transcript(
        &self,
        valuations: &[f64],
        false_bids: &[FalseBid],
        rng_seed: Option<u64>,
    ) -> (AuctionOutcome, Transcript) {
        let mut scheme = NonMalleableShaCommitment::default();
        self.run_with_false_bids_using_scheme_with_transcript(
            valuations,
            false_bids,
            None,
            rng_seed,
            &mut scheme,
        )
    }

    pub fn run_with_false_bids_using_scheme<S: CommitmentScheme>(
        &self,
        valuations: &[f64],
        false_bids: &[FalseBid],
        rng_seed: Option<u64>,
        scheme: &mut S,
    ) -> AuctionOutcome {
        let (outcome, _) = self.run_with_false_bids_using_scheme_with_transcript(
            valuations, false_bids, None, rng_seed, scheme,
        );
        outcome
    }

    pub fn run_with_false_bids_using_scheme_with_transcript<S: CommitmentScheme>(
        &self,
        valuations: &[f64],
        false_bids: &[FalseBid],
        real_reveals: Option<&[bool]>,
        rng_seed: Option<u64>,
        scheme: &mut S,
    ) -> (AuctionOutcome, Transcript) {
        let n = valuations.len();
        self.validate_inputs(n).expect("invalid inputs for auction");
        let collateral = self.collateral(n);
        let reserve = self.distribution.reserve_price();
        let mut rng = rng_seed
            .map(StdRng::seed_from_u64)
            .unwrap_or_else(|| StdRng::from_entropy());

        // Commitment phase.
        let mut commitments: Vec<CommitmentRecord> = Vec::new();
        let mut transcript = Transcript {
            commitments: Vec::new(),
            reveals: Vec::new(),
            broadcasts: Vec::new(),
            timings: PhaseTimings::default(),
            outcome: None,
        };
        let mut clock: u64 = 0;
        for (i, &v) in valuations.iter().enumerate() {
            let (commitment, opening) = scheme.commit(v, &mut rng);
            commitments.push(CommitmentRecord {
                id: ParticipantId::Real(i),
                commitment,
                opening,
                posted_collateral: collateral,
                will_reveal: real_reveals
                    .map(|r| r.get(i).copied().unwrap_or(true))
                    .unwrap_or(true),
            });
            transcript.commitments.push(CommitmentEvent {
                participant: ParticipantId::Real(i),
                commitment: commitments.last().unwrap().commitment.clone(),
                timestamp: clock,
            });
            transcript.broadcasts.push(BroadcastEvent {
                timestamp: clock,
                sender: ParticipantId::Real(i),
                message: BroadcastMessage::CommitmentPublished,
            });
            clock += 1;
        }
        for (j, fb) in false_bids.iter().enumerate() {
            let (commitment, opening) = scheme.commit(fb.bid, &mut rng);
            commitments.push(CommitmentRecord {
                id: ParticipantId::False(j),
                commitment,
                opening,
                posted_collateral: collateral,
                will_reveal: fb.reveal,
            });
            transcript.commitments.push(CommitmentEvent {
                participant: ParticipantId::False(j),
                commitment: commitments.last().unwrap().commitment.clone(),
                timestamp: clock,
            });
            transcript.broadcasts.push(BroadcastEvent {
                timestamp: clock,
                sender: ParticipantId::False(j),
                message: BroadcastMessage::CommitmentPublished,
            });
            clock += 1;
        }
        let commit_deadline = clock;
        transcript.broadcasts.push(BroadcastEvent {
            timestamp: commit_deadline,
            sender: ParticipantId::Auctioneer,
            message: BroadcastMessage::PhaseTransition {
                phase: Phase::Reveal,
                reason: PhaseTransitionReason::Manual,
            },
        });
        clock = commit_deadline.saturating_add(1);

        // Revelation phase: only those who reveal enter the valid set.
        let mut valid_bids: Vec<(ParticipantId, f64)> = Vec::new();
        let mut invalid_collateral = 0.0;
        for c in commitments.iter() {
            if c.will_reveal && scheme.verify(&c.commitment, &c.opening) {
                valid_bids.push((c.id.clone(), c.opening.bid));
                transcript.reveals.push(RevealEvent {
                    participant: c.id.clone(),
                    revealed: true,
                    opening: Some(c.opening.clone()),
                    timestamp: clock,
                });
                transcript.broadcasts.push(BroadcastEvent {
                    timestamp: clock,
                    sender: c.id.clone(),
                    message: BroadcastMessage::RevealPublished { success: true },
                });
            } else {
                invalid_collateral += c.posted_collateral;
                transcript.reveals.push(RevealEvent {
                    participant: c.id.clone(),
                    revealed: false,
                    opening: None,
                    timestamp: clock,
                });
                transcript.broadcasts.push(BroadcastEvent {
                    timestamp: clock,
                    sender: ParticipantId::Auctioneer,
                    message: BroadcastMessage::Timeout {
                        phase: Phase::Reveal,
                        target: c.id.clone(),
                    },
                });
            }
            clock += 1;
        }
        let reveal_deadline = clock;
        transcript.broadcasts.push(BroadcastEvent {
            timestamp: reveal_deadline,
            sender: ParticipantId::Auctioneer,
            message: BroadcastMessage::PhaseTransition {
                phase: Phase::Resolved,
                reason: PhaseTransitionReason::Manual,
            },
        });
        transcript.timings = PhaseTimings {
            commit_deadline,
            reveal_deadline,
        };

        // Resolution phase.
        let mut highest: Option<(ParticipantId, f64)> = None;
        let mut second: Option<f64> = None;
        for (id, bid) in valid_bids.iter() {
            match highest {
                None => highest = Some((id.clone(), *bid)),
                Some((ref hid, hbid)) => {
                    if *bid > hbid || (*bid == hbid && id.tie_rank() < hid.tie_rank()) {
                        second = Some(hbid);
                        highest = Some((id.clone(), *bid));
                    } else if *bid == hbid {
                        if second.map(|s| *bid > s).unwrap_or(true) {
                            second = Some(*bid);
                        }
                    } else if second.map(|s| *bid > s).unwrap_or(true) && *bid < hbid {
                        second = Some(*bid);
                    }
                }
            }
        }

        let (winner, winning_bid, payment, transferred_collateral, forfeited_to_auctioneer) =
            match highest {
                None => (None, 0.0, 0.0, 0.0, invalid_collateral),
                Some((id, bid)) => {
                    if bid > reserve {
                        let second_bid = second.unwrap_or(0.0);
                        let pay = reserve.max(second_bid);
                        (Some(id), bid, pay, invalid_collateral, 0.0)
                    } else {
                        (None, bid, 0.0, invalid_collateral, 0.0)
                    }
                }
            };

        let outcome = AuctionOutcome {
            reserve,
            collateral,
            winner,
            winning_bid,
            payment,
            transferred_collateral,
            forfeited_to_auctioneer,
            auctioneer_penalty: 0.0,
            valid_bids,
        };
        transcript.outcome = Some(outcome.clone());
        (outcome, transcript)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::distribution::{Exponential, Uniform, ValueDistribution};

    #[test]
    fn honest_bidders_pay_second_price_above_reserve() {
        let dist = Uniform::new(0.0, 20.0);
        let dra = PublicBroadcastDRA::new(dist.clone(), 1.0);
        let outcome = dra.run_with_false_bids(&[15.0, 9.0, 11.0], &[], Some(7));
        assert_eq!(outcome.winner, Some(ParticipantId::Real(0)));
        assert_eq!(outcome.payment, dist.reserve_price().max(11.0));
    }

    #[test]
    fn no_sale_when_highest_below_reserve() {
        let dist = Exponential::new(1.0);
        let dra = PublicBroadcastDRA::new(dist, 1.0);
        let outcome = dra.run_with_false_bids(&[0.2, 0.5], &[], Some(42));
        assert!(outcome.winner.is_none());
        assert_eq!(outcome.payment, 0.0);
    }

    #[test]
    fn withheld_false_bid_forfeits_collateral() {
        let dist = Exponential::new(0.5);
        let dra = PublicBroadcastDRA::new(dist, 1.0);
        let false_bid = FalseBid {
            bid: 100.0,
            reveal: false,
        };
        let outcome = dra.run_with_false_bids(&[5.0], &[false_bid], Some(1));
        assert!(outcome.forfeited_to_auctioneer > 0.0 || outcome.transferred_collateral > 0.0);
    }

    #[test]
    fn tie_breaks_lexicographically() {
        let dist = Uniform::new(0.0, 20.0);
        let dra = PublicBroadcastDRA::new(dist.clone(), 1.0);
        let outcome = dra.run_with_false_bids(&[12.0, 12.0], &[], Some(3));
        assert_eq!(outcome.winner, Some(ParticipantId::Real(0)));
        assert!((outcome.payment - 12.0).abs() < 1e-6);
    }

    #[test]
    fn winner_collects_forfeited_collateral_when_sale_occurs() {
        let dist = Uniform::new(0.0, 20.0);
        let dra = PublicBroadcastDRA::new(dist, 1.0);
        let false_bid = FalseBid {
            bid: 25.0,
            reveal: false,
        };
        let outcome = dra.run_with_false_bids(&[18.0], &[false_bid], Some(99));
        assert!(outcome.winner.is_some());
        assert!(outcome.transferred_collateral > 0.0);
    }

    #[test]
    fn collateral_transfers_to_highest_valid_bidder() {
        let dist = Uniform::new(0.0, 20.0);
        let dra = PublicBroadcastDRA::new(dist.clone(), 1.0);
        let false_bid = FalseBid {
            bid: 30.0,
            reveal: false,
        };
        let outcome_sale =
            dra.run_with_false_bids(&[dist.reserve_price() + 5.0], &[false_bid.clone()], Some(7));
        assert!(outcome_sale.winner.is_some());
        assert!((outcome_sale.transferred_collateral - dra.collateral(1)).abs() < 1e-9);
        assert_eq!(outcome_sale.forfeited_to_auctioneer, 0.0);

        let outcome_nosale =
            dra.run_with_false_bids(&[dist.reserve_price() - 3.0], &[false_bid], Some(8));
        assert!(outcome_nosale.winner.is_none());
        assert!((outcome_nosale.transferred_collateral - dra.collateral(1)).abs() < 1e-9);
        assert_eq!(outcome_nosale.forfeited_to_auctioneer, 0.0);
    }

    #[test]
    fn pedersen_backend_matches_sha_outcome() {
        use crate::commitment::NonMalleableShaCommitment;
        use crate::commitment::PedersenRistrettoCommitment;
        let dist = Uniform::new(0.0, 20.0);
        let dra = PublicBroadcastDRA::new(dist, 1.0);
        let vals = [12.0, 7.0, 15.0];
        let fbs = [FalseBid {
            bid: 21.0,
            reveal: false,
        }];
        let mut sha = NonMalleableShaCommitment;
        let mut ped = PedersenRistrettoCommitment;
        let o1 = dra.run_with_false_bids_using_scheme(&vals, &fbs, Some(5), &mut sha);
        let o2 = dra.run_with_false_bids_using_scheme(&vals, &fbs, Some(5), &mut ped);
        assert_eq!(o1.winner, o2.winner);
        assert!((o1.payment - o2.payment).abs() < 1e-9);
    }

    #[test]
    #[should_panic]
    fn validate_inputs_panic_on_zero_buyers() {
        let dist = Uniform::new(0.0, 10.0);
        let dra = PublicBroadcastDRA::new(dist, 1.0);
        let _ = dra.run_with_false_bids(&[], &[], None);
    }
}
#[derive(Clone, Debug)]
pub struct CommitmentEvent {
    pub participant: ParticipantId,
    pub commitment: Commitment,
    pub timestamp: u64,
}

#[derive(Clone, Debug)]
pub struct RevealEvent {
    pub participant: ParticipantId,
    pub revealed: bool,
    pub opening: Option<Opening>,
    pub timestamp: u64,
}

#[derive(Clone, Debug)]
pub struct PhaseTimings {
    pub commit_deadline: u64,
    pub reveal_deadline: u64,
}

impl Default for PhaseTimings {
    fn default() -> Self {
        Self {
            commit_deadline: 0,
            reveal_deadline: 0,
        }
    }
}

#[derive(Clone, Debug)]
pub enum PhaseTransitionReason {
    Manual,
    Deadline,
}

#[derive(Clone, Debug)]
pub enum BroadcastMessage {
    CommitmentPublished,
    RevealPublished {
        success: bool,
    },
    PhaseTransition {
        phase: Phase,
        reason: PhaseTransitionReason,
    },
    Timeout {
        phase: Phase,
        target: ParticipantId,
    },
}

#[derive(Clone, Debug)]
pub struct BroadcastEvent {
    pub timestamp: u64,
    pub sender: ParticipantId,
    pub message: BroadcastMessage,
}

#[derive(Clone, Debug)]
pub struct Transcript {
    pub commitments: Vec<CommitmentEvent>,
    pub reveals: Vec<RevealEvent>,
    pub broadcasts: Vec<BroadcastEvent>,
    pub timings: PhaseTimings,
    pub outcome: Option<AuctionOutcome>,
}

#[derive(Debug)]
pub enum AuditError {
    MissingOutcome,
    MissingTimings,
    RevealWithoutCommit(ParticipantId),
    BadOpening(ParticipantId),
    DeadlineViolation {
        participant: ParticipantId,
        phase: Phase,
        timestamp: u64,
    },
    UnorderedEvents(&'static str),
}

/// Audit a transcript against a commitment scheme to ensure the openings match commitments and
/// every reveal references a committed party (Definition 8).
pub fn audit_transcript<S: CommitmentScheme>(
    transcript: &Transcript,
    scheme: &mut S,
) -> Result<(), AuditError> {
    let outcome = transcript
        .outcome
        .as_ref()
        .ok_or(AuditError::MissingOutcome)?;
    if transcript.timings.reveal_deadline < transcript.timings.commit_deadline {
        return Err(AuditError::MissingTimings);
    }
    use std::collections::HashMap;
    let mut commit_map: HashMap<ParticipantId, (&Commitment, u64)> = HashMap::new();
    let mut last_ts = 0u64;
    for c in transcript.commitments.iter() {
        if c.timestamp < last_ts {
            return Err(AuditError::UnorderedEvents("commitments"));
        }
        last_ts = c.timestamp;
        if c.timestamp > transcript.timings.commit_deadline {
            return Err(AuditError::DeadlineViolation {
                participant: c.participant.clone(),
                phase: Phase::Commit,
                timestamp: c.timestamp,
            });
        }
        commit_map.insert(c.participant.clone(), (&c.commitment, c.timestamp));
    }
    last_ts = transcript.timings.commit_deadline;
    for rev in transcript.reveals.iter() {
        if rev.timestamp < last_ts {
            return Err(AuditError::UnorderedEvents("reveals"));
        }
        last_ts = rev.timestamp;
        if rev.timestamp > transcript.timings.reveal_deadline {
            return Err(AuditError::DeadlineViolation {
                participant: rev.participant.clone(),
                phase: Phase::Reveal,
                timestamp: rev.timestamp,
            });
        }
        let (commit, commit_ts) = commit_map
            .get(&rev.participant)
            .ok_or_else(|| AuditError::RevealWithoutCommit(rev.participant.clone()))?;
        if rev.timestamp < *commit_ts {
            return Err(AuditError::DeadlineViolation {
                participant: rev.participant.clone(),
                phase: Phase::Commit,
                timestamp: rev.timestamp,
            });
        }
        if rev.revealed {
            let opening = rev
                .opening
                .as_ref()
                .ok_or_else(|| AuditError::BadOpening(rev.participant.clone()))?;
            if !scheme.verify(commit, opening) {
                return Err(AuditError::BadOpening(rev.participant.clone()));
            }
            let _ = outcome
                .valid_bids
                .iter()
                .find(|(p, _)| p == &rev.participant)
                .ok_or_else(|| AuditError::BadOpening(rev.participant.clone()))?;
        }
    }
    last_ts = 0;
    for event in transcript.broadcasts.iter() {
        if event.timestamp < last_ts {
            return Err(AuditError::UnorderedEvents("broadcasts"));
        }
        last_ts = event.timestamp;
        match &event.message {
            BroadcastMessage::CommitmentPublished => {
                if event.timestamp > transcript.timings.commit_deadline {
                    return Err(AuditError::DeadlineViolation {
                        participant: event.sender.clone(),
                        phase: Phase::Commit,
                        timestamp: event.timestamp,
                    });
                }
            }
            BroadcastMessage::RevealPublished { .. } => {
                if event.timestamp > transcript.timings.reveal_deadline {
                    return Err(AuditError::DeadlineViolation {
                        participant: event.sender.clone(),
                        phase: Phase::Reveal,
                        timestamp: event.timestamp,
                    });
                }
            }
            BroadcastMessage::Timeout { phase, target } => {
                let cutoff = match phase {
                    Phase::Commit => transcript.timings.commit_deadline,
                    Phase::Reveal | Phase::Resolved => transcript.timings.reveal_deadline,
                };
                if event.timestamp < cutoff {
                    return Err(AuditError::DeadlineViolation {
                        participant: target.clone(),
                        phase: *phase,
                        timestamp: event.timestamp,
                    });
                }
            }
            BroadcastMessage::PhaseTransition { phase, .. } => match phase {
                Phase::Commit => {}
                Phase::Reveal => {
                    if event.timestamp < transcript.timings.commit_deadline {
                        return Err(AuditError::DeadlineViolation {
                            participant: event.sender.clone(),
                            phase: *phase,
                            timestamp: event.timestamp,
                        });
                    }
                }
                Phase::Resolved => {
                    if event.timestamp < transcript.timings.reveal_deadline {
                        return Err(AuditError::DeadlineViolation {
                            participant: event.sender.clone(),
                            phase: *phase,
                            timestamp: event.timestamp,
                        });
                    }
                }
            },
        }
    }
    Ok(())
}

#[derive(Debug)]
pub enum ValidationError {
    InsufficientBuyers,
    AlphaTooLarge { requested: f64, supported: f64 },
}
