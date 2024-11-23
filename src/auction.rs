use rand::{rngs::StdRng, SeedableRng};

use crate::collateral::collateral_requirement;
use crate::commitment::{Commitment, CommitmentScheme, NonMalleableShaCommitment, Opening};
use crate::distribution::ValueDistribution;

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
    pub valid_bids: Vec<(ParticipantId, f64)>,
}

pub struct PublicBroadcastDRA<D: ValueDistribution> {
    distribution: D,
    alpha: f64,
}

impl<D: ValueDistribution> PublicBroadcastDRA<D> {
    pub fn new(distribution: D, alpha: f64) -> Self {
        assert!(alpha > 0.0, "alpha must be positive");
        Self { distribution, alpha }
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
        self.run_with_false_bids_using_scheme_with_transcript(valuations, false_bids, rng_seed, &mut scheme)
    }

    pub fn run_with_false_bids_using_scheme<S: CommitmentScheme>(
        &self,
        valuations: &[f64],
        false_bids: &[FalseBid],
        rng_seed: Option<u64>,
        scheme: &mut S,
    ) -> AuctionOutcome {
        let (outcome, _) = self.run_with_false_bids_using_scheme_with_transcript(valuations, false_bids, rng_seed, scheme);
        outcome
    }

    pub fn run_with_false_bids_using_scheme_with_transcript<S: CommitmentScheme>(
        &self,
        valuations: &[f64],
        false_bids: &[FalseBid],
        rng_seed: Option<u64>,
        scheme: &mut S,
    ) -> (AuctionOutcome, Transcript) {
        let n = valuations.len();
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
            outcome: None,
        };
        for (i, &v) in valuations.iter().enumerate() {
            let (commitment, opening) = scheme.commit(v, &mut rng);
            commitments.push(CommitmentRecord {
                id: ParticipantId::Real(i),
                commitment,
                opening,
                posted_collateral: collateral,
                will_reveal: true,
            });
            transcript.commitments.push(CommitmentEvent {
                participant: ParticipantId::Real(i),
                commitment: commitments.last().unwrap().commitment.clone(),
            });
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
            });
        }

        // Revelation phase: only those who reveal enter the valid set.
        let mut valid_bids: Vec<(ParticipantId, f64)> = Vec::new();
        let mut invalid_collateral = 0.0;
        for c in commitments.iter() {
            if c.will_reveal && scheme.verify(&c.commitment, &c.opening) {
                valid_bids.push((c.id.clone(), c.opening.bid));
                transcript.reveals.push(RevealEvent {
                    participant: c.id.clone(),
                    revealed: true,
                });
            } else {
                invalid_collateral += c.posted_collateral;
                transcript.reveals.push(RevealEvent {
                    participant: c.id.clone(),
                    revealed: false,
                });
            }
        }

        // Resolution phase.
        let mut highest: Option<(ParticipantId, f64)> = None;
        let mut second: Option<f64> = None;
        for (id, bid) in valid_bids.iter() {
            match highest {
                None => highest = Some((id.clone(), *bid)),
                Some((ref hid, hbid)) => {
                    if *bid > hbid
                        || (*bid == hbid && id.tie_rank() < hid.tie_rank())
                    {
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
                        (None, bid, 0.0, 0.0, invalid_collateral)
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
    fn pedersen_backend_matches_sha_outcome() {
        use crate::commitment::PedersenRistrettoCommitment;
        use crate::commitment::NonMalleableShaCommitment;
        let dist = Uniform::new(0.0, 20.0);
        let dra = PublicBroadcastDRA::new(dist, 1.0);
        let vals = [12.0, 7.0, 15.0];
        let fbs = [FalseBid { bid: 21.0, reveal: false }];
        let mut sha = NonMalleableShaCommitment;
        let mut ped = PedersenRistrettoCommitment;
        let o1 = dra.run_with_false_bids_using_scheme(&vals, &fbs, Some(5), &mut sha);
        let o2 = dra.run_with_false_bids_using_scheme(&vals, &fbs, Some(5), &mut ped);
        assert_eq!(o1.winner, o2.winner);
        assert!((o1.payment - o2.payment).abs() < 1e-9);
    }
}
#[derive(Clone, Debug)]
pub struct CommitmentEvent {
    pub participant: ParticipantId,
    pub commitment: Commitment,
}

#[derive(Clone, Debug)]
pub struct RevealEvent {
    pub participant: ParticipantId,
    pub revealed: bool,
}

#[derive(Clone, Debug)]
pub struct Transcript {
    pub commitments: Vec<CommitmentEvent>,
    pub reveals: Vec<RevealEvent>,
    pub outcome: Option<AuctionOutcome>,
}
