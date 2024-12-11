use rand::{rngs::StdRng, SeedableRng};

use crate::auction::{
    audit_transcript, AuctionOutcome, CommitmentEvent, FalseBid, ParticipantId, PublicBroadcastDRA,
    RevealEvent, Transcript,
};
use crate::commitment::{Commitment, CommitmentScheme, Opening};
use crate::distribution::ValueDistribution;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Commit,
    Reveal,
    Resolved,
}

#[derive(Debug)]
pub enum ProtocolError {
    WrongPhase,
    DuplicateCommit(ParticipantId),
    DuplicateReveal(ParticipantId),
    MissingCommit(ParticipantId),
    AuditFailure,
}

/// A simple state machine to model the commit/reveal/resolution phases in the paper’s public-broadcast DRA.
pub struct ProtocolSession<D: ValueDistribution, S: CommitmentScheme> {
    dra: PublicBroadcastDRA<D>,
    rng: StdRng,
    scheme: S,
    phase: Phase,
    commitments: Vec<(ParticipantId, Commitment, Opening, f64, bool)>,
    transcript: Transcript,
}

impl<D: ValueDistribution, S: CommitmentScheme + Clone> ProtocolSession<D, S> {
    pub fn new(dra: PublicBroadcastDRA<D>, scheme: S, seed: u64) -> Self {
        Self {
            dra,
            rng: StdRng::seed_from_u64(seed),
            scheme,
            phase: Phase::Commit,
            commitments: Vec::new(),
            transcript: Transcript {
                commitments: Vec::new(),
                reveals: Vec::new(),
                outcome: None,
            },
        }
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn commit_real(&mut self, buyer_idx: usize, bid: f64, collateral: f64) -> Result<(), ProtocolError> {
        self.commit_internal(ParticipantId::Real(buyer_idx), bid, collateral, true)
    }

    pub fn commit_false(&mut self, idx: usize, bid: f64, collateral: f64, reveal: bool) -> Result<(), ProtocolError> {
        self.commit_internal(ParticipantId::False(idx), bid, collateral, reveal)
    }

    fn commit_internal(
        &mut self,
        id: ParticipantId,
        bid: f64,
        collateral: f64,
        will_reveal: bool,
    ) -> Result<(), ProtocolError> {
        if self.phase != Phase::Commit {
            return Err(ProtocolError::WrongPhase);
        }
        if self.commitments.iter().any(|(p, _, _, _, _)| p == &id) {
            return Err(ProtocolError::DuplicateCommit(id));
        }
        let (commitment, opening) = self.scheme.commit(bid, &mut self.rng);
        self.transcript.commitments.push(CommitmentEvent {
            participant: id.clone(),
            commitment: commitment.clone(),
        });
        self.commitments
            .push((id, commitment, opening, collateral, will_reveal));
        Ok(())
    }

    pub fn end_commit_phase(&mut self) -> Result<(), ProtocolError> {
        if self.phase != Phase::Commit {
            return Err(ProtocolError::WrongPhase);
        }
        self.phase = Phase::Reveal;
        Ok(())
    }

    pub fn reveal(&mut self, id: ParticipantId) -> Result<(), ProtocolError> {
        if self.phase != Phase::Reveal {
            return Err(ProtocolError::WrongPhase);
        }
        let idx = self
            .commitments
            .iter()
            .position(|(p, _, _, _, _)| p == &id)
            .ok_or_else(|| ProtocolError::MissingCommit(id.clone()))?;
        if self
            .transcript
            .reveals
            .iter()
            .any(|r| r.participant == id)
        {
            return Err(ProtocolError::DuplicateReveal(id));
        }
        let (_pid, commitment, opening, _collateral, _will_reveal) = &self.commitments[idx];
        let reveals_ok = self.scheme.verify(commitment, opening);
        self.transcript.reveals.push(RevealEvent {
            participant: id,
            revealed: reveals_ok,
            opening: if reveals_ok { Some(opening.clone()) } else { None },
        });
        Ok(())
    }

    pub fn end_reveal_and_resolve(mut self) -> Result<(AuctionOutcome, Transcript), ProtocolError> {
        if self.phase != Phase::Reveal {
            return Err(ProtocolError::WrongPhase);
        }
        self.phase = Phase::Resolved;
        // Apply reveals: set will_reveal flags based on reveal events.
        for (pid, _, _, _, will_reveal) in self.commitments.iter_mut() {
            if let Some(rev) = self
                .transcript
                .reveals
                .iter()
                .find(|r| r.participant == *pid)
            {
                *will_reveal = rev.revealed;
            }
        }
        // Prepare inputs for core DRA.
        let mut real_bids: Vec<f64> = Vec::new();
        let mut real_reveals: Vec<bool> = Vec::new();
        let mut false_bids: Vec<FalseBid> = Vec::new();
        let mut max_real_idx = 0usize;
        for (pid, _c, o, _coll, will_reveal) in self.commitments.iter() {
            match pid {
                ParticipantId::Real(i) => {
                    if *i >= max_real_idx {
                        max_real_idx = *i;
                    }
                    real_bids.push(o.bid);
                    real_reveals.push(*will_reveal);
                }
                ParticipantId::False(_) => false_bids.push(FalseBid {
                    bid: o.bid,
                    reveal: *will_reveal,
                }),
                ParticipantId::Auctioneer => {}
            }
        }
        // Run auction.
        let (outcome, mut transcript) = self.dra.run_with_false_bids_using_scheme_with_transcript(
            &real_bids,
            &false_bids,
            Some(&real_reveals),
            None,
            &mut self.scheme.clone(),
        );
        // Merge transcripts.
        transcript.commitments = self.transcript.commitments;
        transcript.reveals = self.transcript.reveals;
        // Final audit.
        audit_transcript(&transcript, &mut self.scheme.clone()).map_err(|_| ProtocolError::AuditFailure)?;
        Ok((outcome, transcript))
    }
}

