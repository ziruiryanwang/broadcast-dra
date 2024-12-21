use rand::{SeedableRng, rngs::StdRng};

use crate::auction::{
    AuctionOutcome, BroadcastEvent, BroadcastMessage, CommitmentEvent, FalseBid, ParticipantId,
    PhaseTimings, PhaseTransitionReason, PublicBroadcastDRA, RevealEvent, Transcript,
    audit_transcript,
};
use crate::commitment::{Commitment, CommitmentScheme, Opening};
use crate::distribution::ValueDistribution;
use crate::network::{BroadcastLog, DeliveredMessage, MessagePayload};

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
    ClockRewind { requested: u64, current: u64 },
    DeadlineExceeded(Phase),
    AuditFailure,
}

/// A simple state machine to model the commit/reveal/resolution phases in the paper’s public-broadcast DRA.
pub struct ProtocolSession<D: ValueDistribution, S: CommitmentScheme> {
    dra: PublicBroadcastDRA<D>,
    rng: StdRng,
    scheme: S,
    phase: Phase,
    schedule: PhaseTimings,
    current_time: u64,
    commitments: Vec<(ParticipantId, Commitment, Opening, f64, bool)>,
    transcript: Transcript,
    broadcasts: Vec<BroadcastEvent>,
    network_log: BroadcastLog,
    subscribers: Vec<ParticipantId>,
}

impl<D: ValueDistribution, S: CommitmentScheme + Clone> ProtocolSession<D, S> {
    pub fn new(
        dra: PublicBroadcastDRA<D>,
        scheme: S,
        seed: u64,
        schedule: PhaseTimings,
        participants: Vec<ParticipantId>,
    ) -> Self {
        let mut subscribers = vec![ParticipantId::Auctioneer];
        for participant in participants {
            if !subscribers.contains(&participant) {
                subscribers.push(participant);
            }
        }
        Self {
            dra,
            rng: StdRng::seed_from_u64(seed),
            scheme,
            phase: Phase::Commit,
            schedule: schedule.clone(),
            current_time: 0,
            commitments: Vec::new(),
            transcript: Transcript {
                commitments: Vec::new(),
                reveals: Vec::new(),
                broadcasts: Vec::new(),
                timings: schedule,
                outcome: None,
            },
            broadcasts: Vec::new(),
            network_log: BroadcastLog::new(),
            subscribers,
        }
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn network_log(&self) -> &BroadcastLog {
        &self.network_log
    }

    pub fn advance_to(&mut self, now: u64) -> Result<(), ProtocolError> {
        if now < self.current_time {
            return Err(ProtocolError::ClockRewind {
                requested: now,
                current: self.current_time,
            });
        }
        self.current_time = now;
        if self.phase == Phase::Commit && now >= self.schedule.commit_deadline {
            self.transition_to_phase(Phase::Reveal, PhaseTransitionReason::Deadline)?;
        }
        if self.phase == Phase::Reveal && now >= self.schedule.reveal_deadline {
            self.transition_to_phase(Phase::Resolved, PhaseTransitionReason::Deadline)?;
        }
        Ok(())
    }

    pub fn commit_real(
        &mut self,
        buyer_idx: usize,
        bid: f64,
        collateral: f64,
    ) -> Result<(), ProtocolError> {
        self.commit_internal(ParticipantId::Real(buyer_idx), bid, collateral, true)
    }

    pub fn commit_false(
        &mut self,
        idx: usize,
        bid: f64,
        collateral: f64,
        reveal: bool,
    ) -> Result<(), ProtocolError> {
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
        if self.current_time >= self.schedule.commit_deadline {
            return Err(ProtocolError::DeadlineExceeded(Phase::Commit));
        }
        if self.commitments.iter().any(|(p, _, _, _, _)| p == &id) {
            return Err(ProtocolError::DuplicateCommit(id));
        }
        let (commitment, opening) = self.scheme.commit(bid, &mut self.rng);
        self.ensure_subscriber(&id);
        self.transcript.commitments.push(CommitmentEvent {
            participant: id.clone(),
            commitment: commitment.clone(),
            timestamp: self.current_time,
        });
        self.log_broadcast(
            id.clone(),
            BroadcastMessage::CommitmentPublished,
            Some(MessagePayload::Commitment { from: id.clone() }),
        );
        self.commitments
            .push((id, commitment, opening, collateral, will_reveal));
        Ok(())
    }

    fn log_broadcast(
        &mut self,
        sender: ParticipantId,
        message: BroadcastMessage,
        payload: Option<MessagePayload>,
    ) {
        self.broadcasts.push(BroadcastEvent {
            timestamp: self.current_time,
            sender: sender.clone(),
            message,
        });
        if let Some(payload) = payload {
            self.deliver_payload(sender, payload);
        }
    }

    fn ensure_subscriber(&mut self, participant: &ParticipantId) {
        if !self.subscribers.contains(participant) {
            self.subscribers.push(participant.clone());
        }
    }

    fn deliver_payload(&mut self, sender: ParticipantId, payload: MessagePayload) {
        for recipient in self.subscribers.clone() {
            self.network_log.record(DeliveredMessage {
                sender: sender.clone(),
                recipient,
                phase: self.phase,
                payload: payload.clone(),
            });
        }
    }

    fn transition_to_phase(
        &mut self,
        next: Phase,
        reason: PhaseTransitionReason,
    ) -> Result<(), ProtocolError> {
        match (self.phase, next) {
            (Phase::Commit, Phase::Reveal) | (Phase::Reveal, Phase::Resolved) => {
                self.phase = next;
                self.log_broadcast(
                    ParticipantId::Auctioneer,
                    BroadcastMessage::PhaseTransition {
                        phase: next,
                        reason,
                    },
                    Some(MessagePayload::EndPhase { phase: next }),
                );
                Ok(())
            }
            (Phase::Reveal, Phase::Reveal) | (Phase::Resolved, Phase::Resolved) => Ok(()),
            _ => Err(ProtocolError::WrongPhase),
        }
    }

    pub fn end_commit_phase(&mut self) -> Result<(), ProtocolError> {
        if self.phase != Phase::Commit {
            return Err(ProtocolError::WrongPhase);
        }
        self.transition_to_phase(Phase::Reveal, PhaseTransitionReason::Manual)
    }

    pub fn reveal(&mut self, id: ParticipantId) -> Result<(), ProtocolError> {
        if self.phase != Phase::Reveal {
            return Err(ProtocolError::WrongPhase);
        }
        if self.current_time >= self.schedule.reveal_deadline {
            return Err(ProtocolError::DeadlineExceeded(Phase::Reveal));
        }
        let idx = self
            .commitments
            .iter()
            .position(|(p, _, _, _, _)| p == &id)
            .ok_or_else(|| ProtocolError::MissingCommit(id.clone()))?;
        if self.transcript.reveals.iter().any(|r| r.participant == id) {
            return Err(ProtocolError::DuplicateReveal(id));
        }
        let (_pid, commitment, opening, _collateral, _will_reveal) = &self.commitments[idx];
        let reveals_ok = self.scheme.verify(commitment, opening);
        self.transcript.reveals.push(RevealEvent {
            participant: id,
            revealed: reveals_ok,
            opening: if reveals_ok {
                Some(opening.clone())
            } else {
                None
            },
            timestamp: self.current_time,
        });
        let sender = self.commitments[idx].0.clone();
        self.log_broadcast(
            sender.clone(),
            BroadcastMessage::RevealPublished {
                success: reveals_ok,
            },
            Some(MessagePayload::Reveal {
                from: sender,
                success: reveals_ok,
            }),
        );
        Ok(())
    }

    pub fn end_reveal_and_resolve(
        mut self,
    ) -> Result<(AuctionOutcome, Transcript, BroadcastLog), ProtocolError> {
        if self.phase != Phase::Reveal {
            return Err(ProtocolError::WrongPhase);
        }
        self.transition_to_phase(Phase::Resolved, PhaseTransitionReason::Manual)?;
        // Apply reveals: set will_reveal flags based on reveal events.
        let mut missing: Vec<ParticipantId> = Vec::new();
        for (pid, _, _, _, will_reveal) in self.commitments.iter_mut() {
            if let Some(rev) = self
                .transcript
                .reveals
                .iter()
                .find(|r| r.participant == *pid)
            {
                *will_reveal = rev.revealed;
            } else {
                *will_reveal = false;
                missing.push(pid.clone());
            }
        }
        for pid in missing {
            self.transcript.reveals.push(RevealEvent {
                participant: pid.clone(),
                revealed: false,
                opening: None,
                timestamp: self.current_time,
            });
            self.log_broadcast(
                ParticipantId::Auctioneer,
                BroadcastMessage::Timeout {
                    phase: Phase::Reveal,
                    target: pid.clone(),
                },
                Some(MessagePayload::Timeout { target: pid }),
            );
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
        transcript.broadcasts = self.broadcasts;
        transcript.timings = self.schedule;
        // Final audit.
        audit_transcript(&transcript, &mut self.scheme.clone())
            .map_err(|_| ProtocolError::AuditFailure)?;
        Ok((outcome, transcript, self.network_log.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::NonMalleableShaCommitment;
    use crate::distribution::Uniform;
    use crate::network::MessagePayload;

    #[test]
    fn broadcast_log_shows_all_commitments_to_each_buyer() {
        let dist = Uniform::new(0.0, 10.0);
        let dra = PublicBroadcastDRA::new(dist, 1.0);
        let schedule = PhaseTimings {
            commit_deadline: 4,
            reveal_deadline: 8,
        };
        let collateral = dra.collateral(2);
        let participants = vec![ParticipantId::Real(0), ParticipantId::Real(1)];
        let mut session =
            ProtocolSession::new(dra, NonMalleableShaCommitment, 17, schedule, participants);
        session
            .commit_real(0, 7.0, collateral)
            .expect("commit buyer 0");
        session
            .commit_real(1, 5.0, collateral)
            .expect("commit buyer 1");
        let log = session.network_log.clone();
        let view_b = log.per_recipient_view(&ParticipantId::Real(1));
        assert!(
            view_b.iter().any(|msg| matches!(
                msg.payload,
                MessagePayload::Commitment {
                    from: ParticipantId::Real(0)
                }
            )),
            "buyer 1 should see buyer 0 commitment"
        );
    }
}
