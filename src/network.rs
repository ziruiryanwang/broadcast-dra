use std::collections::HashSet;

use crate::auction::ParticipantId;
use crate::protocol::Phase;

#[derive(Clone, Debug)]
pub struct DeliveredMessage {
    pub sender: ParticipantId,
    pub recipient: ParticipantId,
    pub phase: Phase,
    pub payload: MessagePayload,
}

#[derive(Clone, Debug)]
pub enum MessagePayload {
    Commitment { from: ParticipantId },
    Reveal { from: ParticipantId, success: bool },
    EndPhase { phase: Phase },
    Timeout { target: ParticipantId },
}

#[derive(Clone, Debug)]
pub struct BroadcastLog {
    deliveries: Vec<DeliveredMessage>,
}

impl BroadcastLog {
    pub fn new() -> Self {
        Self {
            deliveries: Vec::new(),
        }
    }

    pub fn record(&mut self, message: DeliveredMessage) {
        self.deliveries.push(message);
    }

    pub fn per_recipient_view(&self, recipient: &ParticipantId) -> Vec<&DeliveredMessage> {
        self.deliveries
            .iter()
            .filter(|msg| &msg.recipient == recipient)
            .collect()
    }

    pub fn all(&self) -> &[DeliveredMessage] {
        &self.deliveries
    }
}

#[derive(Clone, Debug)]
pub struct OmittedDelivery {
    pub sender: ParticipantId,
    pub omitted: ParticipantId,
    pub phase: Phase,
    pub payload: MessagePayload,
}

#[derive(Clone, Debug)]
pub struct CentralizedChannel {
    subscribers: Vec<ParticipantId>,
    deliveries: Vec<DeliveredMessage>,
    omissions: Vec<OmittedDelivery>,
}

impl CentralizedChannel {
    pub fn new(mut participants: Vec<ParticipantId>) -> Self {
        if !participants.iter().any(|p| *p == ParticipantId::Auctioneer) {
            participants.push(ParticipantId::Auctioneer);
        }
        Self {
            subscribers: participants,
            deliveries: Vec::new(),
            omissions: Vec::new(),
        }
    }

    pub fn register(&mut self, participant: ParticipantId) {
        if !self.subscribers.contains(&participant) {
            self.subscribers.push(participant);
        }
    }

    pub fn private_message(
        &mut self,
        sender: ParticipantId,
        recipient: ParticipantId,
        phase: Phase,
        payload: MessagePayload,
    ) {
        self.deliveries.push(DeliveredMessage {
            sender,
            recipient,
            phase,
            payload,
        });
    }

    pub fn broadcast_subset(
        &mut self,
        sender: ParticipantId,
        phase: Phase,
        payload: MessagePayload,
        allowed: &[ParticipantId],
    ) {
        let allow_set: HashSet<_> = allowed.iter().cloned().collect();
        for recipient in self.subscribers.clone() {
            if recipient == sender {
                continue;
            }
            if allow_set.contains(&recipient) {
                self.deliveries.push(DeliveredMessage {
                    sender: sender.clone(),
                    recipient: recipient.clone(),
                    phase,
                    payload: payload.clone(),
                });
            } else {
                self.omissions.push(OmittedDelivery {
                    sender: sender.clone(),
                    omitted: recipient.clone(),
                    phase,
                    payload: payload.clone(),
                });
            }
        }
    }

    pub fn deliveries(&self) -> &[DeliveredMessage] {
        &self.deliveries
    }

    pub fn omissions(&self) -> &[OmittedDelivery] {
        &self.omissions
    }

    pub fn per_recipient_view(&self, recipient: &ParticipantId) -> Vec<&DeliveredMessage> {
        self.deliveries
            .iter()
            .filter(|msg| &msg.recipient == recipient)
            .collect()
    }

    pub fn omitted_for(&self, recipient: &ParticipantId) -> Vec<&OmittedDelivery> {
        self.omissions
            .iter()
            .filter(|entry| &entry.omitted == recipient)
            .collect()
    }
}
