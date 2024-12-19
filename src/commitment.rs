use std::{fmt, sync::{Arc, Mutex}};

use blake3::Hasher;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use merlin::Transcript;
use rand::{RngCore, SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha256};

pub const SALT_BYTES: usize = 32;
pub const BID_BYTES: usize = 16;
pub const BID_SCALE: f64 = 1_000_000.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BidEncoding([u8; BID_BYTES]);

impl BidEncoding {
    pub fn new(bid: f64) -> Self {
        assert!(bid.is_finite(), "bid must be finite");
        assert!(bid >= 0.0, "bid must be non-negative");
        let scaled = (bid * BID_SCALE).round();
        let scaled_i = scaled as i128;
        BidEncoding(scaled_i.to_le_bytes())
    }

    pub fn as_bytes(&self) -> &[u8; BID_BYTES] {
        &self.0
    }

    pub fn as_i128(&self) -> i128 {
        i128::from_le_bytes(self.0)
    }

    pub fn as_u64(&self) -> u64 {
        let value = self.as_i128();
        assert!(
            value >= 0,
            "bid encoding must be non-negative to map into u64"
        );
        assert!(
            value <= u64::MAX as i128,
            "bid encoding exceeds u64 range for bulletproof backend"
        );
        value as u64
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Commitment(pub [u8; 32]);

#[derive(Clone, Debug, PartialEq)]
pub struct Opening {
    pub bid: f64,
    pub encoding: BidEncoding,
    pub salt: [u8; SALT_BYTES],
    pub mask: [u8; SALT_BYTES],
    pub proof: Option<FischlinProof>,
    pub audit_receipt: Option<AuditReceipt>,
    pub bulletproof: Option<BulletproofProofData>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FischlinProof {
    pub challenge: [u8; 32],
    pub response_blind: [u8; 32],
    pub response_message: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditReceipt {
    pub index: usize,
    pub root: [u8; 32],
    pub entry_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BulletproofProofData {
    pub proof: Vec<u8>,
    pub blinding: [u8; 32],
    pub range_bits: usize,
}

impl FischlinProof {
    fn challenge_scalar(&self) -> Scalar {
        Scalar::from_bytes_mod_order(self.challenge)
    }

    fn response_blind_scalar(&self) -> Scalar {
        Scalar::from_bytes_mod_order(self.response_blind)
    }

    fn response_message_scalar(&self) -> Scalar {
        Scalar::from_bytes_mod_order(self.response_message)
    }
}

impl BulletproofProofData {
    fn blinding_scalar(&self) -> Scalar {
        Scalar::from_bytes_mod_order(self.blinding)
    }

    fn range_proof(&self) -> Option<RangeProof> {
        RangeProof::from_bytes(&self.proof).ok()
    }
}

pub trait CommitmentScheme {
    fn commit<R: RngCore>(&self, bid: f64, rng: &mut R) -> (Commitment, Opening);
    fn verify(&self, commitment: &Commitment, opening: &Opening) -> bool;
}

#[derive(Clone, Debug, Default)]
pub struct NonMalleableShaCommitment;

impl CommitmentScheme for NonMalleableShaCommitment {
    fn commit<R: RngCore>(&self, bid: f64, rng: &mut R) -> (Commitment, Opening) {
        let salt = random_bytes(rng);
        let mask = random_bytes(rng);
        let encoding = BidEncoding::new(bid);
        let commitment = hash_commitment(&encoding, &salt, &mask);
        (
            commitment,
            Opening {
                bid,
                encoding,
                salt,
                mask,
                proof: None,
                audit_receipt: None,
                bulletproof: None,
            },
        )
    }

    fn verify(&self, commitment: &Commitment, opening: &Opening) -> bool {
        let encoding = BidEncoding::new(opening.bid);
        encoding == opening.encoding
            && *commitment == hash_commitment(&encoding, &opening.salt, &opening.mask)
    }
}

#[derive(Clone, Debug, Default)]
pub struct PedersenRistrettoCommitment;

impl CommitmentScheme for PedersenRistrettoCommitment {
    fn commit<R: RngCore>(&self, bid: f64, rng: &mut R) -> (Commitment, Opening) {
        let salt = random_bytes(rng);
        let mask = random_bytes(rng);
        let encoding = BidEncoding::new(bid);
        let point = pedersen_point(&encoding, &salt, &mask);
        (
            Commitment(point.compress().to_bytes()),
            Opening {
                bid,
                encoding,
                salt,
                mask,
                proof: None,
                audit_receipt: None,
                bulletproof: None,
            },
        )
    }

    fn verify(&self, commitment: &Commitment, opening: &Opening) -> bool {
        if BidEncoding::new(opening.bid) != opening.encoding {
            return false;
        }
        let Some(point) = decompress_point(commitment) else {
            return false;
        };
        let expected = pedersen_point(&opening.encoding, &opening.salt, &opening.mask);
        point == expected
    }
}

#[derive(Clone, Debug, Default)]
pub struct RealNonMalleableCommitment;

impl CommitmentScheme for RealNonMalleableCommitment {
    fn commit<R: RngCore>(&self, bid: f64, rng: &mut R) -> (Commitment, Opening) {
        let encoding = BidEncoding::new(bid);
        let salt = random_bytes(rng);
        let mask = random_bytes(rng);
        let blind = hash_to_scalar(&salt);
        let message_scalar = scalar_from_encoding(&encoding);
        let point = blind * RISTRETTO_BASEPOINT_POINT + message_scalar * derive_h_point();
        let proof = build_fischlin_proof(&point, blind, message_scalar, &mask, &encoding);
        (
            Commitment(point.compress().to_bytes()),
            Opening {
                bid,
                encoding,
                salt,
                mask,
                proof: Some(proof),
                audit_receipt: None,
                bulletproof: None,
            },
        )
    }

    fn verify(&self, commitment: &Commitment, opening: &Opening) -> bool {
        if BidEncoding::new(opening.bid) != opening.encoding {
            return false;
        }
        let Some(proof) = opening.proof.as_ref() else {
            return false;
        };
        let Some(point) = decompress_point(commitment) else {
            return false;
        };
        verify_fischlin_proof(
            &point,
            proof,
            &opening.encoding,
            hash_to_scalar(&opening.salt),
            scalar_from_encoding(&opening.encoding),
        )
    }
}

#[derive(Clone)]
pub struct BulletproofsCommitment {
    pedersen: PedersenGens,
    generators: BulletproofGens,
    range_bits: usize,
}

impl BulletproofsCommitment {
    pub fn new(range_bits: usize) -> Self {
        assert!(
            range_bits.is_power_of_two(),
            "range bits must be a power of two"
        );
        assert!(range_bits >= 8, "range bits must be at least 8");
        Self {
            pedersen: PedersenGens::default(),
            generators: BulletproofGens::new(range_bits, 1),
            range_bits,
        }
    }
}

impl Default for BulletproofsCommitment {
    fn default() -> Self {
        Self::new(64)
    }
}

impl fmt::Debug for BulletproofsCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BulletproofsCommitment")
            .field("range_bits", &self.range_bits)
            .finish()
    }
}

impl CommitmentScheme for BulletproofsCommitment {
    fn commit<R: RngCore>(&self, bid: f64, rng: &mut R) -> (Commitment, Opening) {
        let encoding = BidEncoding::new(bid);
        let mut transcript = Transcript::new(b"DRA-BULLETPROOF");
        let mut proof_rng = StdRng::from_seed(random_bytes(rng));
        let blinding = scalar_from_rng(&mut proof_rng);
        let (proof, commitment_point) = RangeProof::prove_single_with_rng(
            &self.generators,
            &self.pedersen,
            &mut transcript,
            encoding.as_u64(),
            &blinding,
            self.range_bits,
            &mut proof_rng,
        )
        .expect("bulletproof proving should succeed for valid bids");
        (
            Commitment(commitment_point.to_bytes()),
            Opening {
                bid,
                encoding,
                salt: [0u8; SALT_BYTES],
                mask: [0u8; SALT_BYTES],
                proof: None,
                audit_receipt: None,
                bulletproof: Some(BulletproofProofData {
                    proof: proof.to_bytes(),
                    blinding: blinding.to_bytes(),
                    range_bits: self.range_bits,
                }),
            },
        )
    }

    fn verify(&self, commitment: &Commitment, opening: &Opening) -> bool {
        if BidEncoding::new(opening.bid) != opening.encoding {
            return false;
        }
        let Some(bp) = opening.bulletproof.as_ref() else {
            return false;
        };
        let Some(point) = decompress_point(commitment) else {
            return false;
        };
        let mut transcript = Transcript::new(b"DRA-BULLETPROOF");
        let proof = match bp.range_proof() {
            Some(p) => p,
            None => return false,
        };
        if proof
            .verify_single(
                &self.generators,
                &self.pedersen,
                &mut transcript,
                &CompressedRistretto(commitment.0),
                bp.range_bits,
            )
            .is_err()
        {
            return false;
        }
        let expected = self
            .pedersen
            .commit(
                Scalar::from(opening.encoding.as_u64()),
                bp.blinding_scalar(),
            );
        expected == point
    }
}

#[derive(Clone, Debug)]
pub struct AuditLedger {
    entries: Arc<Mutex<Vec<[u8; 32]>>>,
}

impl AuditLedger {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn log_entry(&self, entry_hash: [u8; 32]) -> AuditReceipt {
        let mut guard = self.entries.lock().expect("ledger poisoned");
        guard.push(entry_hash);
        let root = aggregate_root(&guard[..]);
        AuditReceipt {
            index: guard.len() - 1,
            root,
            entry_hash,
        }
    }

    pub fn verify(&self, receipt: &AuditReceipt) -> bool {
        let guard = self.entries.lock().expect("ledger poisoned");
        if receipt.index >= guard.len() {
            return false;
        }
        guard[receipt.index] == receipt.entry_hash
            && aggregate_root(&guard[..=receipt.index]) == receipt.root
    }
}

fn aggregate_root(entries: &[[u8; 32]]) -> [u8; 32] {
    let mut acc = [0u8; 32];
    for entry in entries {
        let mut hasher = Hasher::new();
        hasher.update(b"DRA-AUDIT-ROOT");
        hasher.update(&acc);
        hasher.update(entry);
        acc.copy_from_slice(hasher.finalize().as_bytes());
    }
    acc
}

#[derive(Clone, Debug)]
pub struct AuditedNonMalleableCommitment {
    inner: BulletproofsCommitment,
    ledger: AuditLedger,
}

impl Default for AuditedNonMalleableCommitment {
    fn default() -> Self {
        Self {
            inner: BulletproofsCommitment::default(),
            ledger: AuditLedger::new(),
        }
    }
}

impl AuditedNonMalleableCommitment {
    pub fn with_ledger(ledger: AuditLedger) -> Self {
        Self {
            inner: BulletproofsCommitment::default(),
            ledger,
        }
    }
}

impl CommitmentScheme for AuditedNonMalleableCommitment {
    fn commit<R: RngCore>(&self, bid: f64, rng: &mut R) -> (Commitment, Opening) {
        let (commitment, mut opening) = self.inner.commit(bid, rng);
        let entry_hash = audit_entry_hash(&commitment, &opening);
        let receipt = self.ledger.log_entry(entry_hash);
        opening.audit_receipt = Some(receipt);
        (commitment, opening)
    }

    fn verify(&self, commitment: &Commitment, opening: &Opening) -> bool {
        let Some(receipt) = opening.audit_receipt.as_ref() else {
            return false;
        };
        self.inner.verify(commitment, opening)
            && entry_hash_matches(receipt, commitment, opening)
            && self.ledger.verify(receipt)
    }
}

fn entry_hash_matches(receipt: &AuditReceipt, commitment: &Commitment, opening: &Opening) -> bool {
    receipt.entry_hash == audit_entry_hash(commitment, opening)
}

fn build_fischlin_proof(
    commitment: &RistrettoPoint,
    blind: Scalar,
    message_scalar: Scalar,
    mask: &[u8; SALT_BYTES],
    encoding: &BidEncoding,
) -> FischlinProof {
    let mut seed = *mask;
    let mut rng = StdRng::from_seed(seed);
    let k_blind = scalar_from_rng(&mut rng);
    rng.fill_bytes(&mut seed);
    let mut seeded = StdRng::from_seed(seed);
    let k_msg = scalar_from_rng(&mut seeded);
    let witness_point = k_blind * RISTRETTO_BASEPOINT_POINT + k_msg * derive_h_point();
    let challenge = derive_challenge(commitment, &witness_point, encoding);
    let response_blind = k_blind + challenge * blind;
    let response_msg = k_msg + challenge * message_scalar;

    FischlinProof {
        challenge: challenge.to_bytes(),
        response_blind: response_blind.to_bytes(),
        response_message: response_msg.to_bytes(),
    }
}

fn verify_fischlin_proof(
    commitment: &RistrettoPoint,
    proof: &FischlinProof,
    encoding: &BidEncoding,
    blind_scalar: Scalar,
    message_scalar: Scalar,
) -> bool {
    let challenge = proof.challenge_scalar();
    let resp_blind = proof.response_blind_scalar();
    let resp_msg = proof.response_message_scalar();
    let lhs = resp_blind * RISTRETTO_BASEPOINT_POINT + resp_msg * derive_h_point();
    let rhs = challenge * commitment;
    let witness_point = lhs - rhs;
    let recomputed = derive_challenge(commitment, &witness_point, encoding);
    if recomputed != challenge {
        return false;
    }
    let reconstructed =
        blind_scalar * RISTRETTO_BASEPOINT_POINT + message_scalar * derive_h_point();
    reconstructed == *commitment
}

fn derive_challenge(
    commitment: &RistrettoPoint,
    witness: &RistrettoPoint,
    encoding: &BidEncoding,
) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(b"DRA-FISCHLIN-CHALLENGE");
    hasher.update(commitment.compress().as_bytes());
    hasher.update(witness.compress().as_bytes());
    hasher.update(encoding.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    Scalar::from_bytes_mod_order(bytes)
}

fn hash_commitment(
    encoding: &BidEncoding,
    salt: &[u8; SALT_BYTES],
    mask: &[u8; SALT_BYTES],
) -> Commitment {
    let mut hasher = Sha256::new();
    hasher.update(b"DRA-BID");
    hasher.update(encoding.as_bytes());
    hasher.update(salt);
    hasher.update(mask);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Commitment(out)
}

fn random_bytes<R: RngCore>(rng: &mut R) -> [u8; SALT_BYTES] {
    let mut bytes = [0u8; SALT_BYTES];
    rng.fill_bytes(&mut bytes);
    bytes
}

fn scalar_from_rng<R: RngCore>(rng: &mut R) -> Scalar {
    let mut wide = [0u8; 64];
    rng.fill_bytes(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn hash_to_scalar(data: &[u8]) -> Scalar {
    let mut hasher = Hasher::new();
    hasher.update(data);
    let output = hasher.finalize();
    Scalar::from_bytes_mod_order(*output.as_bytes())
}

fn derive_h_point() -> RistrettoPoint {
    let h_scalar = hash_to_scalar(b"DRA-H-POINT");
    h_scalar * RISTRETTO_BASEPOINT_POINT
}

fn pedersen_point(
    encoding: &BidEncoding,
    salt: &[u8; SALT_BYTES],
    mask: &[u8; SALT_BYTES],
) -> RistrettoPoint {
    let blind = hash_to_scalar(salt);
    let msg = scalar_from_encoding(encoding) + hash_to_scalar(mask);
    blind * RISTRETTO_BASEPOINT_POINT + msg * derive_h_point()
}

fn scalar_from_encoding(encoding: &BidEncoding) -> Scalar {
    let mut wide = [0u8; 32];
    wide[..BID_BYTES].copy_from_slice(encoding.as_bytes());
    Scalar::from_bytes_mod_order(wide)
}

fn decompress_point(commitment: &Commitment) -> Option<RistrettoPoint> {
    CompressedRistretto(commitment.0).decompress()
}

fn audit_entry_hash(commitment: &Commitment, opening: &Opening) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"DRA-AUDIT-ENTRY");
    hasher.update(&commitment.0);
    hasher.update(opening.encoding.as_bytes());
    hasher.update(&opening.salt);
    hasher.update(&opening.mask);
    if let Some(proof) = opening.proof.as_ref() {
        hasher.update(&proof.challenge);
        hasher.update(&proof.response_blind);
        hasher.update(&proof.response_message);
    }
    if let Some(bp) = opening.bulletproof.as_ref() {
        hasher.update(&bp.blinding);
        hasher.update(&(bp.range_bits as u64).to_le_bytes());
        hasher.update(&bp.proof);
    }
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha_commit_round_trip() {
        let mut rng = rand::thread_rng();
        let scheme = NonMalleableShaCommitment;
        let (commitment, opening) = scheme.commit(10.0, &mut rng);
        assert!(scheme.verify(&commitment, &opening));
    }

    #[test]
    fn sha_commit_rejects_wrong_bid() {
        let mut rng = rand::thread_rng();
        let scheme = NonMalleableShaCommitment;
        let (commitment, mut opening) = scheme.commit(10.0, &mut rng);
        opening.bid = 11.0;
        assert!(!scheme.verify(&commitment, &opening));
    }

    #[test]
    fn pedersen_commit_round_trip() {
        let mut rng = rand::thread_rng();
        let scheme = PedersenRistrettoCommitment;
        let (commitment, opening) = scheme.commit(7.0, &mut rng);
        assert!(scheme.verify(&commitment, &opening));
    }

    #[test]
    fn pedersen_commit_rejects_modified_mask() {
        let mut rng = rand::thread_rng();
        let scheme = PedersenRistrettoCommitment;
        let (commitment, mut opening) = scheme.commit(7.0, &mut rng);
        opening.mask[0] ^= 0xFF;
        assert!(!scheme.verify(&commitment, &opening));
    }

    #[test]
    fn real_commitment_round_trip() {
        let mut rng = rand::thread_rng();
        let scheme = RealNonMalleableCommitment;
        let (commitment, opening) = scheme.commit(15.5, &mut rng);
        assert!(scheme.verify(&commitment, &opening));
    }

    #[test]
    fn real_commitment_rejects_tampering() {
        let mut rng = rand::thread_rng();
        let scheme = RealNonMalleableCommitment;
        let (commitment, mut opening) = scheme.commit(4.5, &mut rng);
        opening.proof.as_mut().unwrap().response_blind[0] ^= 0x01;
        assert!(!scheme.verify(&commitment, &opening));
    }

    #[test]
    fn audited_commitment_round_trip_and_receipt() {
        let mut rng = rand::thread_rng();
        let scheme = AuditedNonMalleableCommitment::default();
        let (commitment, opening) = scheme.commit(9.0, &mut rng);
        assert!(scheme.verify(&commitment, &opening));
        assert!(opening.audit_receipt.is_some());
    }

    #[test]
    fn audited_commitment_rejects_modified_receipt() {
        let mut rng = rand::thread_rng();
        let scheme = AuditedNonMalleableCommitment::default();
        let (commitment, mut opening) = scheme.commit(4.0, &mut rng);
        opening.audit_receipt.as_mut().unwrap().entry_hash[0] ^= 0xFF;
        assert!(!scheme.verify(&commitment, &opening));
    }

    #[test]
    fn bulletproof_commit_round_trip() {
        let mut rng = rand::thread_rng();
        let scheme = BulletproofsCommitment::default();
        let (commitment, opening) = scheme.commit(13.0, &mut rng);
        assert!(scheme.verify(&commitment, &opening));
    }

    #[test]
    fn bulletproof_commit_rejects_tampering() {
        let mut rng = rand::thread_rng();
        let scheme = BulletproofsCommitment::default();
        let (commitment, mut opening) = scheme.commit(7.0, &mut rng);
        opening
            .bulletproof
            .as_mut()
            .expect("proof present")
            .proof[0] ^= 0xAA;
        assert!(!scheme.verify(&commitment, &opening));
    }
}
