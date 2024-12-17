use rand::RngCore;
use sha2::{Digest, Sha256};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use blake3::Hasher;

pub const SALT_BYTES: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Commitment(pub [u8; 32]);

#[derive(Clone, Debug, PartialEq)]
pub struct Opening {
    pub bid: f64,
    pub salt: [u8; SALT_BYTES],
    pub mask: [u8; SALT_BYTES],
}

fn encode_bid(bid: f64) -> [u8; 8] {
    bid.to_le_bytes()
}

impl Commitment {
    pub fn verify_with<S: CommitmentScheme>(&self, opening: &Opening, scheme: &S) -> bool {
        scheme.verify(self, opening)
    }
}

/// Commitment backend abstraction to allow swapping a stronger non-malleable scheme.
pub trait CommitmentScheme {
    fn commit<R: RngCore>(&self, bid: f64, rng: &mut R) -> (Commitment, Opening);
    fn verify(&self, commitment: &Commitment, opening: &Opening) -> bool;
}

/// Default scheme: domain-separated SHA-256 with independent salt/mask.
#[derive(Clone, Debug, Default)]
pub struct NonMalleableShaCommitment;

impl CommitmentScheme for NonMalleableShaCommitment {
    fn commit<R: RngCore>(&self, bid: f64, rng: &mut R) -> (Commitment, Opening) {
        let salt = random_bytes(rng);
        let mask = random_bytes(rng);
        let commitment = commit_with_opening(bid, &salt, &mask);
        (
            commitment,
            Opening {
                bid,
                salt,
                mask,
            },
        )
    }

    fn verify(&self, commitment: &Commitment, opening: &Opening) -> bool {
        commitment == &commit_with_opening(opening.bid, &opening.salt, &opening.mask)
    }
}

/// Pedersen-style commitment over Ristretto. Provides computational binding and hiding.
#[derive(Clone, Debug, Default)]
pub struct PedersenRistrettoCommitment;

impl CommitmentScheme for PedersenRistrettoCommitment {
    fn commit<R: RngCore>(&self, bid: f64, rng: &mut R) -> (Commitment, Opening) {
        let salt = random_bytes(rng);
        let mask = random_bytes(rng);
        let point = pedersen_point(bid, &salt, &mask);
        (Commitment(point.compress().to_bytes()), Opening { bid, salt, mask })
    }

    fn verify(&self, commitment: &Commitment, opening: &Opening) -> bool {
        let point = pedersen_point(opening.bid, &opening.salt, &opening.mask);
        commitment.0 == point.compress().to_bytes()
    }
}

/// Audited-style wrapper that layers a keyed hash tag over the Pedersen commitment.
/// NOTE: This is a placeholder for an audited non-malleable scheme; it is not a security-audited construction.
#[derive(Clone, Debug, Default)]
pub struct AuditedNonMalleableCommitment;

impl CommitmentScheme for AuditedNonMalleableCommitment {
    fn commit<R: RngCore>(&self, bid: f64, rng: &mut R) -> (Commitment, Opening) {
        let salt = random_bytes(rng);
        let mask = random_bytes(rng);
        let point = pedersen_point(bid, &salt, &mask);
        let base = point.compress().to_bytes();
        let tag = nm_tag(&base, bid, &salt, &mask);
        (
            Commitment(tag),
            Opening { bid, salt, mask },
        )
    }

    fn verify(&self, commitment: &Commitment, opening: &Opening) -> bool {
        let point = pedersen_point(opening.bid, &opening.salt, &opening.mask);
        let base = point.compress().to_bytes();
        let tag = nm_tag(&base, opening.bid, &opening.salt, &opening.mask);
        commitment.0 == tag
    }
}

/// Placeholder for an "external" non-malleable scheme. In practice, swap this with a vetted library.
#[derive(Clone, Debug, Default)]
pub struct ExternalNonMalleableCommitment;

impl CommitmentScheme for ExternalNonMalleableCommitment {
    fn commit<R: RngCore>(&self, bid: f64, rng: &mut R) -> (Commitment, Opening) {
        let salt = random_bytes(rng);
        let mask = random_bytes(rng);
        // Use audited NM tag as a stand-in.
        let point = pedersen_point(bid, &salt, &mask);
        let base = point.compress().to_bytes();
        let tag = nm_tag(&base, bid, &salt, &mask);
        (
            Commitment(tag),
            Opening { bid, salt, mask },
        )
    }

    fn verify(&self, commitment: &Commitment, opening: &Opening) -> bool {
        let point = pedersen_point(opening.bid, &opening.salt, &opening.mask);
        let base = point.compress().to_bytes();
        let tag = nm_tag(&base, opening.bid, &opening.salt, &opening.mask);
        commitment.0 == tag
    }
}

/// Commit to a bid using domain-separated hashing with independent salts and masks.
pub fn commit_with_opening(bid: f64, salt: &[u8; SALT_BYTES], mask: &[u8; SALT_BYTES]) -> Commitment {
    let mut hasher = Sha256::new();
    hasher.update(b"DRA-BID");
    hasher.update(&encode_bid(bid));
    hasher.update(salt);
    hasher.update(mask);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Commitment(out)
}

fn random_bytes<R: RngCore>(rng: &mut R) -> [u8; SALT_BYTES] {
    let mut salt = [0u8; SALT_BYTES];
    rng.fill_bytes(&mut salt);
    salt
}

fn hash_to_scalar(data: &[u8]) -> Scalar {
    let mut hasher = Hasher::new();
    hasher.update(data);
    let output = hasher.finalize();
    Scalar::from_bytes_mod_order(*output.as_bytes())
}

fn derive_h_point() -> curve25519_dalek::ristretto::RistrettoPoint {
    let h_scalar = hash_to_scalar(b"DRA-H-POINT");
    h_scalar * RISTRETTO_BASEPOINT_POINT
}

fn pedersen_point(bid: f64, salt: &[u8; SALT_BYTES], mask: &[u8; SALT_BYTES]) -> curve25519_dalek::ristretto::RistrettoPoint {
    let r = hash_to_scalar(salt);
    let mut buf = Vec::with_capacity(8 + SALT_BYTES * 2);
    buf.extend_from_slice(&encode_bid(bid));
    buf.extend_from_slice(salt);
    buf.extend_from_slice(mask);
    let m = hash_to_scalar(&buf);
    let h_point = derive_h_point();
    r * RISTRETTO_BASEPOINT_POINT + m * h_point
}

fn nm_tag(base: &[u8; 32], bid: f64, salt: &[u8; SALT_BYTES], mask: &[u8; SALT_BYTES]) -> [u8; 32] {
    const KEY: [u8; 32] = *b"AUDITED-NM-COMMITMENT-KEY-32BYTE";
    let mut hasher = Hasher::new_keyed(&KEY);
    hasher.update(base);
    hasher.update(&encode_bid(bid));
    hasher.update(salt);
    hasher.update(mask);
    let tag = hasher.finalize();
    *tag.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_accepts_correct_opening() {
        let mut rng = rand::thread_rng();
        let scheme = NonMalleableShaCommitment;
        let (c, open) = scheme.commit(10.0, &mut rng);
        assert!(c.verify_with(&open, &scheme));
    }

    #[test]
    fn verify_rejects_wrong_opening() {
        let mut rng = rand::thread_rng();
        let scheme = NonMalleableShaCommitment;
        let (c, mut open) = scheme.commit(10.0, &mut rng);
        open.bid = 9.0;
        assert!(!c.verify_with(&open, &scheme));
    }

    #[test]
    fn distinct_salts_hide_bid_structure() {
        let mut rng = rand::thread_rng();
        let scheme = NonMalleableShaCommitment;
        let (c1, _) = scheme.commit(5.0, &mut rng);
        let (c2, _) = scheme.commit(5.0, &mut rng);
        assert_ne!(c1, c2);
    }

    #[test]
    fn pedersen_backend_verifies() {
        let mut rng = rand::thread_rng();
        let scheme = PedersenRistrettoCommitment;
        let (c, open) = scheme.commit(13.0, &mut rng);
        assert!(scheme.verify(&c, &open));
    }

    #[test]
    fn pedersen_rejects_tampered_opening() {
        let mut rng = rand::thread_rng();
        let scheme = PedersenRistrettoCommitment;
        let (c, mut open) = scheme.commit(9.0, &mut rng);
        open.salt[0] ^= 0xFF;
        assert!(!scheme.verify(&c, &open));
    }

    #[test]
    fn audited_backend_verifies_and_rejects() {
        let mut rng = rand::thread_rng();
        let scheme = AuditedNonMalleableCommitment;
        let (c, open) = scheme.commit(11.0, &mut rng);
        assert!(scheme.verify(&c, &open));

        let mut bad = open.clone();
        bad.mask[0] ^= 0x01;
        assert!(!scheme.verify(&c, &bad));
    }

    #[test]
    fn external_placeholder_matches_audited_logic() {
        let mut rng = rand::thread_rng();
        let scheme = ExternalNonMalleableCommitment;
        let (c, open) = scheme.commit(7.0, &mut rng);
        assert!(scheme.verify(&c, &open));
    }
}
