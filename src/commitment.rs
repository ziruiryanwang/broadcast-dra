use rand::RngCore;
use sha2::{Digest, Sha256};

pub const SALT_BYTES: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Commitment(pub [u8; 32]);

#[derive(Clone, Debug, PartialEq)]
pub struct Opening {
    pub bid: f64,
    pub salt: [u8; SALT_BYTES],
    pub mask: [u8; SALT_BYTES],
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

/// Commit to a bid using domain-separated hashing with independent salts and masks.
pub fn commit_with_opening(bid: f64, salt: &[u8; SALT_BYTES], mask: &[u8; SALT_BYTES]) -> Commitment {
    let mut hasher = Sha256::new();
    hasher.update(b"DRA-BID");
    hasher.update(&bid.to_le_bytes());
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
}
