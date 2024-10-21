use rand::RngCore;
use sha2::{Digest, Sha256};

pub const SALT_BYTES: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Commitment(pub [u8; 32]);

/// Deterministically produce a commitment for a bid and salt.
pub fn commit_bid(bid: f64, salt: &[u8; SALT_BYTES]) -> Commitment {
    let mut hasher = Sha256::new();
    hasher.update(&bid.to_le_bytes());
    hasher.update(salt);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Commitment(out)
}

impl Commitment {
    pub fn verify(&self, bid: f64, salt: &[u8; SALT_BYTES]) -> bool {
        &self.0 == &commit_bid(bid, salt).0
    }
}

/// Draw a uniformly random salt of length `SALT_BYTES`.
pub fn random_salt<R: RngCore>(rng: &mut R) -> [u8; SALT_BYTES] {
    let mut salt = [0u8; SALT_BYTES];
    rng.fill_bytes(&mut salt);
    salt
}
