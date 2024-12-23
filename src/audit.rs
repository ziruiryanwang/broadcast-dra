use sha2::{Digest, Sha256};
use std::fs;

pub fn emit_provenance() -> Result<(), Box<dyn std::error::Error>> {
    const BULLETPROOFS_SHA: &str = "012e2e5f88332083bd4235d445ae78081c00b2558443821a9ca5adfe1070073d";
    const BULLETPROOFS_VERSION: &str = "5.0.0";
    let tex_path = "reference_material/Credible_Optimal_Auctions_public_broadcast_full.tex";
    let tex_bytes = fs::read(tex_path)?;
    let mut hasher = Sha256::new();
    hasher.update(&tex_bytes);
    let tex_hash = format!("{:x}", hasher.finalize());
    let payload = serde_json::json!({
        "bulletproofs_crate": {
            "version": BULLETPROOFS_VERSION,
            "sha256": BULLETPROOFS_SHA,
        },
        "paper_tex": {
            "path": tex_path,
            "sha256": tex_hash,
        }
    });
    println!("{}", serde_json::to_string_pretty(&payload)?);
    Ok(())
}
