use anyhow::{bail, Context, Result};
use aws_lc_rs::signature;
use aws_lc_rs::signature::KeyPair as _;

use crate::util::decode_key_material;

/// Optional Ed25519 detached signature verification for remote catalogs.
pub struct CatalogSignature {
    public_key: Vec<u8>,
}

impl CatalogSignature {
    pub fn new(encoded_public_key: &str) -> Result<Self> {
        let public_key = decode_key_material(encoded_public_key)
            .context("decoding catalog signature public key")?;
        if public_key.len() != 32 {
            bail!(
                "Ed25519 public key must be 32 bytes (got {})",
                public_key.len()
            );
        }
        Ok(Self { public_key })
    }

    pub fn verify(&self, message: &[u8], encoded_signature: &[u8]) -> Result<()> {
        let signature = decode_signature(encoded_signature)?;
        signature::UnparsedPublicKey::new(&signature::ED25519, &self.public_key)
            .verify(message, &signature)
            .map_err(|_| anyhow::anyhow!("catalog Ed25519 signature verification failed"))
    }
}

fn decode_signature(raw: &[u8]) -> Result<Vec<u8>> {
    // Signatures are usually raw 64-byte files, but accepting base64/hex text is convenient.
    if raw.len() == 64 {
        return Ok(raw.to_vec());
    }
    if let Ok(text) = std::str::from_utf8(raw) {
        let decoded = decode_key_material(text).context("decoding catalog signature")?;
        if decoded.len() == 64 {
            return Ok(decoded);
        }
    }
    bail!(
        "catalog signature must be 64 raw bytes or base64/hex (got {} bytes)",
        raw.len()
    )
}

/// Generate a detached signature for tests and the catalog publishing helper.
pub fn sign_with_seed(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let key_pair = signature::Ed25519KeyPair::from_seed_unchecked(seed).expect("valid seed");
    let mut out = [0u8; 64];
    out.copy_from_slice(key_pair.sign(message).as_ref());
    out
}

pub fn public_key_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    let key_pair = signature::Ed25519KeyPair::from_seed_unchecked(seed).expect("valid seed");
    let mut out = [0u8; 32];
    out.copy_from_slice(key_pair.public_key().as_ref());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn verifies_signature() {
        let seed = [42u8; 32];
        let message = br#"{"v":1}"#;
        let public = public_key_from_seed(&seed);
        let signature = sign_with_seed(&seed, message);
        let verifier =
            CatalogSignature::new(&base64::engine::general_purpose::STANDARD.encode(public))
                .unwrap();
        verifier.verify(message, &signature).unwrap();
        verifier.verify(b"tampered", &signature).unwrap_err();
    }
}
