//! Subresource-Integrity verification of downloaded tarballs.
//!
//! npm pins each tarball's `sha512-<base64>` digest — in a `package-lock.json` and in the
//! registry's `dist.integrity`. [`verify`] checks the downloaded bytes against it before they
//! are trusted, exactly as `npm install` / `npm ci` do. An integrity string with no sha512
//! component is an error: we never install unverified.

use base64::Engine;
use sha2::{Digest, Sha512};

/// Verify `bytes` against a Subresource-Integrity string (`sha512-<base64>`, possibly several
/// space-separated algorithms — we require and check the sha512 one). `name` is for messages.
pub fn verify(name: &str, bytes: &[u8], integrity: &str) -> Result<(), Box<dyn std::error::Error>> {
    let expected = integrity
        .split_whitespace()
        .find_map(|token| token.strip_prefix("sha512-"))
        .ok_or_else(|| format!("package `{name}`: no sha512 integrity to verify against"))?;
    let actual = base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes));
    if actual != expected {
        return Err(format!(
            "package `{name}`: integrity mismatch — the downloaded tarball does not match \
             the expected sha512"
        )
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_checks_sha512_and_rejects_tampering() {
        let bytes = b"a downloaded tarball's bytes";
        let good = format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
        );
        verify("p", bytes, &good).expect("matching sha512 passes");

        let mut tampered = bytes.to_vec();
        tampered[0] ^= 0xff;
        assert!(verify("p", &tampered, &good).is_err(), "flipped byte fails");

        // An integrity string with no sha512 component is rejected (npm-ci-strict).
        assert!(verify("p", bytes, "sha1-deadbeef").is_err());
    }
}
