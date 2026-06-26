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
    let expected_b64 = integrity
        .split_whitespace()
        .find_map(|token| token.strip_prefix("sha512-"))
        .ok_or_else(|| format!("package `{name}`: no sha512 integrity to verify against"))?;
    // Compare the raw 64 digest bytes, not the base64 text.
    // Decoding the expected SRI makes the check independent of base64 padding or any
    // non-canonical encoding in the integrity string.
    let expected = base64::engine::general_purpose::STANDARD
        .decode(expected_b64)
        .map_err(|e| format!("package `{name}`: malformed sha512 integrity: {e}"))?;
    if expected.as_slice() != Sha512::digest(bytes).as_slice() {
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

    #[test]
    fn verify_rejects_malformed_base64() {
        // A sha512- token whose payload isn't valid base64 is a hard error, not a silent mismatch.
        assert!(verify("p", b"x", "sha512-@@@@").is_err());
    }

    #[test]
    fn verify_finds_sha512_among_algorithms_and_tolerates_whitespace() {
        // An SRI string may list several space-separated algorithms; we find and check the sha512 one.
        let bytes = b"multi-algorithm payload";
        let b64 = base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes));
        let integrity = format!("  sha1-deadbeef   sha512-{b64}  ");
        verify("p", bytes, &integrity).expect("sha512 is found among the listed algorithms");
    }

    #[test]
    fn verify_rejects_a_short_digest() {
        // Valid base64, but it decodes to fewer than 64 bytes: the raw-slice compare rejects it
        // on length alone, so a truncated SRI can never match a full sha512 digest.
        let short = base64::engine::general_purpose::STANDARD.encode(b"only nine");
        let integrity = format!("sha512-{short}");
        assert!(
            verify("p", b"a downloaded tarball's bytes", &integrity).is_err(),
            "a sub-64-byte digest cannot match"
        );
    }

    #[test]
    fn verify_accepts_exactly_the_pinned_bytes_and_nothing_else() {
        // For several payloads the canonical SRI verifies, and flipping any single byte of the
        // data fails: the check accepts exactly the pinned bytes, never a near-miss.
        for payload in [b"".as_slice(), b"x", b"a slightly longer tarball payload"] {
            let good = format!(
                "sha512-{}",
                base64::engine::general_purpose::STANDARD.encode(Sha512::digest(payload))
            );
            verify("p", payload, &good).expect("the exact payload verifies");
            for i in 0..payload.len() {
                let mut tampered = payload.to_vec();
                tampered[i] ^= 0xff;
                assert!(
                    verify("p", &tampered, &good).is_err(),
                    "flipping byte {i} must fail"
                );
            }
        }
    }
}
