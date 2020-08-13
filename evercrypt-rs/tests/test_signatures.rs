use evercrypt::prelude::*;

#[test]
fn test_p256_signature() {
    let msg = b"Message to sign";
    let (sk, pk) = signature_key_gen(SignatureMode::P256).unwrap();
    let sig = sign(
        SignatureMode::P256,
        Some(DigestMode::Sha256),
        &sk,
        msg,
        Some(&p256_ecdsa_random_nonce()),
    )
    .unwrap();
    let verified = verify(
        SignatureMode::P256,
        Some(DigestMode::Sha256),
        &pk,
        &sig,
        msg,
    )
    .unwrap();
    assert!(verified);
}
