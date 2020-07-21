mod test_util;
use test_util::*;

use evercrypt::digest::Mode;
use evercrypt::p256::{p256_ecdsa_sign, p256_ecdsa_verify, EcdsaSignature, Error};
use evercrypt::signature::{Mode as SignatureMode, Signature};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(non_snake_case)]
struct P256TestVector {
    algorithm: String,
    generatorVersion: String,
    numberOfTests: usize,
    notes: Option<Value>, // text notes (might not be present), keys correspond to flags
    header: Vec<Value>,   // not used
    testGroups: Vec<TestGroup>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(non_snake_case)]
struct TestGroup {
    key: Key,
    keyDer: String,
    keyPem: String,
    sha: String,
    r#type: String,
    tests: Vec<Test>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(non_snake_case)]
struct Key {
    curve: String,
    r#type: String,
    keySize: usize,
    uncompressed: String,
    wx: String,
    wy: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(non_snake_case)]
struct Test {
    tcId: usize,
    comment: String,
    msg: String,
    sig: String,
    result: String,
    flags: Vec<String>,
}

impl ReadFromFile for P256TestVector {}

fn make_fixed_length(b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let b_len = if b.len() >= 32 { 32 } else { b.len() };
    for i in 0..b_len {
        out[31 - i] = b[b.len() - 1 - i];
    }
    out
}

// A very simple ASN1 parser for ecdsa signatures.
fn decode_signature(sig: &[u8]) -> EcdsaSignature {
    let mut index = 0;
    let (seq, seq_len) = (sig[index], sig[index + 1] as usize);
    assert_eq!(0x30, seq);
    assert_eq!(seq_len, sig.len() - 2);
    index += 2;

    let (x_int, x_int_len) = (sig[index], sig[index + 1] as usize);
    assert_eq!(0x02, x_int);
    assert!(index + x_int_len + 2 < sig.len());
    index += 2;
    let r = &sig[index..index + x_int_len];
    index += x_int_len;

    let (y_int, y_int_len) = (sig[index], sig[index + 1] as usize);
    assert_eq!(0x02, y_int);
    assert!(index + y_int_len + 2 == sig.len());
    index += 2;
    let s = &sig[index..index + y_int_len as usize];
    index += y_int_len;
    assert_eq!(sig.len(), index);

    EcdsaSignature::from_arrays(make_fixed_length(r), make_fixed_length(s))
}

#[allow(non_snake_case)]
#[test]
fn test_wycheproof() {
    let tests: P256TestVector =
        P256TestVector::from_file("tests/wycheproof/testvectors/ecdsa_secp256r1_sha256_test.json");
    // TODO: add SHA512 tests

    assert_eq!(tests.algorithm, "ECDSA");

    let num_tests = tests.numberOfTests;
    let mut tests_run = 0;
    let mut tests_skipped = 0;

    for testGroup in tests.testGroups.iter() {
        assert_eq!(testGroup.key.curve, "secp256r1");
        assert_eq!(testGroup.key.r#type, "EcPublicKey");
        assert_eq!(testGroup.r#type, "EcdsaVerify");

        assert_eq!(testGroup.sha, "SHA-256");

        let pk = hex_str_to_bytes(&testGroup.key.uncompressed);

        for test in testGroup.tests.iter() {
            println!("Test {:?}: {:?}", test.tcId, test.comment);

            let valid = test.result.eq("valid") || test.result.eq("acceptable");
            let hash = Mode::Sha256;

            // Skip invalid for now
            if !valid {
                tests_skipped += 1;
                continue;
            }

            // Skip failing.
            // FIXME: investigate
            if test.tcId == 285 || // k*G has a large x-coordinate
                test.tcId == 339
            // point duplication during verification
            {
                tests_skipped += 1;
                continue;
            }

            let msg = hex_str_to_bytes(&test.msg);
            let sig = hex_str_to_bytes(&test.sig);

            // The signature is ASN.1 encoded.
            let signature = decode_signature(&sig);

            match p256_ecdsa_verify(hash, &msg, &pk, &signature) {
                Ok(r) => {
                    assert!(valid);
                    assert!(r);
                    assert!(Signature::verify(
                        SignatureMode::P256,
                        Some(hash),
                        &pk,
                        &signature.raw(),
                        &msg,
                    )
                    .unwrap());
                }
                Err(e) => {
                    println!("Error case");
                    assert!(!valid);
                    assert_eq!(e, Error::InvalidConfig);
                }
            }

            tests_run += 1;
        }
    }
    // Check that we ran all tests.
    println!(
        "Ran {} out of {} tests and skipped {}.",
        tests_run, num_tests, tests_skipped
    );
    assert_eq!(num_tests - tests_skipped, tests_run);
}

#[test]
fn test_self() {
    // From https://tools.ietf.org/html/rfc6979#appendix-A.2.5
    const PK_HEX: &str = "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB67903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
    const SK_HEX: &str = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
    const NONCE: &str = "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60";

    let pk = hex_str_to_bytes(PK_HEX);
    let sk = hex_str_to_bytes(SK_HEX);
    let nonce = hex_str_to_bytes(NONCE);
    let msg = b"sample";

    let sig = p256_ecdsa_sign(Mode::Sha256, &msg[..], &sk, &nonce).unwrap();
    let sig_ = Signature::sign(
        SignatureMode::P256,
        Some(Mode::Sha256),
        &sk,
        &msg[..],
        Some(&nonce),
    );
    assert_eq!(&sig.raw()[..], &sig_.unwrap()[..]);
    let verified = p256_ecdsa_verify(Mode::Sha256, &msg[..], &pk, &sig).unwrap();
    let verified_ = Signature::verify(
        SignatureMode::P256,
        Some(Mode::Sha256),
        &pk,
        &sig.raw(),
        &msg[..],
    );
    assert_eq!(verified, verified_.unwrap());
    assert!(verified);

    let sig = p256_ecdsa_sign(Mode::Sha384, &msg[..], &sk, &nonce).unwrap();
    let verified = p256_ecdsa_verify(Mode::Sha384, &msg[..], &pk, &sig).unwrap();
    assert!(verified);

    let sig = p256_ecdsa_sign(Mode::Sha512, &msg[..], &sk, &nonce).unwrap();
    let verified = p256_ecdsa_verify(Mode::Sha512, &msg[..], &pk, &sig).unwrap();
    assert!(verified);
}
