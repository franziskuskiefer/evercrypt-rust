mod test_util;
use test_util::*;

use evercrypt::ed25519::{self, Point, Scalar};
use evercrypt::signature::{self, Mode};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(non_snake_case)]
struct Ed25519TestVector {
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
    jwk: Value, // not used here
    key: EdDsaKey,
    keyDer: String,
    keyPem: String,
    r#type: String,
    tests: Vec<Test>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(non_snake_case)]
struct EdDsaKey {
    curve: String,
    keySize: usize,
    pk: String,
    sk: String,
    r#type: String,
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

impl ReadFromFile for Ed25519TestVector {}

#[allow(non_snake_case)]
#[test]
fn test_wycheproof() {
    let tests: Ed25519TestVector =
        Ed25519TestVector::from_file("tests/wycheproof/testvectors/eddsa_test.json");

    assert_eq!(tests.algorithm, "EDDSA");

    let num_tests = tests.numberOfTests;
    let mut tests_run = 0;

    for testGroup in tests.testGroups.iter() {
        assert_eq!(testGroup.key.curve, "edwards25519");
        assert_eq!(testGroup.r#type, "EddsaVerify");
        assert_eq!(testGroup.key.keySize, 255);

        let pk: Point = hex_str_to_array(&testGroup.key.pk);
        let sk: Scalar = hex_str_to_array(&testGroup.key.sk);

        let my_pk = ed25519::sk2pk(&sk);
        assert_eq!(&pk[..], &my_pk[..]);
        for test in testGroup.tests.iter() {
            let valid = test.result.eq("valid");
            println!("Test {:?}: {:?}", test.tcId, test.comment);
            let msg = hex_str_to_bytes(&test.msg);
            let sig = hex_str_to_bytes(&test.sig); // Can't use to_array because it's too large
            if sig.len() != 64 {
                assert!(!valid);
                tests_run += 1;
                continue;
            }
            let mut signature = [0u8; 64];
            signature.clone_from_slice(&sig);

            let my_sig = ed25519::eddsa_sign(&sk, &msg);
            let my_sig_ = signature::sign(Mode::Ed25519, None, &sk, &msg, None);
            assert_eq!(&my_sig[..], &my_sig_.unwrap()[..]);
            if valid {
                assert_eq!(&my_sig[..], &signature[..]);
            }
            let sig_verified = ed25519::eddsa_verify(&pk, &signature, &msg);
            let sig_verified_ = signature::verify(Mode::Ed25519, None, &pk, &sig, &msg);
            assert_eq!(sig_verified, sig_verified_.unwrap());
            if valid {
                assert!(sig_verified);
            }
            tests_run += 1;
        }
    }
    // Check that we ran all tests.
    println!("Ran {} out of {} tests.", tests_run, num_tests);
    assert_eq!(num_tests, tests_run);
}
