mod test_util;
use test_util::*;

use evercrypt::ed25519::{ed25519_sign, ed25519_sk2pk, ed25519_verify};
use evercrypt::signature::{Mode, Signature};

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

        let pk = hex_str_to_bytes(&testGroup.key.pk);
        let sk = hex_str_to_bytes(&testGroup.key.sk);

        let my_pk = ed25519_sk2pk(&sk);
        assert_eq!(&pk[..], &my_pk[..]);
        for test in testGroup.tests.iter() {
            let valid = test.result.eq("valid");
            println!("Test {:?}: {:?}", test.tcId, test.comment);
            let msg = hex_str_to_bytes(&test.msg);
            let sig = hex_str_to_bytes(&test.sig);

            let my_sig = ed25519_sign(&sk, &msg);
            let my_sig_ = Signature::sign(Mode::Ed25519, None, &sk, &msg, None);
            assert_eq!(&my_sig[..], &my_sig_.unwrap()[..]);
            if valid {
                assert_eq!(&my_sig[..], &sig[..]);
            }
            let sig_verified = ed25519_verify(&pk, &sig, &msg);
            let sig_verified_ = Signature::verify(Mode::Ed25519, None, &pk, &sig, &msg);
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
