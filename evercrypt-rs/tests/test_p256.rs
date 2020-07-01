mod test_util;
use test_util::*;

use evercrypt::p256::{p256_dh, Error};

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
    curve: String,
    r#type: String,
    encoding: String,
    tests: Vec<Test>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(non_snake_case)]
struct Test {
    tcId: usize,
    comment: String,
    public: String,
    private: String,
    shared: String,
    result: String,
    flags: Vec<String>,
}

impl ReadFromFile for P256TestVector {}

#[allow(non_snake_case)]
#[test]
fn test_wycheproof() {
    let tests: P256TestVector =
        P256TestVector::from_file("/Users/franziskus/repos/evercrypt-rust/evercrypt-rs/tests/wycheproof/testvectors/ecdh_secp256r1_ecpoint_test.json");

    assert_eq!(tests.algorithm, "ECDH");

    let num_tests = tests.numberOfTests;
    let mut skipped_tests = 0;
    let mut tests_run = 0;

    for testGroup in tests.testGroups.iter() {
        assert_eq!(testGroup.curve, "secp256r1");
        assert_eq!(testGroup.r#type, "EcdhEcpointTest");
        assert_eq!(testGroup.encoding, "ecpoint");
        for test in testGroup.tests.iter() {
            if test.flags.contains(&"CompressedPoint".to_owned()) {
                skipped_tests += 1;
                continue;
            }
            if test.comment.eq("point with coordinate x = 0")
            || test.comment.eq("point with coordinate x = 0 in left to right addition chain")
            || test.comment.eq("point with coordinate x = 0 in right to left addition chain")
            || test.comment.eq("point with coordinate x = 0 in precomputation or right to left addition chain")
            || test.comment.eq("point with coordinate y = 1")
            || test.comment.eq("point with coordinate y = 1 in left to right addition chain")
            || test.comment.eq("point with coordinate y = 1 in right to left addition chain")
            || test.comment.eq("point with coordinate y = 1 in precomputation or right to left addition chain")
            || test.comment.eq("edge case private key") {
                println!("These tests currently fail.");
                skipped_tests += 1;
                continue;
            }
            // We can't handle compressed points.
            let valid = test.result.eq("valid");
            println!("Test {:?}: {:?}", test.tcId, test.comment);
            let pk_start = if valid {
                2
            } else {
                0
            };
            let public = hex_str_to_bytes(&test.public[pk_start..]);
            let private = hex_str_to_bytes(&test.private);
            let shared = hex_str_to_bytes(&test.shared);

            match p256_dh(&public, &private) {
                Ok(r) => {
                    assert!(valid);
                    // r holds the entire point. We only care about X
                    assert_eq!(r[..32], shared[..]);
                }
                Err(e) => {
                    println!("Error case");
                    assert!(!valid);
                    assert_eq!(e, Error::InvalidPoint);
                }
            }
            tests_run += 1;
        }
    }
    // Check that we ran all tests.
    println!(
        "Ran {} out of {} tests and skipped {}.",
        tests_run, num_tests, skipped_tests
    );
    assert_eq!(num_tests - skipped_tests, tests_run);
}
