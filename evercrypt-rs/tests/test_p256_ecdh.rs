mod test_util;
use test_util::*;

use evercrypt::ecdh::{self, Mode};
use evercrypt::p256::{self, Error};

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
        P256TestVector::from_file("tests/wycheproof/testvectors/ecdh_secp256r1_ecpoint_test.json");

    assert_eq!(tests.algorithm, "ECDH");

    let num_tests = tests.numberOfTests;
    let mut tests_run = 0;

    for testGroup in tests.testGroups.iter() {
        assert_eq!(testGroup.curve, "secp256r1");
        assert_eq!(testGroup.r#type, "EcdhEcpointTest");
        assert_eq!(testGroup.encoding, "ecpoint");
        for test in testGroup.tests.iter() {
            println!("Test {:?}: {:?}", test.tcId, test.comment);

            let valid = test.result.eq("valid") || test.result.eq("acceptable");
            let public = hex_str_to_bytes(&test.public);
            let private = hex_str_to_bytes(&test.private);
            let shared = hex_str_to_bytes(&test.shared);

            let result = p256::dh(&public, &private);
            let result_ = ecdh::derive(Mode::P256, &public, &private);
            match result {
                Ok(r) => {
                    assert!(valid);
                    assert_eq!(r[..], result_.unwrap()[..]);
                    // r holds the entire point. We only care about X
                    assert_eq!(r[..32], shared[..]);
                }
                Err(e) => {
                    println!("Error case");
                    println!("test: {:?}", test);
                    assert!(!valid);
                    assert_eq!(e, Error::InvalidPoint);
                }
            }
            tests_run += 1;
        }
    }
    // Check that we ran all tests.
    println!("Ran {} out of {} tests.", tests_run, num_tests);
    assert_eq!(num_tests, tests_run);
}
