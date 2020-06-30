mod test_util;
use test_util::*;

use evercrypt::hmac::{hmac, Mode};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(non_snake_case)]
struct HmacTestVector {
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
    keySize: usize,
    tagSize: usize,
    r#type: String,
    tests: Vec<Test>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(non_snake_case)]
struct Test {
    tcId: usize,
    comment: String,
    key: String,
    msg: String,
    tag: String,
    result: String,
    flags: Vec<String>,
}

impl ReadFromFile for HmacTestVector {}

#[allow(non_snake_case)]
#[test]
fn test_wycheproof() {
    let sha1_tests: HmacTestVector =
        HmacTestVector::from_file("tests/wycheproof/testvectors/hmac_sha1_test.json");
    let sha256_tests: HmacTestVector =
        HmacTestVector::from_file("tests/wycheproof/testvectors/hmac_sha256_test.json");
    let sha384_tests: HmacTestVector =
        HmacTestVector::from_file("tests/wycheproof/testvectors/hmac_sha384_test.json");
    let sha512_tests: HmacTestVector =
        HmacTestVector::from_file("tests/wycheproof/testvectors/hmac_sha512_test.json");

    let test_vectors = [sha1_tests, sha256_tests, sha384_tests, sha512_tests];

    for tests in test_vectors.iter() {
        let algorithm = match tests.algorithm.as_str() {
            "HMACSHA1" => Mode::Sha1,
            "HMACSHA256" => Mode::Sha256,
            "HMACSHA384" => Mode::Sha384,
            "HMACSHA512" => Mode::Sha512,
            _ => panic!("Unknown HMAC algorithm {}", tests.algorithm),
        };
        println!("Testing {:?}", algorithm);

        let num_tests = tests.numberOfTests;
        let mut tests_run = 0;

        for testGroup in tests.testGroups.iter() {
            assert_eq!(testGroup.r#type, "MacTest");
            let _key_size = testGroup.keySize;
            let tag_size = testGroup.tagSize;
            for test in testGroup.tests.iter() {
                let valid = test.result.eq("valid");
                println!("Test {:?}: {:?}", test.tcId, test.comment);
                let key = hex_str_to_bytes(&test.key);
                let msg = hex_str_to_bytes(&test.msg);
                let tag = hex_str_to_bytes(&test.tag);

                let r = hmac(algorithm, &key, &msg, Some(tag_size >> 3));
                if valid {
                    assert_eq!(r[..], tag[..]);
                }
                tests_run += 1;
            }
        }
        // Check that we ran all tests.
        println!("Ran {} out of {} tests.", tests_run, num_tests);
        assert_eq!(num_tests, tests_run);
    }
}
