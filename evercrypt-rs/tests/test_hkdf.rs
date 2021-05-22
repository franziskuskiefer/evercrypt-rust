mod test_util;
use test_util::*;

use evercrypt::prelude::*;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(non_snake_case)]
struct HkdfTestVector {
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
    r#type: String,
    tests: Vec<Test>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(non_snake_case)]
struct Test {
    tcId: usize,
    comment: String,
    ikm: String,
    salt: String,
    info: String,
    size: usize,
    okm: String,
    result: String,
    flags: Vec<String>,
}

impl ReadFromFile for HkdfTestVector {}

#[allow(non_snake_case)]
#[test]
fn test_wycheproof() {
    let sha1_tests: HkdfTestVector =
        HkdfTestVector::from_file("tests/wycheproof/testvectors/hkdf_sha1_test.json");
    let sha256_tests: HkdfTestVector =
        HkdfTestVector::from_file("tests/wycheproof/testvectors/hkdf_sha256_test.json");
    let sha384_tests: HkdfTestVector =
        HkdfTestVector::from_file("tests/wycheproof/testvectors/hkdf_sha384_test.json");
    let sha512_tests: HkdfTestVector =
        HkdfTestVector::from_file("tests/wycheproof/testvectors/hkdf_sha512_test.json");

    let test_vectors = [sha1_tests, sha256_tests, sha384_tests, sha512_tests];

    for tests in test_vectors.iter() {
        let algorithm = match tests.algorithm.as_str() {
            "HKDF-SHA-1" => HmacMode::Sha1,
            "HKDF-SHA-256" => HmacMode::Sha256,
            "HKDF-SHA-384" => HmacMode::Sha384,
            "HKDF-SHA-512" => HmacMode::Sha512,
            _ => panic!("Unknown HKDF algorithm {}", tests.algorithm),
        };
        println!("Testing {:?}", algorithm);

        let num_tests = tests.numberOfTests;
        let mut tests_run = 0;

        for testGroup in tests.testGroups.iter() {
            assert_eq!(testGroup.r#type, "HkdfTest");
            let _key_size = testGroup.keySize;
            for test in testGroup.tests.iter() {
                let _valid = test.result.eq("valid");
                println!("Test {:?}: {:?}", test.tcId, test.comment);
                let ikm = hex_str_to_bytes(&test.ikm);
                let salt = hex_str_to_bytes(&test.salt);
                let info = hex_str_to_bytes(&test.info);
                let size = test.size;
                let okm = hex_str_to_bytes(&test.okm);

                // Single-shot
                let r = hkdf(algorithm, &salt, &ikm, &info, size);

                // Extract & Expand
                let prk = hkdf_extract(algorithm, &salt, &ikm);
                let r_expand = hkdf_expand(algorithm, &prk, &info, size);

                assert_eq!(r[..], okm[..]);
                assert_eq!(r_expand[..], okm[..]);

                tests_run += 1;
            }
        }
        // Check that we ran all tests.
        println!("Ran {} out of {} tests.", tests_run, num_tests);
        assert_eq!(num_tests, tests_run);
    }
}

#[test]
fn test_empty_salt() {
    let algorithm = HmacMode::Sha1;
    let ikm = hex_str_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let okm = hex_str_to_bytes(
        "0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918",
    );
    let prk = hkdf_extract(algorithm, &vec![0u8; tag_size(algorithm)], &ikm);
    let r_expand = hkdf_expand(algorithm, &prk, &[], 42);
    assert_eq!(r_expand[..], okm[..]);
    let prk = hkdf_extract(algorithm, &[], &ikm);
    let r_expand = hkdf_expand(algorithm, &prk, &[], 42);
    assert_eq!(r_expand[..], okm[..]);
}
