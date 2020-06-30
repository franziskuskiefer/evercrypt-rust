mod test_util;
use test_util::*;

use evercrypt::aead::{Aead, Error, Mode};

#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(non_snake_case)]
struct AeadTestVector {
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
    ivSize: usize,
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
    iv: String,
    aad: String,
    msg: String,
    ct: String,
    tag: String,
    result: String,
    flags: Vec<String>,
}

impl ReadFromFile for AeadTestVector {}

#[allow(non_snake_case)]
#[test]
fn test_wycheproof() {
    let aes_gcm_tests: AeadTestVector =
        AeadTestVector::from_file("tests/wycheproof/testvectors/aes_gcm_test.json");
    let chacha_poly_tests: AeadTestVector =
        AeadTestVector::from_file("tests/wycheproof/testvectors/chacha20_poly1305_test.json");

    let num_tests = aes_gcm_tests.numberOfTests + chacha_poly_tests.numberOfTests;
    let mut skipped_tests = 0;
    let mut tests_run = 0;
    assert_eq!(aes_gcm_tests.algorithm, "AES-GCM");
    assert_eq!(chacha_poly_tests.algorithm, "CHACHA20-POLY1305");

    test_group(aes_gcm_tests, &mut skipped_tests, &mut tests_run);
    test_group(chacha_poly_tests, &mut skipped_tests, &mut tests_run);

    fn test_group(test_vec: AeadTestVector, skipped_tests: &mut usize, tests_run: &mut usize) {
        for testGroup in test_vec.testGroups.iter() {
            assert_eq!(testGroup.r#type, "AeadTest");
            let algorithm = match test_vec.algorithm.as_str() {
                "AES-GCM" => match testGroup.keySize {
                    128 => Mode::Aes128Gcm,
                    256 => Mode::Aes256Gcm,
                    _ => {
                        // not implemented
                        println!("Only AES 128 and 256 are implemented.");
                        *skipped_tests += testGroup.tests.len();
                        continue;
                    }
                },
                "CHACHA20-POLY1305" => {
                    assert_eq!(testGroup.keySize, 256);
                    Mode::Chacha20Poly1305
                }
                _ => panic!("Unknown algorithm {:?}", test_vec.algorithm),
            };
            let invalid_iv = if testGroup.ivSize != 96 { true } else { false };

            for test in testGroup.tests.iter() {
                let valid = test.result.eq("valid");
                let invalid_iv = if test.comment == "invalid nonce size" || invalid_iv {
                    true
                } else {
                    false
                };
                println!("Test {:?}: {:?}", test.tcId, test.comment);
                let nonce = hex_str_to_bytes(&test.iv);
                let msg = hex_str_to_bytes(&test.msg);
                let aad = hex_str_to_bytes(&test.aad);
                let exp_cipher = hex_str_to_bytes(&test.ct);
                let exp_tag = hex_str_to_bytes(&test.tag);
                let key = hex_str_to_bytes(&test.key);

                let cipher = Aead::new(algorithm, &key).unwrap();
                let (ctxt, tag) = match cipher.encrypt(&msg, &nonce, &aad) {
                    Ok(v) => v,
                    Err(e) => {
                        if invalid_iv {
                            assert_eq!(e, Error::InvalidNonce);
                        } else {
                            println!("Encrypt failed unexpectedly {:?}", e);
                            assert!(false);
                        }
                        *tests_run += 1;
                        continue;
                    }
                };
                if valid {
                    assert_eq!(tag, exp_tag);
                } else {
                    assert_ne!(tag, exp_tag);
                }
                assert_eq!(ctxt, exp_cipher);
                *tests_run += 1;
            }
        }
    }
    // Check that we ran all tests.
    println!(
        "Ran {} out of {} tests and skipped {}.",
        tests_run, num_tests, skipped_tests
    );
    assert_eq!(num_tests - skipped_tests, tests_run);
}
