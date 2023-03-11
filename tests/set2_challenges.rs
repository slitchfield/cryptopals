
use cryptopals::*;

#[test]
fn challenge_9() -> Result<(), &'static str> {
    let input = b"YELLOW SUBMARINE";
    let output = b"YELLOW SUBMARINE\x04\x04\x04\x04";

    let test_result = utility::pkcs7_padding(input, 20).unwrap();
    assert_eq!(test_result, output);

    let output =
        b"YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10";

    let test_result = utility::pkcs7_padding(input, 16).unwrap();
    assert_eq!(test_result, output);

    Ok(())
}