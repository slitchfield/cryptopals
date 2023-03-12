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

#[test]
fn challenge_10() -> Result<(), &'static str> {
    use std::fs::File;
    use std::io::BufRead;
    use std::path::Path;

    let target_path = Path::new("./inputs/set2/10.txt");
    let _display = target_path.display();
    let file = match File::open(target_path) {
        Err(_why) => {
            panic!("Could not open file");
        }
        Ok(file) => file,
    };

    let bufreader = std::io::BufReader::new(file);

    let mut file_bytes: Vec<u8> = vec![];

    for line in bufreader.lines() {
        match line {
            Ok(s) => match conversions::base64_to_bytes(s) {
                Ok(mut bytes) => {
                    file_bytes.append(&mut bytes);
                }
                Err(_err) => {
                    println!("ParseIntErr!");
                }
            },
            Err(_err) => {
                println!("Line read error?")
            }
        }
    }

    let key = b"YELLOW SUBMARINE";
    let iv = &[0u8; 16];

    let second_recovered_plaintext =
        block_ciphers::simple_cbc_decrypt(&file_bytes, key, iv).unwrap();
    println!(
        "Recovered plaintext:\n\n{}",
        conversions::bytes_to_str(&second_recovered_plaintext).unwrap()
    );

    Ok(())
}
