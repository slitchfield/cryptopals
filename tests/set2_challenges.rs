use block_ciphers::stable_ecb_oracle;
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

#[test]
fn challenge_11() -> Result<(), &'static str> {
    let _detected_type =
        crate::block_ciphers::ecb_detector(crate::block_ciphers::encryption_oracle).unwrap();
    dbg!(_detected_type);
    Ok(())
}

fn vector_compare(va: &[u8], vb: &[u8]) -> bool {
    (va.len() == vb.len()) && va.iter().zip(vb).all(|(a, b)| a == b)
}

use std::collections::HashMap;
fn find_key_for_value(map: &HashMap<u8, Vec<u8>>, value: &Vec<u8>) -> Option<u8> {
    map.iter().find_map(|(key, val)| {
        if vector_compare(val, value) {
            Some(*key)
        } else {
            None
        }
    })
}

#[test]
fn challenge_12() -> Result<(), &'static str> {
    // 1. Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block size of the cipher.
    let block_size = crate::block_ciphers::detect_block_size(stable_ecb_oracle).unwrap();

    // 2. Detect that the function is using ECB.
    let cryptotype = crate::block_ciphers::ecb_detector(stable_ecb_oracle).unwrap();
    assert!(matches!(cryptotype, crate::block_ciphers::CRYPTOTYPE::ECB));

    // 3. Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put in that last byte position.
    let oracle_input = "A".repeat(block_size - 1);

    // 4. Make a dictionary of every possible last byte by feeding different strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.
    println!("Generating dictionary...");
    let printable_ascii = b" !\"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
    let mut oracle_dictionary: HashMap<u8, Vec<u8>> = HashMap::new();
    for ch in printable_ascii {
        let mut full_oracle_input = oracle_input.clone();
        full_oracle_input.push(*ch as char);
        let mut oracle_output =
            crate::block_ciphers::stable_ecb_oracle(full_oracle_input.as_bytes()).unwrap();
        oracle_output.truncate(block_size);
        print!("\tPushing \'{}\' => \'", full_oracle_input);
        for b in oracle_output.iter() {
            print!("{:02x} ", b);
        }
        println!("\'");
        oracle_dictionary.insert(*ch, oracle_output);
    }

    // 5. Match the output of the one-byte-short input to one of the entries in your dictionary. You've now discovered the first byte of unknown-string.
    println!("Trying short block...");
    let mut oracle_output =
        crate::block_ciphers::stable_ecb_oracle(oracle_input.as_bytes()).unwrap();
    oracle_output.truncate(block_size);
    print!("\tGot     \'{}\' => \'", oracle_input);
    for b in oracle_output.iter() {
        print!("{:02x} ", b);
    }
    println!("\'");
    let first_char = find_key_for_value(&oracle_dictionary, &oracle_output)
        .unwrap_or_else(|| panic!("Could not find expected output!"));
    dbg!(first_char as char);

    // 6. Repeat for the next byte.

    Ok(())
}
