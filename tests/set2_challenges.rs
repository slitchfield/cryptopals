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

fn find_next_char(
    block_size: usize,
    unknown_message: &String,
    oracle: fn(&[u8]) -> Result<Vec<u8>, &'static str>,
) -> Option<char> {
    // Identify required inputs
    let num_identified_chars = unknown_message.len();
    let cur_char_idx = num_identified_chars;
    let block_offset = cur_char_idx / block_size;
    let char_offset = cur_char_idx % block_size;
    let oracle_input = "A".repeat(block_size - (char_offset + 1));
    println!("Cracking Block {} Char {}", block_offset, char_offset);
    println!("\tResulting oracle input: {}", oracle_input);

    // 4. Make a dictionary of every possible last byte by feeding different strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.
    println!("Generating dictionary...");
    // let printable_ascii = b" !\"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
    let mut oracle_dictionary: HashMap<u8, Vec<u8>> = HashMap::new();
    for ch in 0u8..128u8 {
        let mut full_oracle_input = oracle_input.clone();
        full_oracle_input.push_str(unknown_message);
        full_oracle_input.push(ch as char);
        let start_idx = block_offset * block_size;
        let end_idx = start_idx + block_size;
        let oracle_output = oracle(&full_oracle_input.as_bytes()).unwrap();
        let block_of_interest = Vec::from(&oracle_output[start_idx..end_idx]);
        print!(
            "\tPushing \'{}\' => ({}..{}) \'",
            &full_oracle_input[start_idx..end_idx],
            start_idx,
            end_idx
        );
        for b in block_of_interest.iter() {
            print!("{:02x} ", b);
        }
        println!("\'");
        oracle_dictionary.insert(ch, block_of_interest);
    }

    // 5. Match the output of the one-byte-short input to one of the entries in your dictionary. You've now discovered the first byte of unknown-string.
    println!("Trying short block...");
    let mut oracle_output = oracle(oracle_input.as_bytes()).unwrap();
    let start_idx = block_offset * block_size;
    let end_idx = start_idx + block_size;
    let block_of_interest = Vec::from(&oracle_output[start_idx..end_idx]);
    oracle_output.truncate(block_size);
    print!("\tGot     \'{:15}\'  => \'", oracle_input);
    for b in block_of_interest.iter() {
        print!("{:02x} ", b);
    }
    println!("\'");
    if let Some(next_char) = find_key_for_value(&oracle_dictionary, &block_of_interest) {
        print!("\tFound match            \'{}\' => \'", next_char as char);
        for b in oracle_dictionary[&next_char].iter() {
            print!("{:02x} ", b);
        }
        println!("");
        Some(next_char as char)
    } else {
        println!("Could not find match, presumed end of message");
        None
    }
}

#[test]
fn challenge_12() -> Result<(), &'static str> {
    let mut unknown_message = String::new();
    // 1. Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block size of the cipher.
    let block_size = crate::block_ciphers::detect_block_size(stable_ecb_oracle).unwrap();

    // 2. Detect that the function is using ECB.
    let cryptotype = crate::block_ciphers::ecb_detector(stable_ecb_oracle).unwrap();
    assert!(matches!(cryptotype, crate::block_ciphers::CRYPTOTYPE::ECB));

    let unknown_message_len = crate::block_ciphers::stable_ecb_oracle("".as_bytes())
        .unwrap()
        .len();

    for char_idx in 0..unknown_message_len {
        println!("Cracking offset {} of {}", char_idx, unknown_message_len);
        if let Some(next_char) = find_next_char(
            block_size,
            &unknown_message,
            crate::block_ciphers::stable_ecb_oracle,
        ) {
            unknown_message.push(next_char);
            println!("Unknown message:\n{}", unknown_message);
        } else {
            println!("Could not find next char. Presumed end of message, exiting");
            break;
        }
    }

    print!("Final unknown message:\n\n{}", unknown_message);

    Ok(())
}

fn kv_parsing(input_str: &str) -> Result<HashMap<String, String>, &'static String> {
    // Rough set of operations
    // 1. Split input_str by '&' characters
    // 2. Split each sub-token by '=' characters
    // 3. Insert k/v into hashmap
    let mut ret_map = HashMap::new();

    for token in input_str.split('&') {
        let (k, v) = token.split_at(token.find('=').unwrap());
        let v = &v[1..];
        println!("Token: \"{}\" = \"{}\"", k, v);
        ret_map.insert(String::from(k), String::from(v));
    }
    Ok(ret_map)
}

fn kv_encoding(input_struct: &HashMap<String, String>) -> Result<String, &'static String> {

    let mut ret_str: String = String::new();
    for (k, v) in input_struct {
        ret_str.push_str(k.as_str());
        ret_str.push_str("=");
        ret_str.push_str(v.as_str());
        ret_str.push_str("&")
    }
    ret_str.pop(); // Remove trailing "&". TODO: find way to insert & only between tokens
    Ok(ret_str)
}

use std::sync::atomic::{AtomicU32, Ordering};
fn profile_for(emailaddr: String) -> Result<String, &'static String> {
    // First, escape all encoding metacharacters
    let sanitized_email = emailaddr.replace("&", "AND");
    let sanitized_email = sanitized_email.replace("=", "EQUALS");
    static uid_gen: AtomicU32 = AtomicU32::new(0);
    let uid = uid_gen.fetch_add(1, Ordering::Relaxed);
    let role = String::from("user");

    let mut encoded_str = String::new();
    encoded_str.push_str("email=");
    encoded_str.push_str(&sanitized_email);
    encoded_str.push_str("&uid=");
    encoded_str.push_str(&uid.to_string());
    encoded_str.push_str("&role=");
    encoded_str.push_str(&role);

    Ok(encoded_str)
}

#[test]
fn challenge_13() -> Result<(), &'static String> {

    let input_str = "foo=bar&baz=qux&zap=zazzle";
    let parsed_struct: HashMap<String, String> = kv_parsing(&input_str)?;
    let _encoded_str = kv_encoding(&parsed_struct)?;

    let encoded_profile = profile_for(String::from("foo@bar.com"))?; 
    dbg!(encoded_profile);
    let encoded_profile = profile_for(String::from("foo@bar.com&role=admin"))?; 
    dbg!(encoded_profile);
    Ok(())
}
