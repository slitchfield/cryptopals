use cryptopals::conversions;
use cryptopals::xor;

#[test]
fn challenge_1() -> Result<(), &'static str> {
    let hex_str = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    let base64_str =
        String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");

    let bytes: Vec<u8> = match conversions::read_hexstr_as_bytes(hex_str.as_ref()) {
        Ok(v) => v,
        Err(_) => {
            panic!()
        }
    };

    assert_eq!(conversions::bytes_to_base64(bytes)?, base64_str);

    Ok(())
}

#[test]
fn challenge_2() -> Result<(), &'static str> {
    let buf1 = match conversions::read_hexstr_as_bytes(
        String::from("1c0111001f010100061a024b53535009181c").as_ref(),
    ) {
        Ok(v) => v,
        Err(_) => {
            panic!()
        }
    };

    let buf2 = match conversions::read_hexstr_as_bytes(
        String::from("686974207468652062756c6c277320657965").as_ref(),
    ) {
        Ok(v) => v,
        Err(_) => {
            panic!()
        }
    };

    let _ = xor::fixed_xor(&buf1, &buf2)?;

    Ok(())
}

#[test]
fn challenge_3() -> Result<(), &'static str> {
    let buf = match conversions::read_hexstr_as_bytes(
        String::from("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
            .as_ref(),
    ) {
        Ok(v) => v,
        Err(_) => {
            panic!()
        }
    };

    let (plaintext, key, score) = xor::recover_xor_key(&buf)?;
    //println!("Final Plaintext: {}", String::from_utf8(plaintext.clone()).unwrap());
    println!(
        "Final Plaintext: {}",
        conversions::bytes_to_str(&plaintext).unwrap()
    );
    println!("Final Key:       {}", key);
    println!("Final Score:     {}", score);

    Ok(())
}

#[test]
fn challenge_4() -> Result<(), &'static str> {
    use std::fs::File;
    use std::io::BufRead;
    use std::path::Path;

    #[derive(Debug)]
    struct Result {
        input: Vec<u8>,
        plaintext: Vec<u8>,
        key: char,
        score: f32,
    }

    let target_path = Path::new("./inputs/set1/4.txt");
    let _display = target_path.display();

    let file = match File::open(target_path) {
        Err(_why) => {
            panic!("Could not open file");
        }
        Ok(file) => file,
    };

    let bufreader = std::io::BufReader::new(file);

    let mut res_vec: Vec<Result> = vec![];

    for line in bufreader.lines() {
        match line {
            Ok(s) => {
                match conversions::read_hexstr_as_bytes(&s) {
                    Ok(bytes) => {
                        //println!("Original String: \"{}\"", s);
                        let (plaintext, key, score) = xor::recover_xor_key(&bytes)?;
                        //let plainstr = bytes_to_str(plaintext.clone()).unwrap();
                        //println!("\tFinal Plaintext: {}", plainstr);
                        //println!("\tFinal Key:       {}", key as char);
                        //println!("\tFinal Score:     {}", score);
                        let res: Result = Result {
                            input: bytes,
                            plaintext,
                            key,
                            score,
                        };
                        res_vec.push(res);
                    }
                    Err(_err) => {
                        println!("ParseIntErr!");
                    }
                }
            }
            Err(_err) => {
                println!("Line read error?")
            }
        }
    }
    use std::cmp::Ordering::Equal;
    res_vec.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(Equal));
    res_vec.reverse();

    for (i, elem) in res_vec.iter().enumerate().take(1) {
        println!("Top {} Result:", i + 1);
        let cipherstr = String::from_utf8_lossy(&elem.input);
        println!("\tCipherText:      {}", cipherstr);
        let plainstr = String::from_utf8_lossy(&elem.plaintext);
        println!("\tFinal Plaintext: {}", plainstr);
        println!("\tFinal Key:       {}", elem.key);
        println!("\tFinal Score:     {}", res_vec[i].score);
    }

    Ok(())
}

#[test]
fn challenge_5() -> Result<(), &'static str> {
    let plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let key = "ICE";
    let ciphertext  = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

    let plainbytes = conversions::str_to_bytes(plaintext).unwrap();
    let keybytes = conversions::str_to_bytes(key).unwrap();
    let test_left1 = xor::repeating_key_xor(&plainbytes, &keybytes).unwrap();
    let test_right1 = conversions::read_hexstr_as_bytes(ciphertext).unwrap();
    assert_eq!(test_left1, test_right1);

    Ok(())
}

#[test]
fn challenge_6() -> Result<(), &'static str> {
    use std::fs::File;
    use std::io::BufRead;
    use std::path::Path;

    let target_path = Path::new("./inputs/set1/6.txt");
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

    let key_len = xor::recover_key_len(&file_bytes, 2, 40).unwrap();

    // Break input into every key_len bytes
    let mut blocks: Vec<Vec<u8>> = vec![];
    let mut key_chars: Vec<u8> = vec![];

    for i in 0..key_len {
        // Construct blocks[i] out of every i'th byte
        blocks.push(vec![]);
        let mut block_iter = file_bytes.iter();

        if i > 0 {
            // Skip first elements to get stride right
            for _ in 0..i {
                block_iter.next();
            }
        }

        let stride: Vec<u8> = block_iter.step_by(key_len).copied().collect();

        let (_, key_char, _) = xor::recover_xor_key(&stride).unwrap();
        key_chars.push(key_char as u8);
    }
    println!(
        "Key found: {}",
        conversions::bytes_to_str(&key_chars).unwrap()
    );

    let plaintext = xor::repeating_key_xor(&file_bytes, &key_chars).unwrap();
    let plainstr = conversions::bytes_to_str(&plaintext).unwrap();
    println!("Plaintext: {}", plainstr);

    Ok(())
}

#[test]
fn challenge_7() -> Result<(), &'static str> {
    let key = "YELLOW SUBMARINE";
    let keybytes = conversions::str_to_bytes(key).unwrap();

    use std::fs::File;
    use std::io::BufRead;
    use std::path::Path;

    let target_path = Path::new("./inputs/set1/7.txt");
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

    let plaintext = openssl::symm::decrypt(
        openssl::symm::Cipher::aes_128_ecb(),
        &keybytes,
        None,
        &file_bytes,
    )
    .unwrap();
    println!(
        "Plaintext: {}",
        conversions::bytes_to_str(&plaintext).unwrap()
    );

    Ok(())
}

#[test]
fn challenge_8() -> Result<(), &'static str> {
    use std::fs::File;
    use std::io::BufRead;
    use std::path::Path;

    let target_path = Path::new("./inputs/set1/8.txt");
    let _display = target_path.display();
    let file = match File::open(target_path) {
        Err(_why) => {
            panic!("Could not open file");
        }
        Ok(file) => file,
    };

    let bufreader = std::io::BufReader::new(file);

    let mut file_bytes: Vec<Vec<u8>> = vec![];

    for line in bufreader.lines() {
        match line {
            Ok(s) => match conversions::read_hexstr_as_bytes(s.as_str()) {
                Ok(bytes) => {
                    file_bytes.push(bytes);
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

    // Detect aes128ecb
    // Same 16B plaintext will result in same 16B ciphertext
    // Iterate over 16B blocks and check for equality?
    let mut equality_count: Vec<usize> = vec![];
    for entry in file_bytes {
        let mut block_equality_count = 0;

        for i in 0..entry.len() / 16 {
            let block_start = i * 16;
            let block_end = i * 16 + 16;
            let bytes = &entry[block_start..block_end];

            for j in i + 1..entry.len() / 16 {
                let right_block_start = j * 16;
                let right_block_end = j * 16 + 16;
                let right_bytes = &entry[right_block_start..right_block_end];

                if bytes == right_bytes {
                    block_equality_count += 1;
                }
            }
        }

        equality_count.push(block_equality_count);
    }

    let mut max_dups = 0;
    let mut max_idx = 0;
    for (i, dup_count) in equality_count.iter().enumerate() {
        if *dup_count > max_dups {
            max_dups = *dup_count;
            max_idx = i;
        }
    }
    println!(
        "Found possible ecb in entry {} with {} duplicate blocks",
        max_idx, max_dups
    );

    Ok(())
}
