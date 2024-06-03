use std::collections::VecDeque;

use crate::conversions::base64_to_bytes;
use crate::utility;
use crate::xor::fixed_xor;

use rand::prelude::*;

pub fn generate_random_aeskey(key_len_bytes: usize) -> Result<Vec<u8>, &'static str> {
    let mut buf = vec![0; key_len_bytes];
    if (openssl::rand::rand_bytes(buf.as_mut_slice()).is_err()) {
        return Err("Could not generate random key bytes!");
    }
    return Ok(buf);
}

pub fn simple_ecb_encrypt(input: &[u8], key: &[u8]) -> Result<Vec<u8>, &'static str> {
    let ciphertext =
        openssl::symm::encrypt(openssl::symm::Cipher::aes_128_ecb(), key, None, input).unwrap();
    Ok(ciphertext)
}

pub fn simple_cbc_encrypt(input: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut plaintext = Vec::from(input);

    // Pad plaintext to make it an integer number of 16B blocks
    plaintext = utility::pkcs7_padding(&plaintext, 16).unwrap();
    println!("Plaintext len: {}", plaintext.len());
    println!("\tnum blocks:  {}", plaintext.len() / 16);
    println!("\tpaddingvalue: {}", plaintext[21]);

    let mut full_ciphertext: Vec<u8> = vec![];

    let mut iv_vec: Vec<u8> = Vec::from(iv);
    if (iv_vec.len() != 16) {
        return Err("simple_cbc_encrypt: IV must be 16B long!");
    }

    for i in 0..plaintext.len() / 16 {
        let block_input = fixed_xor(&plaintext[i * 16..(i + 1) * 16], &iv_vec[0..16]).unwrap();
        let block_ciphertext = openssl::symm::encrypt(
            openssl::symm::Cipher::aes_128_ecb(),
            key,
            None,
            &block_input,
        )
        .unwrap();
        println!("Block ciphertext len? {}", block_ciphertext.len());
        iv_vec = block_ciphertext.clone();
        full_ciphertext.extend(&block_ciphertext[0..16]);
    }

    Ok(full_ciphertext)
}

pub fn simple_cbc_decrypt(input: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, &'static str> {
    let ciphertext = Vec::from(input);

    let mut full_plaintext: Vec<u8> = vec![];

    let mut iv_vec: Vec<u8> = Vec::from(iv);
    if (iv_vec.len() != 16) {
        return Err("simple_cbc_decrypt: IV must be 16B long!");
    }

    // For each block...
    for i in 0..ciphertext.len() / 16 {
        let block_input = &ciphertext[i * 16..(i + 1) * 16];

        // Run the ciphertext through the core...
        let mut crypter = openssl::symm::Crypter::new(
            openssl::symm::Cipher::aes_128_ecb(),
            openssl::symm::Mode::Decrypt,
            key,
            None,
        )
        .unwrap();
        crypter.pad(false);
        let mut block_output = vec![0u8; 32];
        let count = crypter
            .update(block_input, block_output.as_mut_slice())
            .unwrap();
        // println!("\tCount: {}", count); // No need to print the count out most of the time.

        // XOR the result with the current IV
        let block_plaintext = fixed_xor(&block_output[0..16], &iv_vec[0..16]).unwrap();
        full_plaintext.extend(&block_plaintext);

        // Update the IV with the previous ciphertext block
        iv_vec = Vec::from(block_input);
    }

    Ok(full_plaintext)
}

pub fn encryption_oracle(input: &[u8]) -> Result<Vec<u8>, &'static str> {
    let random_key = generate_random_aeskey(16).unwrap();
    let random_iv = generate_random_aeskey(16).unwrap();

    let num_prepend: u8 = (rand::random::<u8>() % 6) + 5; // Uniform over 5-10
    let num_append: u8 = (rand::random::<u8>() % 6) + 5; // Uniform over 5-10
    let prepend_bytes = generate_random_aeskey(num_prepend as usize).unwrap();
    let append_bytes = generate_random_aeskey(num_append as usize).unwrap();

    let mut input_vecdeque = VecDeque::from(Vec::from(input));
    for byte in prepend_bytes {
        input_vecdeque.push_front(byte);
    }
    for byte in append_bytes {
        input_vecdeque.push_back(byte);
    }
    let input_vec = Vec::from(input_vecdeque);

    let mut output_bytes: Vec<u8> = Vec::new();
    match rand::random::<u8>() % 2 {
        0 => {
            println!("Oracle chose cbc");
            output_bytes = crate::block_ciphers::simple_cbc_encrypt(
                input_vec.as_slice(),
                random_key.as_slice(),
                random_iv.as_slice(),
            )
            .unwrap()
        }
        1 => {
            println!("Oracle chose ecb");
            output_bytes = crate::block_ciphers::simple_ecb_encrypt(
                input_vec.as_slice(),
                random_key.as_slice(),
            )
            .unwrap()
        }
        _ => return Err("encryption_oracle: Broke math! (% 2)"),
    }

    Ok(output_bytes)
}

pub fn stable_ecb_oracle(input: &[u8]) -> Result<Vec<u8>, &'static str> {
    let random_key = Vec::from([
        48, 95, 77, 88, 214, 163, 80, 78, 205, 3, 202, 129, 233, 242, 221, 162,
    ]);

    let unknown_string = base64_to_bytes(String::from("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")).unwrap();
    let mut input_vec = Vec::from(input);
    input_vec.extend_from_slice(&unknown_string);

    let mut output_bytes: Vec<u8> = Vec::new();
    output_bytes =
        crate::block_ciphers::simple_ecb_encrypt(input_vec.as_slice(), random_key.as_slice())
            .unwrap();

    Ok(output_bytes)
}

#[derive(Debug)]
pub enum CRYPTOTYPE {
    ECB,
    CBC,
}

fn find_repeated_blocks(ciphertext: &Vec<u8>, blocklen: usize) -> bool {
    let num_blocks = ciphertext.len() / blocklen;
    dbg!(num_blocks);

    for i in 0..num_blocks {
        for j in i + 1..num_blocks {
            let l_idx = i * blocklen;
            let r_idx = j * blocklen;
            println!("Comparing blocks {} and {}", i, j);
            print!("\tLeft:  ");
            for byte in ciphertext[l_idx..l_idx + 16].iter() {
                print!("{:02x} ", *byte);
            }
            print!("\tRight: ");
            for byte in ciphertext[r_idx..r_idx + 16].iter() {
                print!("{:02x} ", *byte);
            }
            if (ciphertext[l_idx..l_idx + 16] == ciphertext[r_idx..r_idx + 16]) {
                println!("\tIdentical");
                return true;
            }
            println!("\tNot identical");
        }
    }

    false
}

pub fn ecb_detector(
    encrypter: fn(&[u8]) -> Result<Vec<u8>, &'static str>,
) -> Result<CRYPTOTYPE, &'static str> {
    // Generate input long enough to have at least two full cipher blocks
    let blocklen: usize = 16;
    let chosen_plaintext = "X".repeat(4 * blocklen);
    let oracle_ciphertext = encrypter(chosen_plaintext.as_bytes()).unwrap();

    if (find_repeated_blocks(&oracle_ciphertext, blocklen)) {
        Ok(CRYPTOTYPE::ECB)
    } else {
        Ok(CRYPTOTYPE::CBC)
    }
}

#[cfg(test)]
mod tests {
    use openssl::symm::encrypt;

    #[test]
    pub fn simple_cbc_test() -> Result<(), &'static str> {
        use super::*;
        use crate::conversions;
        let key = b"YELLOW SUBMARINE";
        let iv = &[0u8; 16];

        let input = b"Hello from cbc land!";

        let output = simple_cbc_encrypt(input, key, iv).unwrap();

        let recovered_plaintext =
            openssl::symm::decrypt(openssl::symm::Cipher::aes_128_cbc(), key, Some(iv), &output)
                .unwrap();
        println!(
            "Recovered plaintext: {}",
            conversions::bytes_to_str(&recovered_plaintext).unwrap()
        );

        let second_recovered_plaintext = simple_cbc_decrypt(&output, key, iv).unwrap();
        println!(
            "Second recovered plaintext: {}",
            conversions::bytes_to_str(&second_recovered_plaintext).unwrap()
        );
        Ok(())
    }

    #[test]
    pub fn simple_keygen_test() -> Result<(), &'static str> {
        use super::*;
        let rand_bytes = match generate_random_aeskey(16) {
            Ok(r) => r,
            Err(e) => return Err(e),
        };
        dbg!(&rand_bytes);
        assert_eq!(rand_bytes.len(), 16usize);
        Ok(())
    }

    #[test]
    pub fn encryption_oracle_test() -> Result<(), &'static str> {
        use super::*;

        let input = b"Hello from cbc land!";
        let _random_data = encryption_oracle(input);

        Ok(())
    }

    #[test]
    pub fn stable_oracle_test() -> Result<(), &'static str> {
        use super::*;

        let input = b"Hello from ecb land!";
        let _random_data = stable_ecb_oracle(input);

        Ok(())
    }
}
