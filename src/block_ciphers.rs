use crate::utility;
use crate::xor::fixed_xor;

pub fn simple_ecb_encrypt(input: &[u8], key: &[u8]) -> Result<Vec<u8>, &'static str> {
    let ciphertext =
        openssl::symm::encrypt(openssl::symm::Cipher::aes_128_ecb(), key, None, input).unwrap();
    Ok(ciphertext)
}

pub fn simple_cbc_encrypt(
    input: &[u8],
    key: &[u8],
    iv: &[u8; 16],
) -> Result<Vec<u8>, &'static str> {
    let mut plaintext = Vec::from(input);

    // Pad plaintext to make it an integer number of 16B blocks
    plaintext = utility::pkcs7_padding(&plaintext, 16).unwrap();
    println!("Plaintext len: {}", plaintext.len());
    println!("\tnum blocks:  {}", plaintext.len() / 16);
    println!("\tpaddingvalue: {}", plaintext[21]);

    let mut full_ciphertext: Vec<u8> = vec![];

    let mut iv_vec: Vec<u8> = Vec::from(*iv);

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

pub fn simple_cbc_decrypt(
    input: &[u8],
    key: &[u8],
    iv: &[u8; 16],
) -> Result<Vec<u8>, &'static str> {
    let ciphertext = Vec::from(input);

    let mut full_plaintext: Vec<u8> = vec![];

    let mut iv_vec: Vec<u8> = Vec::from(*iv);
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
        println!("\tCount: {}", count);

        // XOR the result with the current IV
        let block_plaintext = fixed_xor(&block_output[0..16], &iv_vec[0..16]).unwrap();
        full_plaintext.extend(&block_plaintext);

        // Update the IV with the previous ciphertext block
        iv_vec = Vec::from(block_input);
    }

    Ok(full_plaintext)
}

#[cfg(test)]
mod tests {

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
}
