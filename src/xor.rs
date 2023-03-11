
pub fn fixed_xor(left: &Vec<u8>, right: &Vec<u8>) -> Result<Vec<u8>, &'static str> {

    if left.len() != right.len() {
        return Err("fixed_xor: vectors must be the same length");
    }

    Ok(
        (0..left.len())
            .map(|i| left[i] ^ right[i])
            .collect()
    )
}

pub fn repeating_key_xor(left: &Vec<u8>, right: &Vec<u8>) -> Result<Vec<u8>, &'static str> {

    let keymat = (0..left.len())
                                .map(|i| right[i % right.len()])
                                .collect();
    fixed_xor(left, &keymat)
}