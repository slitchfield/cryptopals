use std::{num::ParseIntError};

pub fn read_hexstr_as_bytes(inputstr: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..inputstr.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&inputstr[i..i+2], 16))
        .collect()
}

pub fn bytes_to_base64(bytes: Vec<u8>) -> Result<String, &'static str> {
    let b64 = base64::encode(bytes);
    Ok(b64)
}

pub fn base64_to_bytes(input: String) -> Result<Vec<u8>, &'static str> {
    match base64::decode(input) {
        Ok(res) => return Ok(res),
        Err(_) => return Err("Could not decode!"),
    };
}

pub fn bytes_to_str(bytes: &Vec<u8>) -> Result<String, &'static str> {
    let char_str: String = bytes.iter().map(|c| *c as char).collect();
    Ok(char_str)
}

pub fn str_to_bytes(input: &str) -> Result<Vec<u8>, &'static str> {
    let bytevec: Vec<u8> = input.chars().map(|c| c as u8).collect();
    Ok(bytevec)
}