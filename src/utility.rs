pub fn hamming_distance_byte(left: u8, right: u8) -> usize {
    let differences = left ^ right;
    differences.count_ones() as usize
}

pub fn hamming_distance<'a, T: IntoIterator<Item = &'a u8>>(
    left: T,
    right: T,
) -> Result<usize, &'static str> {
    let mut distance = 0;

    for (lc, rc) in left.into_iter().zip(right.into_iter()) {
        distance += hamming_distance_byte(*lc, *rc);
    }

    Ok(distance)
}

use std::collections::HashMap;
pub fn gen_english_map() -> HashMap<u8, f32> {
    HashMap::from([
        (b'E', 0.111607),
        (b'A', 0.084966),
        (b'R', 0.075809),
        (b'I', 0.075448),
        (b'O', 0.071635),
        (b'T', 0.069509),
        (b'N', 0.066544),
        (b'S', 0.057351),
        (b'L', 0.054893),
        (b'C', 0.045388),
        (b'U', 0.036308),
        (b'D', 0.033844),
        (b'P', 0.031671),
        (b'M', 0.030129),
        (b'H', 0.030034),
        (b'G', 0.024705),
        (b'B', 0.020720),
        (b'F', 0.018121),
        (b'Y', 0.017779),
        (b'W', 0.012899),
        (b'K', 0.011016),
        (b'V', 0.010074),
        (b'X', 0.002902),
        (b'Z', 0.002722),
        (b'J', 0.001965),
        (b'Q', 0.001962),
        (b'*', 0.0),
    ])
}

pub fn count_elem(input: &[u8], elem: u8) -> u32 {
    let mut count = 0;
    let upper_elem = elem.to_ascii_uppercase();

    for item in input.iter() {
        // item is ascii, potentially lower case
        let upper_item = (*item).to_ascii_uppercase();
        if upper_item == upper_elem {
            count += 1;
        } else if elem == b'*' {
            if !(*item).is_ascii_alphabetic() && (*item != b' ') {
                count += 1;
            } else if (*item).is_ascii_control() {
                //count = count + 10;
                count += 100;
            }
        }
    }

    count
}

use std::collections::HashSet;
pub fn euclidean_freq_distance(left: &HashMap<u8, f32>, right: &HashMap<u8, f32>) -> f32 {
    let left_keys: HashSet<u8> = left.keys().cloned().collect();
    let right_keys: HashSet<u8> = right.keys().cloned().collect();

    if left_keys != right_keys {
        println!("Keys don't match!");
        return 0.0;
    }

    let mut accum = 0.0;
    for (key, left_value) in left.iter() {
        let right_value = right.get(key).unwrap();
        accum += (left_value - right_value) * (left_value - right_value);
    }

    accum
}

pub fn count_freq(input: &Vec<u8>) -> HashMap<u8, f32> {
    let mut output: HashMap<u8, f32> = HashMap::from([
        (b'E', 0.),
        (b'A', 0.),
        (b'R', 0.),
        (b'I', 0.),
        (b'O', 0.),
        (b'T', 0.),
        (b'N', 0.),
        (b'S', 0.),
        (b'L', 0.),
        (b'C', 0.),
        (b'U', 0.),
        (b'D', 0.),
        (b'P', 0.),
        (b'M', 0.),
        (b'H', 0.),
        (b'G', 0.),
        (b'B', 0.),
        (b'F', 0.),
        (b'Y', 0.),
        (b'W', 0.),
        (b'K', 0.),
        (b'V', 0.),
        (b'X', 0.),
        (b'Z', 0.),
        (b'J', 0.),
        (b'Q', 0.),
        (b'*', 0.),
    ]);

    let length = input.len() as f32;

    for (letter, val) in output.iter_mut() {
        let new_val = (count_elem(input, *letter) as f32) / length;
        *val = new_val;
    }

    output
}

#[allow(dead_code)]
pub struct EnglishScore {
    input_bytes: Vec<u8>,
    input_freq: HashMap<u8, f32>,
    ideal_freqs: HashMap<u8, f32>,
    pub score: f32,
}

#[allow(dead_code)]
impl EnglishScore {
    pub fn from(input: &Vec<u8>) -> Self {
        EnglishScore {
            input_bytes: input.clone(),
            input_freq: count_freq(input),
            ideal_freqs: gen_english_map(),
            score: euclidean_freq_distance(&count_freq(input), &gen_english_map()),
        }
    }
}

pub fn pkcs7_padding(input: &[u8], block_size: usize) -> Result<Vec<u8>, &'static str> {
    if block_size > 256 {
        return Err("pkcs7 only valid for block sizes <= 256");
    }

    let mut ret_vec: Vec<u8> = Vec::from(input);

    let cur_len = input.len();
    let padding_size = block_size - (cur_len % block_size);
    let mut padding_bytes: Vec<u8> = (0..padding_size)
        .into_iter()
        .map(|_| padding_size as u8)
        .collect();
    ret_vec.append(&mut padding_bytes);

    Ok(ret_vec)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_count_elem() -> Result<(), &'static str> {
        let haystack: Vec<u8> = String::from("ASDFasdf").as_bytes().to_vec();
        let result = count_elem(&haystack, b'a');
        assert_eq!(result, 2);
        let result2 = count_elem(&haystack, b'S');
        assert_eq!(result2, 2);
        let result3 = count_elem(&haystack, b'Q');
        assert_eq!(result3, 0);
        Ok(())
    }

    #[test]
    fn test_count_freq() -> Result<(), &'static str> {
        let input1: Vec<u8> = String::from("AAAAAAA").as_bytes().to_vec();
        let result1 = count_freq(&input1);
        assert_eq!(result1.get(&(b'A')), Some(&1.0));
        let input1: Vec<u8> = String::from("AAAAAAABBBBBBB").as_bytes().to_vec();
        let result1 = count_freq(&input1);
        assert_eq!(result1.get(&(b'A')), Some(&0.5));
        let input1: Vec<u8> = String::from("AB|||").as_bytes().to_vec();
        let result1 = count_freq(&input1);
        assert_eq!(result1.get(&(b'A')), Some(&0.2));
        assert_eq!(result1.get(&(b'C')), Some(&0.0));
        Ok(())
    }

    #[test]
    fn test_euclidean_score() -> Result<(), &'static str> {
        let left: Vec<u8> = String::from("We hold these truths to be self-evident, that all men are created equal, that they are endowed by their Creator with certain unalienable Rights, that among these are Life, Liberty and the pursuit of Happiness.").as_bytes().to_vec();
        let left_freqs = count_freq(&left);
        let right_freqs = gen_english_map();
        let result = euclidean_freq_distance(&left_freqs, &right_freqs);
        assert!((result - 0.009184015) < 0.01);
        Ok(())
    }

    #[test]
    fn test_english_score() -> Result<(), &'static str> {
        let input: Vec<u8> = String::from("We hold these truths to be self-evident, that all men are created equal, that they are endowed by their Creator with certain unalienable Rights, that among these are Life, Liberty and the pursuit of Happiness.").as_bytes().to_vec();
        let object = EnglishScore::from(&input);
        println!("{}", object.score);
        assert!((object.score - 0.01) < 0.001);
        Ok(())
    }

    #[test]
    fn test_hamming_byte() -> Result<(), &'static str> {
        let left = 0xff;
        let right = 0x00;
        let distance = hamming_distance_byte(left, right);
        assert_eq!(distance, 8);

        let left = 0xff;
        let right = 0xaa;
        let distance = hamming_distance_byte(left, right);
        assert_eq!(distance, 4);

        let left = 0xaa;
        let right = 0xaa;
        let distance = hamming_distance_byte(left, right);
        assert_eq!(distance, 0);
        Ok(())
    }

    #[test]
    fn test_hamming_str() -> Result<(), &'static str> {
        use crate::conversions::str_to_bytes;

        let left = "this is a test";
        let left_bytes = str_to_bytes(left).unwrap();
        let right = "wokka wokka!!!";
        let right_bytes = str_to_bytes(right).unwrap();

        let distance_gen = hamming_distance(&left_bytes[..], &right_bytes[..]).unwrap();
        assert_eq!(distance_gen, 37);
        let distance_gen = hamming_distance(&left_bytes, &right_bytes).unwrap();
        assert_eq!(distance_gen, 37);

        Ok(())
    }

    #[test]
    fn test_pkcs7_padding() -> Result<(), &'static str> {
        let input = b"YELLOW SUBMARINE";
        let output = b"YELLOW SUBMARINE\x04\x04\x04\x04";

        let test_result = pkcs7_padding(input, 20).unwrap();
        assert_eq!(test_result, output);

        let output =
            b"YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10";

        let test_result = pkcs7_padding(input, 16).unwrap();
        assert_eq!(test_result, output);

        Ok(())
    }
}
