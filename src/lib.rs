
pub mod conversions;
pub mod xor;

pub fn hamming_distance_byte(left: u8, right: u8) -> usize {
    let differences = left ^ right;
    let distance = differences.count_ones() as usize;
    return distance
    
}

pub fn hamming_distance<'a, T: IntoIterator<Item = &'a u8>> (left: T, right: T) -> Result<usize, &'static str> {
    let mut distance = 0;

    for (lc, rc) in left.into_iter().zip(right.into_iter()) {
        distance += hamming_distance_byte(*lc, *rc);
    }

    Ok(distance)
}

pub fn hamming_distance_vec(left: &Vec<u8>, right: &Vec<u8>) -> Result<usize, &'static str> {
    let mut distance = 0;

    if left.len() != right.len() {
        return Err("Hamming distance: inputs should be the same size.");
    }

    for (i, lc) in left.iter().enumerate() {
        let rc = right[i];
        distance += hamming_distance_byte(*lc, rc);
    }

    Ok(distance)
}

use std::collections::HashMap;
pub fn gen_english_map() -> HashMap<u8, f32> {
    let english_freqs: HashMap<u8, f32> = HashMap::from([
        ('E' as u8, 0.111607),
        ('A' as u8, 0.084966),
        ('R' as u8, 0.075809),
        ('I' as u8, 0.075448),
        ('O' as u8, 0.071635),
        ('T' as u8, 0.069509),
        ('N' as u8, 0.066544),
        ('S' as u8, 0.057351),
        ('L' as u8, 0.054893),
        ('C' as u8, 0.045388),
        ('U' as u8, 0.036308),
        ('D' as u8, 0.033844),
        ('P' as u8, 0.031671),
        ('M' as u8, 0.030129),
        ('H' as u8, 0.030034),
        ('G' as u8, 0.024705),
        ('B' as u8, 0.020720),
        ('F' as u8, 0.018121),
        ('Y' as u8, 0.017779),
        ('W' as u8, 0.012899),
        ('K' as u8, 0.011016),
        ('V' as u8, 0.010074),
        ('X' as u8, 0.002902),
        ('Z' as u8, 0.002722),
        ('J' as u8, 0.001965),
        ('Q' as u8, 0.001962),
        ('*' as u8, 0.0),

    ]);
    return english_freqs
}

pub fn count_elem(input: &Vec<u8>, elem: u8) -> u32 {
    let mut count = 0;
    let upper_elem = elem.to_ascii_uppercase();
        
    for item in input.iter() {
        // item is ascii, potentially lower case
        let upper_item = (*item).to_ascii_uppercase();
        if upper_item == upper_elem {
            count = count + 1;
        }
        else if elem == '*' as u8 {
            if !(*item).is_ascii_alphabetic() && (*item != ' ' as u8) {
                count = count + 1;
            } else if (*item).is_ascii_control() {
                //count = count + 10;
                count = count + 100;
            }
        }
    }

    return count; 
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
    
    return accum;    
}

pub fn count_freq(input: &Vec<u8>) -> HashMap<u8, f32> {

    let mut output: HashMap<u8, f32> = HashMap::from([
        ('E' as u8, 0.),
        ('A' as u8, 0.),
        ('R' as u8, 0.),
        ('I' as u8, 0.),
        ('O' as u8, 0.),
        ('T' as u8, 0.),
        ('N' as u8, 0.),
        ('S' as u8, 0.),
        ('L' as u8, 0.),
        ('C' as u8, 0.),
        ('U' as u8, 0.),
        ('D' as u8, 0.),
        ('P' as u8, 0.),
        ('M' as u8, 0.),
        ('H' as u8, 0.),
        ('G' as u8, 0.),
        ('B' as u8, 0.),
        ('F' as u8, 0.),
        ('Y' as u8, 0.),
        ('W' as u8, 0.),
        ('K' as u8, 0.),
        ('V' as u8, 0.),
        ('X' as u8, 0.),
        ('Z' as u8, 0.),
        ('J' as u8, 0.),
        ('Q' as u8, 0.),
        ('*' as u8, 0.),
    ]);

    let length = input.len() as f32;

    for (letter, val) in output.iter_mut() {
        let new_val = (count_elem(input, *letter) as f32) / length;
        *val = new_val;
    }

    return output
}

#[allow(dead_code)]
struct EnglishScore {
    input_bytes: Vec<u8>,
    input_freq: HashMap<u8, f32>,
    ideal_freqs: HashMap<u8, f32>,
    score: f32,
}

#[allow(dead_code)]
impl EnglishScore {

    fn from(input: &Vec<u8>) -> Self {
        EnglishScore {
            input_bytes: input.clone(),
            input_freq: count_freq(input),
            ideal_freqs: gen_english_map(),
            score: euclidean_freq_distance(&count_freq(input), &gen_english_map()),
        }
    }
}

#[cfg(test)]
mod tests {
    use openssl::symm::decrypt;

    use super::*;

    #[test]
    fn test_count_elem() -> Result<(), &'static str>{
        let haystack: Vec<u8> = String::from("ASDFasdf").as_bytes().to_vec();
        let result = count_elem(&haystack, 'a' as u8);
        assert_eq!(result, 2);
        let result2 = count_elem(&haystack, 'S' as u8);
        assert_eq!(result2, 2);
        let result3 = count_elem(&haystack, 'Q' as u8);
        assert_eq!(result3, 0);
        Ok(())
    }
    
    #[test]
    fn test_count_freq() -> Result<(), &'static str>{
        let input1: Vec<u8> = String::from("AAAAAAA").as_bytes().to_vec();
        let result1 = count_freq(&input1);
        assert_eq!(result1.get(&('A' as u8)), Some(&1.0));
        let input1: Vec<u8> = String::from("AAAAAAABBBBBBB").as_bytes().to_vec();
        let result1 = count_freq(&input1);
        assert_eq!(result1.get(&('A' as u8)), Some(&0.5));
        let input1: Vec<u8> = String::from("AB|||").as_bytes().to_vec();
        let result1 = count_freq(&input1);
        assert_eq!(result1.get(&('A' as u8)), Some(&0.2));
        assert_eq!(result1.get(&('C' as u8)), Some(&0.0));
        Ok(())
    }

    #[test]
    fn test_euclidean_score() -> Result<(), &'static str>{
        let left: Vec<u8> = String::from("We hold these truths to be self-evident, that all men are created equal, that they are endowed by their Creator with certain unalienable Rights, that among these are Life, Liberty and the pursuit of Happiness.").as_bytes().to_vec();
        let left_freqs = count_freq(&left);
        let right_freqs = gen_english_map();
        let result = euclidean_freq_distance(&left_freqs, &right_freqs);
        assert!((result - 0.009184015) < 0.01);
        Ok(())
    }

    #[test]
    fn test_english_score() -> Result<(), &'static str>{
        let input: Vec<u8> = String::from("We hold these truths to be self-evident, that all men are created equal, that they are endowed by their Creator with certain unalienable Rights, that among these are Life, Liberty and the pursuit of Happiness.").as_bytes().to_vec();
        let object = EnglishScore::from(&input);
        println!("{}", object.score);
        assert!((object.score - 0.01) < 0.001);
        Ok(())
    }

    #[test]
    fn test_hamming_byte() -> Result<(), &'static str> {
        let left = 0xff as u8;
        let right = 0x00 as u8; 
        let distance = hamming_distance_byte(left, right);
        assert_eq!(distance, 8);

        let left = 0xff as u8;
        let right = 0xaa as u8;
        let distance = hamming_distance_byte(left, right);
        assert_eq!(distance, 4);

        let left = 0xaa as u8;
        let right = 0xaa as u8;
        let distance = hamming_distance_byte(left, right);
        assert_eq!(distance, 0); 
        Ok(())
    }

    #[test]
    fn test_hamming_str() -> Result<(), &'static str> {
        
        let left = "this is a test";
        let left_bytes = conversions::str_to_bytes(left).unwrap();
        let right = "wokka wokka!!!";
        let right_bytes = conversions::str_to_bytes(right).unwrap();

        let distance_gen = hamming_distance(&left_bytes[..], &right_bytes[..]).unwrap();
        assert_eq!(distance_gen, 37);
        let distance_gen = hamming_distance(&left_bytes, &right_bytes).unwrap();
        assert_eq!(distance_gen, 37);

        Ok(())
    }

}
