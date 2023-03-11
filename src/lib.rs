
use base64;

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

//use log::debug;
pub fn recover_xor_key(input: &Vec<u8>) -> Result<(Vec<u8>, char, f32), &'static str> {
   
    let mut cur_score = f32::INFINITY;
    let mut cur_key = 'A' as char;
    let mut cur_plaintext: Vec<u8> = Vec::new();

    for key in (0 as char)..(0xff as char) {
        //println!("Testing key {}", key as char);
        let keymat = (0..input.len()).map(|_| key as u8).collect();
        let plaintext = xor::fixed_xor(input, &keymat)?;
        //println!("\tPlaintext: \"{}\"", String::from_utf8_lossy(&plaintext.clone()));
        let score_object = EnglishScore::from(&plaintext);
        //println!("\tScore: {}", score_object.score);
        if score_object.score < cur_score {
            //println!("\tFound new best score! Prev: {}, New: {}", cur_score, score_object.score);
            cur_score = score_object.score;
            cur_key = key;
            cur_plaintext = plaintext;
        }
    }
    Ok( (cur_plaintext, cur_key, cur_score) )
}

pub fn recover_key_len(input: &Vec<u8>, min_len: usize, max_len: usize) -> Result<usize, &'static str> {

    #[derive(Debug)]
    struct Result {
        //distance: f32,
        length: usize,
        score: f32,
    }

    let mut result_vec: Vec<Result> = vec![];

    for key_len in min_len..max_len {
        let block1 = &input[0..key_len];
        let block2 = &input[key_len..2*key_len];
        let block3 = &input[2*key_len..3*key_len];
        let block4 = &input[3*key_len..4*key_len];
        let mut distances: Vec<usize> = vec![];
        distances.push(hamming_distance(block1, block2).unwrap());
        distances.push(hamming_distance(block1, block3).unwrap());
        distances.push(hamming_distance(block1, block4).unwrap());
        distances.push(hamming_distance(block2, block3).unwrap());
        distances.push(hamming_distance(block2, block4).unwrap());
        distances.push(hamming_distance(block3, block4).unwrap());
        let test_distance = distances.iter().map(|dist| *dist).sum::<usize>() as f32 / 6.0;
        let score: f32 = test_distance / key_len as f32;

        let res = Result{ length: key_len, score: score};
        result_vec.push(res);
    }
    
    use std::cmp::Ordering::Equal;
    result_vec.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(Equal));
    result_vec.reverse();

    Ok(result_vec[0].length)

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

    #[test]
    fn challenge_1() -> Result<(), &'static str>{
        let hex_str = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        let base64_str = String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");

        let bytes: Vec<u8> = match conversions::read_hexstr_as_bytes(hex_str.as_ref()) {
            Ok(v) => v,
            Err(_) => { assert!(false); return Err("") },
        };

        assert_eq!(conversions::bytes_to_base64(bytes)?, base64_str);

        Ok(())
    }

    #[test]
    fn challenge_2() -> Result<(), &'static str> {

        let buf1 = match conversions::read_hexstr_as_bytes(String::from("1c0111001f010100061a024b53535009181c").as_ref()) {
            Ok(v) => v,
            Err(_) => { assert!(false); return Err("") }
        };
        
        let buf2 = match conversions::read_hexstr_as_bytes(String::from("686974207468652062756c6c277320657965").as_ref()) {
            Ok(v) => v,
            Err(_) => { assert!(false); return Err("") }
        };

        let _ = xor::fixed_xor(&buf1, &buf2)?;
        
        Ok(())
    }

    #[test]
    fn challenge_3() -> Result<(), &'static str> {
        let buf = match conversions::read_hexstr_as_bytes(String::from("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").as_ref()) {
            Ok(v) => v,
            Err(_) => { assert!(false); return Err("") }
        };

        let (plaintext, key, score) = recover_xor_key(&buf)?;
        //println!("Final Plaintext: {}", String::from_utf8(plaintext.clone()).unwrap());
        println!("Final Plaintext: {}", conversions::bytes_to_str(&plaintext).unwrap());
        println!("Final Key:       {}", key as char);
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

        let file = match File::open(&target_path) {
            Err(_why) => { assert!(false); return Err("Could not open file"); },
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
                            let (plaintext, key, score) = recover_xor_key(&bytes)?;
                            //let plainstr = bytes_to_str(plaintext.clone()).unwrap();
                            //println!("\tFinal Plaintext: {}", plainstr);
                            //println!("\tFinal Key:       {}", key as char);
                            //println!("\tFinal Score:     {}", score);
                            let res: Result = Result { input: bytes, plaintext, key, score };
                            res_vec.push(res);
                        },
                        Err(_err) => {
                            println!("ParseIntErr!");
                        }
                    }
                },
                Err(_err) => { println!("Line read error?") }
            }
        }
        use std::cmp::Ordering::Equal;
        res_vec.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(Equal));
        res_vec.reverse();

        for i in 0..1 { 
            println!("Top {} Result:", i + 1);
            let cipherstr = String::from_utf8_lossy(&res_vec[i].input);
            println!("\tCipherText:      {}", cipherstr);
            let plainstr = String::from_utf8_lossy(&res_vec[i].plaintext);
            println!("\tFinal Plaintext: {}", plainstr);
            println!("\tFinal Key:       {}", res_vec[i].key as char);
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
        let file = match File::open(&target_path) {
            Err(_why) => { assert!(false); return Err("Could not open file"); },
            Ok(file) => file,
        };

        let bufreader = std::io::BufReader::new(file);

        let mut file_bytes: Vec<u8> = vec![];

        for line in bufreader.lines() {
            match line {
                Ok(s) => { 
                    match conversions::base64_to_bytes(s) {
                        Ok(mut bytes) => {
                            file_bytes.append(&mut bytes);
                        },
                        Err(_err) => {
                            println!("ParseIntErr!");
                        }
                    }
                },
                Err(_err) => { println!("Line read error?") }
            }
        }

        let key_len = recover_key_len(&file_bytes, 2, 40).unwrap();

        // Break input into every key_len bytes
        let mut blocks: Vec<Vec<u8>> = vec![];
        let mut key_chars:Vec<u8> = vec![];

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

            let stride: Vec<u8> = block_iter.step_by(key_len).map(|c| *c).collect();

            let (_, key_char, _) = recover_xor_key(&stride).unwrap();
            key_chars.push(key_char as u8);

        }
        println!("Key found: {}", conversions::bytes_to_str(&key_chars).unwrap());

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
        let file = match File::open(&target_path) {
            Err(_why) => { assert!(false); return Err("Could not open file"); },
            Ok(file) => file,
        };

        let bufreader = std::io::BufReader::new(file);

        let mut file_bytes: Vec<u8> = vec![];

        for line in bufreader.lines() {
            match line {
                Ok(s) => { 
                    match conversions::base64_to_bytes(s) {
                        Ok(mut bytes) => {
                            file_bytes.append(&mut bytes);
                        },
                        Err(_err) => {
                            println!("ParseIntErr!");
                        }
                    }
                },
                Err(_err) => { println!("Line read error?") }
            }
        }

        let plaintext = decrypt(openssl::symm::Cipher::aes_128_ecb(),
                                         &keybytes,
                                         None,
                                         &file_bytes).unwrap();
        println!("Plaintext: {}", conversions::bytes_to_str(&plaintext).unwrap());

        Ok(())
    }

    #[test] 
    fn challenge_8() -> Result<(), &'static str> {

        use std::fs::File;
        use std::io::BufRead;
        use std::path::Path;
       
        let target_path = Path::new("./inputs/set1/8.txt");
        let _display = target_path.display();
        let file = match File::open(&target_path) {
            Err(_why) => { assert!(false); return Err("Could not open file"); },
            Ok(file) => file,
        };

        let bufreader = std::io::BufReader::new(file);

        let mut file_bytes: Vec<Vec<u8>> = vec![];

        for line in bufreader.lines() {
            match line {
                Ok(s) => { 
                    match conversions::read_hexstr_as_bytes(s.as_str()) {
                        Ok(bytes) => {
                            file_bytes.push(bytes);
                        },
                        Err(_err) => {
                            println!("ParseIntErr!");
                        }
                    }
                },
                Err(_err) => { println!("Line read error?") }
            }
        }

        // Detect aes128ecb
        // Same 16B plaintext will result in same 16B ciphertext
        // Iterate over 16B blocks and check for equality?
        let mut equality_count: Vec<usize> = vec![];
        for entry in file_bytes {
            
            let mut block_equality_count = 0;
           
            for i in 0..entry.len() / 16 {
                let block_start = i*16;
                let block_end = i*16 + 16;
                let bytes = &entry[block_start..block_end];

                for j in i+1..entry.len() / 16 {
                    let right_block_start = j*16;
                    let right_block_end = j*16 + 16;
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
                max_idx  = i;
            }
        }
        println!("Found possible ecb in entry {} with {} duplicate blocks", max_idx, max_dups);

        Ok(())
    }
}
