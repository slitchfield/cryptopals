use crate::utility;
use crate::xor;

pub fn fixed_xor(left: &Vec<u8>, right: &Vec<u8>) -> Result<Vec<u8>, &'static str> {
    if left.len() != right.len() {
        return Err("fixed_xor: vectors must be the same length");
    }

    Ok((0..left.len()).map(|i| left[i] ^ right[i]).collect())
}

pub fn repeating_key_xor(left: &Vec<u8>, right: &Vec<u8>) -> Result<Vec<u8>, &'static str> {
    let keymat = (0..left.len()).map(|i| right[i % right.len()]).collect();
    fixed_xor(left, &keymat)
}

pub fn recover_xor_key(input: &Vec<u8>) -> Result<(Vec<u8>, char, f32), &'static str> {
    let mut cur_score = f32::INFINITY;
    let mut cur_key = 'A';
    let mut cur_plaintext: Vec<u8> = Vec::new();

    for key in (0 as char)..(0xff as char) {
        //println!("Testing key {}", key as char);
        let keymat = (0..input.len()).map(|_| key as u8).collect();
        let plaintext = xor::fixed_xor(input, &keymat)?;
        //println!("\tPlaintext: \"{}\"", String::from_utf8_lossy(&plaintext.clone()));
        let score_object = utility::EnglishScore::from(&plaintext);
        //println!("\tScore: {}", score_object.score);
        if score_object.score < cur_score {
            //println!("\tFound new best score! Prev: {}, New: {}", cur_score, score_object.score);
            cur_score = score_object.score;
            cur_key = key;
            cur_plaintext = plaintext;
        }
    }
    Ok((cur_plaintext, cur_key, cur_score))
}

pub fn recover_key_len(
    input: &[u8],
    min_len: usize,
    max_len: usize,
) -> Result<usize, &'static str> {
    #[derive(Debug)]
    struct Result {
        //distance: f32,
        length: usize,
        score: f32,
    }

    let mut result_vec: Vec<Result> = vec![];

    for key_len in min_len..max_len {
        let block1 = &input[0..key_len];
        let block2 = &input[key_len..2 * key_len];
        let block3 = &input[2 * key_len..3 * key_len];
        let block4 = &input[3 * key_len..4 * key_len];
        let distances: Vec<usize> = vec![
            utility::hamming_distance(block1, block2).unwrap(),
            utility::hamming_distance(block1, block3).unwrap(),
            utility::hamming_distance(block1, block4).unwrap(),
            utility::hamming_distance(block2, block3).unwrap(),
            utility::hamming_distance(block2, block4).unwrap(),
            utility::hamming_distance(block3, block4).unwrap(),
        ];
        let test_distance = distances.iter().sum::<usize>() as f32 / 6.0;
        let score: f32 = test_distance / key_len as f32;

        let res = Result {
            length: key_len,
            score,
        };
        result_vec.push(res);
    }

    use std::cmp::Ordering::Equal;
    result_vec.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(Equal));
    result_vec.reverse();

    Ok(result_vec[0].length)
}
