use std::str::FromStr;
use ark_bn254::Fr as Scalar;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use sha3::{Digest, Keccak256};

fn main() {
    let ctx = "LetsVerify".as_bytes();
    let m0 = Scalar::from_str("48305238028827234457057068308976830949311451167141786071899284143701496669988").unwrap();
    let m1 = Scalar::from_str("30362564611297414121344052595118041020684015714278959822893592029797294529055").unwrap();
    let m2 = Scalar::from_str("89017634352366059964332753369766654038457760534865200995547152036320389318152").unwrap();
    let m3 = Scalar::from_str("89017634352366059964332753369766654038457760534865200995547152036320389318152").unwrap();

    let mut hasher = Keccak256::new();
    let mut payload = Vec::new();
    
    let mut ctx_bytes = [0u8; 32];
    let len = ctx.len().min(32);
    ctx_bytes[..len].copy_from_slice(&ctx[..len]);
    payload.extend_from_slice(&ctx_bytes);

    for m in &[m0, m1, m2, m3] {
        let m_bytes = m.into_bigint().to_bytes_be();
        let mut padded = [0u8; 32];
        let offset = 32 - m_bytes.len().min(32);
        padded[offset..].copy_from_slice(&m_bytes);
        payload.extend_from_slice(&padded);
    }
    
    hasher.update(&payload);
    let hash_result = hasher.finalize();
    println!("Payload Hex: {}", hex::encode(&payload));
    println!("Hash: {}", hex::encode(&hash_result));
    
    let c = Scalar::from_be_bytes_mod_order(&hash_result);
    // Print decimal representation
    println!("C: {}", c);
}