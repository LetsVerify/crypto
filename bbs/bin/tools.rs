use sha3::{Digest, Keccak256};

pub fn main() {
    let mut hasher = Keccak256::new();
    let m1 = String::from("Age=18");
    let m2 = String::from("Nationality=US");
    let m3 = String::from("Verified=true");
    let m4 = String::from("Empty");

    hasher.update(m1.as_bytes());
    println!("Hash of Age=18: 0x{}", hex::encode(hasher.finalize_reset()));
    
    hasher.update(m2.as_bytes());
    println!("Hash of Nationality=US: 0x{}", hex::encode(hasher.finalize_reset()));

    hasher.update(m3.as_bytes());
    println!("Hash of Verified=true: 0x{}", hex::encode(hasher.finalize_reset()));

    hasher.update(m4.as_bytes());
    println!("Hash of Empty: 0x{}", hex::encode(hasher.finalize_reset()));
}