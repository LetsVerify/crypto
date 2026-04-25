use ark_bn254::{Fr as Scalar, G1Affine as G1, G2Affine as G2};
use ark_ec::AffineRepr;
use bbs::structs::PublicKey;
use sha3::{Digest, Keccak256};
use ark_serialize::CanonicalSerialize;
use hex;

// #[test]
fn main() {
    let pk = PublicKey { X: G2::generator() };
    let disclosed = vec![Scalar::from(42u64)];
    let a_bar = G1::generator();
    let b_bar = G1::generator();
    let u = G1::generator();

    let mut hasher = Keccak256::new();
    let mut all_bytes = Vec::new();
    
    let ctx = b"BBS_PoK_1";
    all_bytes.extend_from_slice(ctx);

    let mut pk_bytes = Vec::new();
    pk.X.serialize_compressed(&mut pk_bytes).unwrap();
    all_bytes.extend_from_slice(&pk_bytes);

    for (i, m) in disclosed.iter().enumerate() {
        all_bytes.extend_from_slice(&(i as u64).to_be_bytes());
        let mut m_bytes = Vec::new();
        m.serialize_compressed(&mut m_bytes).unwrap();
        all_bytes.extend_from_slice(&m_bytes);
    }

    let mut a_bytes = Vec::new();
    a_bar.serialize_compressed(&mut a_bytes).unwrap();
    all_bytes.extend_from_slice(&a_bytes);

    let mut b_bytes = Vec::new();
    b_bar.serialize_compressed(&mut b_bytes).unwrap();
    all_bytes.extend_from_slice(&b_bytes);

    let mut u_bytes = Vec::new();
    u.serialize_compressed(&mut u_bytes).unwrap();
    all_bytes.extend_from_slice(&u_bytes);

    hasher.update(&all_bytes);
    let hash_result = hasher.finalize();

    println!("All bytes: 0x{}", hex::encode(&all_bytes));
    println!("Hash result: 0x{}", hex::encode(&hash_result));
    
    let hex_str = format!("0x{}", hex::encode(&all_bytes));
    println!("\nExecuting command: cast keccak {}", hex_str);

    // Call shell command directly using std::process::Command
    let output = std::process::Command::new("cast")
        .arg("keccak")
        .arg(&hex_str)
        .output()
        .expect("Failed to execute cast command. Please Make sure foundry/cast is installed in your PATH.");

    if output.status.success() {
        println!("cast output: {}", String::from_utf8_lossy(&output.stdout).trim());
    } else {
        eprintln!("cast failed: {}", String::from_utf8_lossy(&output.stderr).trim());
    }
}
