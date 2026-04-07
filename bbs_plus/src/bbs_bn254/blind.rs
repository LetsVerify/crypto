//! User functions impl for some user-side operations, including:
//! blind, unblind and proof of knowledge of committed values.

#![allow(unused)]

use ark_bn254::{Fr as Scalar, G1Affine as G1, G1Projective};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::{UniformRand, rand::RngCore};
use sha2::{Digest, Sha256};

use crate::bbs_bn254::{
    Signature,
    structs::{BlindedCommitment, CommitmentProof, Parameters},
};

/// Create a blinded commitment for a list of messages.
/// Returns `Err` if message length exceeds available parameters.
/// for example, if blind_index is 3, and the length of messages is 5
/// the m0, m1, m2 are visual, while m3, m4 are blinded, the commitment will be C = r*H_0 + m3*H_4 + m4*H_5
pub fn blind(
    params: &Parameters,
    messages: &[Scalar],
    blind_index: &usize,
) -> Result<BlindedCommitment, &'static str> {
    let mut rng = ark_std::test_rng();
    blind_with_rng(params, messages, blind_index, &mut rng)
}

/// Create a blinded commitment using a caller-supplied RNG.
pub fn blind_with_rng<R: RngCore>(
    params: &Parameters,
    messages: &[Scalar],
    blind_index: &usize,
    rng: &mut R,
) -> Result<BlindedCommitment, &'static str> {
    if messages.len() > params.L {
        return Err("message length exceeds parameters");
    }
    if params.H.len() < messages.len() + 1 {
        return Err("parameters do not include enough message base points");
    }
    if *blind_index > messages.len() {
        return Err("invalid blind index");
    }

    // calc r*H_1
    let blinding_factor = Scalar::rand(rng);
    let mut commitment = params.H[0] * blinding_factor;

    // calc m_j*H_{j+1}
    for j in *blind_index..messages.len() {
        commitment += params.H[j + 1] * messages[j];
    }

    Ok(BlindedCommitment {
        commitment: commitment.into_affine(),
        blinding_factor,
    })
}

pub fn unblind(
    params: &Parameters,
    signature: &Signature,
    commitment: &BlindedCommitment,
) -> Result<Signature, &'static str> {
    if params.H.len() < 2 {
        return Err("parameters do not include enough message base points");
    }

    let unblinded_s = signature.s + commitment.blinding_factor;
    return Ok(Signature {
        A: signature.A,
        e: signature.e,
        s: unblinded_s,
    });
}

/// Generate a proof of knowledge for the blinded commitment.
pub fn commitment_pok_prove(
    params: &Parameters,
    commitment: &BlindedCommitment,
    blind_index: &usize,
    messages: &[Scalar],
) -> Result<CommitmentProof, &'static str> {
    let mut rng = ark_std::test_rng();
    commitment_pok_prove_with_rng(params, commitment, messages, blind_index, &mut rng)
}

/// Generate a proof of knowledge for the blinded commitment with a caller RNG.
pub fn commitment_pok_prove_with_rng<R: RngCore>(
    params: &Parameters,
    commitment: &BlindedCommitment,
    messages: &[Scalar],
    blind_index: &usize,
    rng: &mut R,
) -> Result<CommitmentProof, &'static str> {
    if params.H.len() < messages.len() + 1 {
        return Err("parameters do not include enough message base points");
    }

    // sample r_s
    let r_s = Scalar::rand(rng);
    // sample r_m for each hidden message
    let mut r_m_vec = Vec::with_capacity(messages.len());
    for _ in 0..messages.len() {
        r_m_vec.push(Scalar::rand(rng));
    }
    // build temp commitment T = r_s*H_0 + sum(r_m*H_{m+1})
    let mut t = params.H[0] * r_s;
    let mut index = *blind_index;
    for (j, r_m) in r_m_vec.iter().enumerate() {
        t += params.H[index + 1] * r_m;
        index += 1;
    }
    let t_affine = t.into_affine();

    // calc challenge = Hash(C | T | hidden_message_len)
    let challenge = commitment_challenge(&commitment.commitment, &t_affine, messages.len())?;

    // calc responses
    // s_hat = r_s + challenge * commitment.blinding_factor
    let s_hat = r_s + challenge * commitment.blinding_factor;
    // m_hat_j = m_j + c*m_j
    let mut m_hats = Vec::with_capacity(messages.len());
    for (j, r_m) in r_m_vec.iter().enumerate() {
        m_hats.push(*r_m + challenge * messages[j])
    }

    // pi = (T, c, s_hat, {m_hat_j})
    Ok(CommitmentProof {
        t: t_affine,
        challenge,
        s_hat,
        m_hats,
    })
}

/// Verify a commitment proof of knowledge.
pub fn commitment_pok_verify(
    params: &Parameters,
    commitment: &BlindedCommitment,
    proof: &CommitmentProof,
    blind_index: &usize
) -> Result<bool, &'static str> {
    if params.H.len() < proof.m_hats.len() + 1 {
        return Err("parameters do not include enough message base points");
    }

    // first step: check c' == c
    let expected_challenge =
        commitment_challenge(&commitment.commitment, &proof.t, proof.m_hats.len())?;
    if expected_challenge != proof.challenge {
        return Ok(false);
    }

    // second step: assert(s_hat * H_0 + sum(m_hat_j*H_j) == T + challenge * commitement)
    let mut lhs = params.H[0] * proof.s_hat;
    let mut index = *blind_index;
    for (i, m_hat) in proof.m_hats.iter().enumerate() {
        lhs += params.H[index + 1] * m_hat;
        index += 1;
    }

    let rhs = G1Projective::from(proof.t) + (commitment.commitment * proof.challenge);
    Ok(lhs.into_affine() == rhs.into_affine())
}

fn commitment_challenge(
    commitment: &G1,
    t: &G1,
    message_len: usize,
) -> Result<Scalar, &'static str> {
    let mut bytes = Vec::new();
    commitment
        .serialize_compressed(&mut bytes)
        .map_err(|_| "failed to serialize commitment")?;
    t.serialize_compressed(&mut bytes)
        .map_err(|_| "failed to serialize commitment T")?;
    bytes.extend_from_slice(&(message_len as u64).to_le_bytes());

    let hash = Sha256::digest(bytes);
    Ok(Scalar::from_le_bytes_mod_order(&hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bbs_bn254::keygen::keygen;
    
    #[test]
    fn blind_and_pok_roundtrip() {
        let (params, _pk, _sk) = keygen(3);
        let messages = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];

        let mut rng = ark_std::test_rng();
        let blind_index = 1;
        let commitment = blind_with_rng(&params, &messages, &1, &mut rng).unwrap();
        let hidden_part = vec![Scalar::from(2u64), Scalar::from(3u64)];
        let proof =
            commitment_pok_prove_with_rng(&params, &commitment, &hidden_part, &blind_index, &mut rng).unwrap();

        let ok = commitment_pok_verify(&params, &commitment, &proof, &blind_index).unwrap();
        assert!(ok);
    }
}
