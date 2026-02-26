use ark_bn254::{G1Affine as G1, G1Projective as G1Projective, Fr as Scalar};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::{rand::RngCore, UniformRand};
use sha2::{Digest, Sha256};

use crate::bbs_bn254::structs::{BlindedCommitment, CommitmentProof, Parameters};

/// User functions impl for BBS+ signatures over BN254.
/// Includes blind, unblind, proofgen

/// Create a blinded commitment for a list of messages.
/// Returns `Err` if message length exceeds available parameters.
pub fn blind(params: &Parameters, messages: &[Scalar]) -> Result<BlindedCommitment, &'static str> {
	let mut rng = ark_std::test_rng();
	blind_with_rng(params, messages, &mut rng)
}

/// Create a blinded commitment using a caller-supplied RNG.
pub fn blind_with_rng<R: RngCore>(
	params: &Parameters,
	messages: &[Scalar],
	rng: &mut R,
) -> Result<BlindedCommitment, &'static str> {
	if messages.len() > params.L {
		return Err("message length exceeds parameters");
	}
	if params.H.len() < messages.len() + 1 {
		return Err("parameters do not include enough message base points");
	}

	let blinding_factor = Scalar::rand(rng);
	let mut commitment = params.H[0] * blinding_factor;
	for (i, m) in messages.iter().enumerate() {
		commitment += params.H[i + 1] * m;
	}

	Ok(BlindedCommitment {
		commitment: commitment.into_affine(),
		blinding_factor,
	})
}

/// Generate a proof of knowledge for the blinded commitment.
pub fn commitment_pok_prove(
	params: &Parameters,
	commitment: &BlindedCommitment,
	messages: &[Scalar],
) -> Result<CommitmentProof, &'static str> {
	let mut rng = ark_std::test_rng();
	commitment_pok_prove_with_rng(params, commitment, messages, &mut rng)
}

/// Generate a proof of knowledge for the blinded commitment with a caller RNG.
pub fn commitment_pok_prove_with_rng<R: RngCore>(
	params: &Parameters,
	commitment: &BlindedCommitment,
	messages: &[Scalar],
	rng: &mut R,
) -> Result<CommitmentProof, &'static str> {
	if params.H.len() < messages.len() + 1 {
		return Err("parameters do not include enough message base points");
	}

	let r_s = Scalar::rand(rng);
	let mut r_ms = Vec::with_capacity(messages.len());
	for _ in 0..messages.len() {
		r_ms.push(Scalar::rand(rng));
	}

	let mut t = params.H[0] * r_s;
	for (i, r_m) in r_ms.iter().enumerate() {
		t += params.H[i + 1] * r_m;
	}
	let t_affine = t.into_affine();

	let challenge = commitment_challenge(&commitment.commitment, &t_affine, messages.len())?;

	let s_hat = r_s + challenge * commitment.blinding_factor;
	let mut m_hats = Vec::with_capacity(messages.len());
	for (m, r_m) in messages.iter().zip(r_ms.iter()) {
		m_hats.push(*r_m + challenge * m);
	}

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
) -> Result<bool, &'static str> {
	if params.H.len() < proof.m_hats.len() + 1 {
		return Err("parameters do not include enough message base points");
	}

	let expected_challenge =
		commitment_challenge(&commitment.commitment, &proof.t, proof.m_hats.len())?;
	if expected_challenge != proof.challenge {
		return Ok(false);
	}

	let mut lhs = params.H[0] * proof.s_hat;
	for (i, m_hat) in proof.m_hats.iter().enumerate() {
		lhs += params.H[i + 1] * m_hat;
	}

	let rhs = G1Projective::from(proof.t) + (commitment.commitment * proof.challenge);
	Ok(lhs.into_affine() == rhs.into_affine())
}

fn commitment_challenge(commitment: &G1, t: &G1, message_len: usize) -> Result<Scalar, &'static str> {
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
		let commitment = blind_with_rng(&params, &messages, &mut rng).unwrap();
		let proof = commitment_pok_prove_with_rng(&params, &commitment, &messages, &mut rng).unwrap();

		let ok = commitment_pok_verify(&params, &commitment, &proof).unwrap();
		assert!(ok);
	}
}
