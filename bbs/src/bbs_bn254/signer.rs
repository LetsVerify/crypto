//! Impl signing related functions.

use ark_bn254::{G1Affine as G1, G2Affine as G2, Fr as Scalar};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_std::{UniformRand, rand::RngCore, test_rng};

use crate::bbs_bn254::{Parameters, PrivateKey, structs::Signature};

pub fn sign_no_blind(
    params: &Parameters,
    sk: &PrivateKey,
    messages: &[Scalar]
) -> Result<Signature, &'static str> {
    let mut rng = test_rng();
    sign_no_blind_with_rng(params, sk, messages, rng)
}

pub fn sign_no_blind_with_rng<R: RngCore>(
    params: &Parameters,
    sk: &PrivateKey,
    messages: &[Scalar],
    rng: &mut R
) -> Result<Signature, &'static str> {
    // Sample random scalars e and s
    let e = Scalar::rand(rng);
    let s = Scalar::rand(rng);

    // Constrruct Commitment C = G_1 + s*H_0 + m_1*H_1 + ... + m_L*H_L
    let mut c = params.g1 + params.H[0] * s;
    for (j, m_j) in messages.iter().enumerate() {
        if j >= params.L {
            return Err("message length exceeds parameters");
        }
        c += params.H[j + 1] * m_j;
    }

    // calc (x + e) ^ (-1)
    let mut tmp = sk.x + e;
    tmp = tmp.inverse().ok_or("failed to compute inverse")?;
    
    Ok(())
}