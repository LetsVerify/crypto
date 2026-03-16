//! Impl signing related functions.

use ark_bn254::{Fr as Scalar, G1Affine as G1};
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_std::{UniformRand, rand::RngCore, test_rng};

use crate::bbs_bn254::{Parameters, PrivateKey, structs::Signature};

pub fn sign_no_blind(
    params: &Parameters,
    sk: &PrivateKey,
    messages: &[Scalar],
) -> Result<Signature, &'static str> {
    let mut rng = test_rng();
    sign_no_blind_with_rng(params, sk, messages, &mut rng)
}

pub fn sign_no_blind_with_rng<R: RngCore>(
    params: &Parameters,
    sk: &PrivateKey,
    messages: &[Scalar],
    rng: &mut R,
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

    // calc A = C * (x + e) ^ (-1)
    let a = (c * tmp).into_affine() as G1;

    // Output signature (A, e, s)
    Ok(Signature { A: a, e, s })
}

pub fn sign_with_blind(
    params: &Parameters,
    sk: &PrivateKey,
    blind_index: &usize,
    commitment: &G1,
    visual_messages: &[Scalar],
) -> Result<Signature, &'static str> {
    let mut rng = test_rng();
    sign_with_blind_with_rng(
        params,
        sk,
        blind_index,
        commitment,
        visual_messages,
        &mut rng,
    )
}

pub fn sign_with_blind_with_rng<R: RngCore>(
    params: &Parameters,
    sk: &PrivateKey,
    blind_index: &usize,
    commitment: &G1,
    visual_messages: &[Scalar],
    rng: &mut R,
) -> Result<Signature, &'static str> {
    // Check
    if visual_messages.len() > params.L {
        return Err("message length exceeds parameters");
    }
    if *blind_index > visual_messages.len() {
        return Err("invalid blind index");
    }

    // Sample random scalars e and s'
    let e = Scalar::rand(rng);
    let s_prime = Scalar::rand(rng);

    // Construct C' = g_1 + commitment + s'*H_0 + sum(m_i*H_i)
    let mut c_p = params.g1 + commitment + params.H[0] * s_prime;
    for (j, m_j) in visual_messages.iter().enumerate() {
        if j >= params.L {
            return Err("message length exceeds parameters");
        }
        c_p += params.H[j + 1] * m_j;
    }

    // calc (x + e) ^ (-1)
    let mut tmp = sk.x + e;
    tmp = tmp.inverse().ok_or("failed to compute inverse")?;

    // calc A = C' * (x + e) ^ (-1)
    let a = (c_p * tmp).into_affine() as G1;

    return Ok(Signature {
        A: a,
        e,
        s: s_prime,
    });
}
