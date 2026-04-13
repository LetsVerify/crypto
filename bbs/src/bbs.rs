//! Basic BBS scheme functions here.
#![allow(non_snake_case)]

use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_std::{UniformRand, rand::RngCore};

use crate::pub_use::*;
use crate::structs::*;

/// Key gen function.
/// `L`: the length of messages.
pub fn setup<R: RngCore>(L: usize, rng: &mut R) -> Params {
    // Sample vector H of length L
    let mut H = Vec::with_capacity(L);
    for _ in 0..L {
        H.push(G1::rand(rng));
    }

    Params {
        G1: G1::generator(),
        G2: G2::generator(),
        L: L,
        H: H,
    }
}

/// Keygen function here
/// `rng`: the rng engine
pub fn keygen<R: RngCore>(rng: &mut R) -> (PublicKey, PrivateKey) {
    let x = Scalar::rand(rng);
    let X = (G2::generator() * x).into_affine();
    (PublicKey { X }, PrivateKey { x })
}

/// Sign function here
/// + `messages`: the messages to be signed, each message is mapped to a Scalar
/// + `params`: the public parameters
/// + `sk`: the private key
/// + `rng`: the rng engine
pub fn sign<R: RngCore>(
    messages: &Messages,
    params: &Params,
    sk: &PrivateKey,
    rng: &mut R,
) -> Result<Signature, &'static str> {
    if messages.0.len() > params.L {
        return Err("message length exceeds parameters");
    }

    // 1. calc commitment C = G_1 + h_0*s' + h_1*m_1 + ... + h_L*m_L
    let mut C = params.G1.into_group();
    for (i, m_i) in messages.0.iter().enumerate() {
        C += params.H[i] * m_i;
    }
    // 2. sample random scalars e
    let e = Scalar::rand(rng);

    // 3. calc A = C * (1/(x+e))
    let mut tmp = sk.x + e;
    tmp = tmp.inverse().ok_or("failed to compute inverse")?;
    let A = (C * tmp).into_affine();

    Ok(Signature { A, e })
}

pub fn verify(messages: &Messages, signature: &Signature, params: &Params, pk: &PublicKey) -> bool {
    if messages.0.len() > params.L {
        return false;
    }

    // 1. calc C' = G_1 + h_0*s' + h_1*m_1 + ... + h_L*m_L
    let mut C_prime = params.G1.into_group();
    for (i, m_i) in messages.0.iter().enumerate() {
        C_prime += params.H[i] * m_i;
    }
    // 2. calc e(A, X + e*G2)
    let left = Bn254::pairing(signature.A, pk.X + params.G2 * signature.e);
    // 3. calc e(C', G2)
    let right = Bn254::pairing(C_prime.into_affine(), params.G2);

    left == right
}
