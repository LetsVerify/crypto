//! Extend funcs and methods for supporting our scheme.
#![allow(non_snake_case)]

use crate::pub_use::*;
use ark_std::{UniformRand, rand::RngCore};

use crate::extend_structs::{PartialSignature, UserCommitment};
use crate::structs::{Signature};

pub struct BBSPlusExtendedScheme;

use ark_ff::{BigInteger, PrimeField};
use ark_bn254::{Fr as Scalar, G1Affine as G1, G2Affine as G2};

/// Converts a Field element to BIG ENDIAN bytes (32 bytes for Fr/Fq)
pub fn field_to_bytes_be<F: PrimeField>(f: &F) -> Vec<u8> {
    f.into_bigint().to_bytes_be()
}

/// Serializes G1 into 64 bytes (X || Y) for EVM compatibility
pub fn push_g1_to_bytes(p: &G1, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&field_to_bytes_be(&p.x));
    buf.extend_from_slice(&field_to_bytes_be(&p.y));
}

/// Serializes G2 into 128 bytes (X.c1 || X.c0 || Y.c1 || Y.c0) for EVM Bn254 compatibility
pub fn push_g2_to_bytes(p: &G2, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&field_to_bytes_be(&p.x.c1));
    buf.extend_from_slice(&field_to_bytes_be(&p.x.c0));
    buf.extend_from_slice(&field_to_bytes_be(&p.y.c1));
    buf.extend_from_slice(&field_to_bytes_be(&p.y.c0));
}

impl BBSPlusExtendedScheme {
    /// Step 2: User computes blinded commitment C2
    pub fn user_commit(
        m_null: &Scalar,
        m_gamma: &Scalar,
        lambda: &Scalar,
        h_bases: &[G1],
    ) -> UserCommitment {
        let l = h_bases.len();
        let h_null = &h_bases[l - 2];
        let h_gamma = &h_bases[l - 1];

        let mut c2_proj = *h_null * *m_null;
        c2_proj += *h_gamma * *m_gamma;
        c2_proj = c2_proj * *lambda;
        UserCommitment {
            C2: c2_proj.into_affine(),
        }
    }

    /// Step 3: Signer generates partial signature
    pub fn signer_sign<R: RngCore>(
        rng: &mut R,
        sk: &Scalar,
        messages: &[Scalar], // public messages m_0 to m_{l-3}
        h_bases: &[G1],      // H0 to H_{l-1}
        g1: &G1,
        c2: &G1,
    ) -> PartialSignature {
        let l = h_bases.len();
        assert_eq!(messages.len(), l - 2, "Public messages count must be l-2");
        
        // C1 = G1 + \sum m_i H_i
        let mut c1_proj = g1.into_group();
        for (m, h) in messages.iter().zip(h_bases.iter()) {
            c1_proj += *h * *m;
        }

        let e = Scalar::rand(rng);
        let mut denominator = *sk;
        denominator += e;
        let inv_denominator = denominator.inverse().unwrap();

        let a1 = (c1_proj * inv_denominator).into_affine();
        let a2_prime = (*c2 * inv_denominator).into_affine();

        PartialSignature {
            A1: a1,
            A2_prime: a2_prime,
            e,
        }
    }

    /// Step 4.1: User unblinds the partial signature to get the full signature (A, e)
    pub fn user_unblind(
        partial_sig: &PartialSignature,
        lambda: &Scalar,
    ) -> Signature {
        let inv_lambda = lambda.inverse().unwrap();
        let a2 = (partial_sig.A2_prime * inv_lambda).into_affine();
        let a = (partial_sig.A1.into_group() + a2).into_affine();
        
        Signature {
            A: a,
            e: partial_sig.e,
        }
    }
}