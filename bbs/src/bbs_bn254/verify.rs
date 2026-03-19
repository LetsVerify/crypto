//! Verification related functions here

use ark_bn254::{Bn254, Fr as Scalar};
use ark_ec::pairing::Pairing;

use crate::bbs_bn254::{Parameters, PublicKey, Signature};

/// Verify a signature without blind.
pub fn verify_no_blind(
    params: &Parameters,
    pk: &PublicKey,
    messages: &[Scalar],
    signature: &Signature,
) -> Result<bool, &'static str> {
    // Check message length
    if messages.len() > params.L {
        return Err("message length exceeds parameters");
    }
    // Check points are on curve
    if !signature.A.is_on_curve() {
        return Err("signature A is not on curve");
    }
    if !pk.w.is_on_curve() {
        return Err("public key w is not on curve");
    }

    // lhs = e(A, w + e*g2)
    //  calc w + e * g2
    let w_e_g2 = pk.w + params.g2 * signature.e;
    //  calc e(A, w + e*g2)
    let lhs = Bn254::pairing(signature.A, w_e_g2);

    // rhs = e(C, g2)
    //  calc C = g1 + s*H_0 + m_1*H_1 + ... + m_L*H_L
    let mut c = params.g1 + params.H[0] * signature.s;
    for i in 0..messages.len() {
        c += params.H[i + 1] * messages[i];
    }
    // calc e(C, g2)
    let rhs = Bn254::pairing(c, params.g2);

    // Check if lhs == rhs
    return Ok(lhs == rhs);
}
