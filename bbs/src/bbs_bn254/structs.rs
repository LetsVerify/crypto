#![allow(non_snake_case, dead_code)]

use ark_bn254::{G1Affine as G1, G2Affine as G2, Fr as Scalar};

/// BBS+ public parameters
/// Contains the generators and message base points for the signing system
pub struct Parameters {
    /// Maximum number of messages
    pub L: usize,
    /// G1 generator g1
    pub g1: G1,
    /// G2 generator g2
    pub g2: G2,
    /// Message base point vector H = [h_0, h_1, ..., h_L]
    /// h_0 is used for the blinding factor; h_1..h_L correspond to each message
    pub H: Vec<G1>,
}

/// BBS+ public key
/// w = x * g2, derived from private key x and generator g2
pub struct PublicKey {
    pub w: G2,
}

/// BBS+ private key
pub struct PrivateKey {
    /// Private key scalar x ∈ Fr
    pub x: Scalar,
}

/// BBS+ signature
/// A signature consists of the triple (A, e, s) satisfying:
///   e(A, w + e*g2) = e(g1 + h_0*s + h_1*m_1 + ... + h_L*m_L, g2)
pub struct Signature {
    /// Signature point A ∈ G1
    pub A: G1,
    /// Random scalar e ∈ Fr
    pub e: Scalar,
    /// Random scalar s ∈ Fr
    pub s: Scalar,
}

/// Collection of messages to be signed
pub struct Messages {
    /// Message scalar list m_1, ..., m_L (each message mapped to an Fr element)
    pub msgs: Vec<Scalar>,
}

/// Commitment in a blind signature request
/// The holder hides some messages and produces commitment C = h_0*s' + h_1*m_1 + ...
pub struct BlindedCommitment {
    /// Commitment point C ∈ G1
    pub commitment: G1,
    /// Blinding factor s' ∈ Fr
    pub blinding_factor: Scalar,
}

/// Proof of Knowledge of committed values (PoK of Committed Values)
/// Proves that the holder knows the hidden messages inside commitment C, without revealing them
pub struct CommitmentProof {
    /// Challenge value c ∈ Fr (Fiat-Shamir hash)
    pub challenge: Scalar,
    /// Blinding factor response: s_hat = s' + c * blinding_factor
    pub s_hat: Scalar,
    /// Per-message responses: m_hat_i = r_i + c * m_i
    pub m_hats: Vec<Scalar>,
}

/// Proof of Knowledge of a BBS+ signature (PoK of Signature)
/// Used for selective disclosure: proves possession of a valid BBS+ signature
/// over a subset of messages without revealing the signature (A, e, s) itself
pub struct SignatureProof {
    /// Randomized signature point A' = A * r1
    pub A_prime: G1,
    /// Intermediate point A_bar = A' * (-e) + h_0 * (s - s'' * r1)
    pub A_bar: G1,
    /// Intermediate point D = h_0^r2 * B^r1
    pub D: G1,
    /// Challenge value c ∈ Fr (Fiat-Shamir hash)
    pub challenge: Scalar,
    /// Response for e: e_hat = e_tilde + c * e
    pub e_hat: Scalar,
    /// Response for r2: r2_hat = r2_tilde + c * r2
    pub r2_hat: Scalar,
    /// Response for r3: r3_hat = r3_tilde + c * r3, where r3 = 1/r1
    pub r3_hat: Scalar,
    /// Response for s'': s_hat = s_tilde + c * s''
    pub s_hat: Scalar,
    /// Per-hidden-message responses: m_hat_i = m_tilde_i + c * m_i
    pub m_hats: Vec<Scalar>,
    /// Indices and values of the disclosed messages
    pub disclosed: Vec<(usize, Scalar)>,
}