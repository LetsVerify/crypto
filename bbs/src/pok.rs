//! Proof of Knowledge of BBS Signature with selective disclosure

#![allow(non_snake_case)]
use ark_bn254::{Bn254, Fr as Scalar, G1Affine as G1};
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_std::{rand::RngCore, UniformRand, Zero};
use std::collections::{HashMap, HashSet};

use crate::pub_use::*;
use crate::structs::{Messages, Params, PublicKey, Signature};
use sha3::{Digest, Keccak256};

/// Represents the public messages provided by the verifier
pub type DisclosedMessages = HashMap<usize, Scalar>;

/// Prover's state for the interactive protocol
pub struct InteractiveProverState {
    pub r: Scalar,
    pub alpha: Scalar,
    pub beta: Scalar,
    pub deltas: HashMap<usize, Scalar>,
    pub hidden_indices: HashSet<usize>,
    pub e: Scalar,
    pub hidden_messages: HashMap<usize, Scalar>,
}

/// Commitment sent from Prover to Verifier in step 1 of interactive protocol
pub struct PoKCommitment {
    pub A_bar: G1,
    pub B_bar: G1,
    pub U: G1,
}

/// Challenge from the Verifier
pub type Challenge = Scalar;

/// Response from Prover to Verifier in step 2 of interactive protocol
pub struct PoKResponse {
    pub s: Scalar,
    pub t: Scalar,
    pub u_i: HashMap<usize, Scalar>,
}

/// Non-interactive Proof (fs)
pub struct NonInteractiveProof {
    pub A_bar: G1,
    pub B_bar: G1,
    pub U: G1,
    pub s: Scalar,
    pub t: Scalar,
    pub u_i: HashMap<usize, Scalar>,
}

/// Context for FS heuristic
const POK_CTX: &[u8] = b"BBS_PoK_1";

/// Compute the public commitment $C_J = G_1 + \sum_{j \in J} m_j \cdot H_j$
pub fn compute_c_j(params: &Params, disclosed: &DisclosedMessages) -> G1 {
    let mut c_j = params.G1.into_group();
    for (&j, m_j) in disclosed.iter() {
        if j < params.L {
            c_j += params.H[j] * m_j;
        }
    }
    c_j.into_affine()
}

/// Interactive Protocol: Step 1 (Prover Commit)
pub fn pok_commit<R: RngCore>(
    params: &Params,
    messages: &Messages,
    signature: &Signature,
    disclosed_indices: &HashSet<usize>,
    rng: &mut R,
) -> Result<(PoKCommitment, InteractiveProverState), &'static str> {
    if messages.0.len() > params.L {
        return Err("message length exceeds parameters");
    }

    let l = messages.0.len();
    let hidden_indices: HashSet<usize> = (0..l).filter(|i| !disclosed_indices.contains(i)).collect();

    // 1. r <- Z_p*
    let mut r = Scalar::rand(rng);
    while r.is_zero() {
        r = Scalar::rand(rng);
    }

    // 2. A_bar <- r * A
    let a_bar = (signature.A * r).into_affine();

    // 3. Compute C_J
    let mut disclosed_msgs = HashMap::new();
    for &j in disclosed_indices.iter() {
        if j < l {
            disclosed_msgs.insert(j, messages.0[j]);
        }
    }
    let c_j = compute_c_j(params, &disclosed_msgs);

    // 4. Compute C and B_bar
    let mut c = params.G1.into_group();
    for (i, m_i) in messages.0.iter().enumerate() {
        c += params.H[i] * m_i;
    }
    let b_bar = (c * r - signature.A * (r * signature.e)).into_affine();

    // 5. Random scalars
    let alpha = Scalar::rand(rng);
    let beta = Scalar::rand(rng);
    let mut deltas = HashMap::new();
    let mut u_term = params.G1.into_group() * Scalar::zero();
    for &i in &hidden_indices {
        let delta_i = Scalar::rand(rng);
        deltas.insert(i, delta_i);
        u_term += params.H[i] * delta_i;
    }

    // 6. U <- alpha * C_J + beta * A_bar + sum(delta_i * H_i)
    let u = (c_j * alpha + a_bar * beta + u_term).into_affine();

    let commitment = PoKCommitment {
        A_bar: a_bar,
        B_bar: b_bar,
        U: u,
    };

    let mut hidden_messages = HashMap::new();
    for &i in &hidden_indices {
        hidden_messages.insert(i, messages.0[i]);
    }

    let state = InteractiveProverState {
        r,
        alpha,
        beta,
        deltas,
        hidden_indices,
        e: signature.e,
        hidden_messages,
    };

    Ok((commitment, state))
}

/// Interactive Protocol: Step 2 (Prover Response)
pub fn pok_prove(state: &InteractiveProverState, challenge: &Challenge) -> PoKResponse {
    let c = *challenge;
    let s = state.alpha + state.r * c;
    let t = state.beta - state.e * c;
    
    let mut u_i = HashMap::new();
    for &i in &state.hidden_indices {
        let delta_i = state.deltas.get(&i).unwrap();
        let m_i = state.hidden_messages.get(&i).unwrap();
        let u = *delta_i + state.r * m_i * c;
        u_i.insert(i, u);
    }

    PoKResponse { s, t, u_i }
}

/// Interactive Protocol: Step 3 (Verifier Check)
pub fn pok_verify(
    params: &Params,
    pk: &PublicKey,
    disclosed: &DisclosedMessages,
    commitment: &PoKCommitment,
    challenge: &Challenge,
    response: &PoKResponse,
) -> bool {
    let c_j = compute_c_j(params, disclosed);
    
    // 1. Pairing check: e(A_bar, X) == e(B_bar, G2)
    let left_pairing = Bn254::pairing(commitment.A_bar, pk.X);
    let right_pairing = Bn254::pairing(commitment.B_bar, params.G2);
    if left_pairing != right_pairing {
        return false;
    }

    // 2. Homomorphic check: U + c * B_bar == s * C_J + t * A_bar + sum(u_i * H_i)
    let lhs = (commitment.U.into_group() + commitment.B_bar * challenge).into_affine();
    
    let mut sum_ui_hi = params.G1.into_group() * Scalar::zero();
    for (&i, u_i) in response.u_i.iter() {
        if i < params.L {
            sum_ui_hi += params.H[i] * u_i;
        }
    }
    
    let rhs = (c_j * response.s + commitment.A_bar * response.t + sum_ui_hi).into_affine();
    
    lhs == rhs
}

/* ================== Non-Interactive Version (Fiat-Shamir) ================== */

fn compute_challenge(
    pk: &PublicKey,
    disclosed: &DisclosedMessages,
    a_bar: &G1,
    b_bar: &G1,
    u: &G1,
) -> Scalar {
    let mut hasher = Keccak256::new();
    hasher.update(POK_CTX);
    
    // Convert components to bytes appropriately (this is simplified, ideal uses CanonicalSerialize)
    use ark_serialize::CanonicalSerialize;
    
    let mut pk_bytes = Vec::new();
    pk.X.serialize_compressed(&mut pk_bytes).unwrap_or_default();
    hasher.update(&pk_bytes);
    
    // Sort disclosed messages by index to ensure deterministic hashing
    let mut indices: Vec<_> = disclosed.keys().cloned().collect();
    indices.sort_unstable();
    for i in indices {
        hasher.update(&(i as u64).to_be_bytes());
        let mut m_bytes = Vec::new();
        disclosed[&i].serialize_compressed(&mut m_bytes).unwrap_or_default();
        hasher.update(&m_bytes);
    }
    
    let mut a_bytes = Vec::new();
    a_bar.serialize_compressed(&mut a_bytes).unwrap_or_default();
    hasher.update(&a_bytes);
    
    let mut b_bytes = Vec::new();
    b_bar.serialize_compressed(&mut b_bytes).unwrap_or_default();
    hasher.update(&b_bytes);
    
    let mut u_bytes = Vec::new();
    u.serialize_compressed(&mut u_bytes).unwrap_or_default();
    hasher.update(&u_bytes);
    
    let hash_result = hasher.finalize();
    // Convert hash to scalar
    Scalar::from_be_bytes_mod_order(&hash_result)
}

/// NIZK Prove (Fiat-Shamir)
pub fn nizk_prove<R: RngCore>(
    params: &Params,
    pk: &PublicKey,
    messages: &Messages,
    signature: &Signature,
    disclosed_indices: &HashSet<usize>,
    rng: &mut R,
) -> Result<NonInteractiveProof, &'static str> {
    let (commitment, state) = pok_commit(params, messages, signature, disclosed_indices, rng)?;
    
    let l = messages.0.len();
    let mut disclosed_msgs = HashMap::new();
    for &j in disclosed_indices.iter() {
        if j < l {
            disclosed_msgs.insert(j, messages.0[j]);
        }
    }
    
    let challenge = compute_challenge(pk, &disclosed_msgs, &commitment.A_bar, &commitment.B_bar, &commitment.U);
    let response = pok_prove(&state, &challenge);
    
    Ok(NonInteractiveProof {
        A_bar: commitment.A_bar,
        B_bar: commitment.B_bar,
        U: commitment.U,
        s: response.s,
        t: response.t,
        u_i: response.u_i,
    })
}

/// NIZK Verify (Fiat-Shamir)
pub fn nizk_verify(
    params: &Params,
    pk: &PublicKey,
    disclosed: &DisclosedMessages,
    proof: &NonInteractiveProof,
) -> bool {
    let challenge = compute_challenge(pk, disclosed, &proof.A_bar, &proof.B_bar, &proof.U);
    
    let commitment = PoKCommitment {
        A_bar: proof.A_bar,
        B_bar: proof.B_bar,
        U: proof.U,
    };
    let response = PoKResponse {
        s: proof.s,
        t: proof.t,
        u_i: proof.u_i.clone(),
    };
    
    pok_verify(params, pk, disclosed, &commitment, &challenge, &response)
}

/* ================== Optimized Non-Interactive Version (Prefix / On-Chain Friendly) ================== */

/// Non-interactive Proof assuming disclosed messages are a continuous prefix: 0..disclosed_count-1
pub struct NonInteractiveProofPrefix {
    pub A_bar: G1,
    pub B_bar: G1,
    pub U: G1,
    pub s: Scalar,
    pub t: Scalar,
    pub u_i: Vec<Scalar>,
}

fn compute_challenge_prefix(
    pk: &PublicKey,
    disclosed: &[Scalar],
    a_bar: &G1,
    b_bar: &G1,
    u: &G1,
) -> Scalar {
    let mut hasher = Keccak256::new();
    hasher.update(POK_CTX);
    
    use ark_serialize::CanonicalSerialize;
    
    let mut pk_bytes = Vec::new();
    pk.X.serialize_compressed(&mut pk_bytes).unwrap_or_default();
    hasher.update(&pk_bytes);
    
    for (i, m) in disclosed.iter().enumerate() {
        hasher.update(&(i as u64).to_be_bytes());
        let mut m_bytes = Vec::new();
        m.serialize_compressed(&mut m_bytes).unwrap_or_default();
        hasher.update(&m_bytes);
    }
    
    let mut a_bytes = Vec::new();
    a_bar.serialize_compressed(&mut a_bytes).unwrap_or_default();
    hasher.update(&a_bytes);
    
    let mut b_bytes = Vec::new();
    b_bar.serialize_compressed(&mut b_bytes).unwrap_or_default();
    hasher.update(&b_bytes);
    
    let mut u_bytes = Vec::new();
    u.serialize_compressed(&mut u_bytes).unwrap_or_default();
    hasher.update(&u_bytes);
    
    let hash_result = hasher.finalize();
    Scalar::from_be_bytes_mod_order(&hash_result)
}

/// NIZK Prove (Prefix Disclosure: 0..disclosed_count-1 are public)
pub fn nizk_prove_prefix<R: RngCore>(
    params: &Params,
    pk: &PublicKey,
    messages: &Messages,
    signature: &Signature,
    disclosed_count: usize,
    rng: &mut R,
) -> Result<NonInteractiveProofPrefix, &'static str> {
    if disclosed_count > messages.0.len() || messages.0.len() > params.L {
        return Err("invalid disclosed count or message length");
    }
    
    let l = messages.0.len();
    
    let mut r = Scalar::rand(rng);
    while r.is_zero() { r = Scalar::rand(rng); }
    
    let a_bar = (signature.A * r).into_affine();
    
    let mut c_j = params.G1.into_group();
    for j in 0..disclosed_count {
        c_j += params.H[j] * messages.0[j];
    }
    
    let mut c = c_j;
    for i in disclosed_count..l {
        c += params.H[i] * messages.0[i];
    }
    let b_bar = (c * r - signature.A * (r * signature.e)).into_affine();
    
    let alpha = Scalar::rand(rng);
    let beta = Scalar::rand(rng);
    let mut deltas = Vec::with_capacity(l - disclosed_count);
    let mut u_term = params.G1.into_group() * Scalar::zero();
    
    for i in disclosed_count..l {
        let delta_i = Scalar::rand(rng);
        deltas.push(delta_i);
        u_term += params.H[i] * delta_i;
    }
    
    let u = (c_j * alpha + a_bar * beta + u_term).into_affine();
    
    let disclosed_msgs = &messages.0[0..disclosed_count];
    let challenge = compute_challenge_prefix(pk, disclosed_msgs, &a_bar, &b_bar, &u);
    
    let s = alpha + r * challenge;
    let t = beta - signature.e * challenge;
    
    let mut u_i = Vec::with_capacity(l - disclosed_count);
    for i in disclosed_count..l {
        let idx = i - disclosed_count;
        u_i.push(deltas[idx] + r * messages.0[i] * challenge);
    }
    
    Ok(NonInteractiveProofPrefix {
        A_bar: a_bar,
        B_bar: b_bar,
        U: u,
        s,
        t,
        u_i,
    })
}

/// NIZK Verify (Prefix Disclosure)
pub fn nizk_verify_prefix(
    params: &Params,
    pk: &PublicKey,
    disclosed_msgs: &[Scalar],
    proof: &NonInteractiveProofPrefix,
) -> bool {
    let disclosed_count = disclosed_msgs.len();
    if disclosed_count > params.L {
        return false;
    }
    
    let challenge = compute_challenge_prefix(pk, disclosed_msgs, &proof.A_bar, &proof.B_bar, &proof.U);
    
    let mut c_j = params.G1.into_group();
    for (j, &m_j) in disclosed_msgs.iter().enumerate() {
        c_j += params.H[j] * m_j;
    }
    
    let left_pairing = Bn254::pairing(proof.A_bar, pk.X);
    let right_pairing = Bn254::pairing(proof.B_bar, params.G2);
    if left_pairing != right_pairing {
        return false;
    }
    
    let lhs = (proof.U.into_group() + proof.B_bar * challenge).into_affine();
    
    let mut sum_ui_hi = params.G1.into_group() * Scalar::zero();
    for (idx, &u_i_val) in proof.u_i.iter().enumerate() {
        let i = disclosed_count + idx;
        if i < params.L {
            sum_ui_hi += params.H[i] * u_i_val;
        }
    }
    
    let rhs = (c_j * proof.s + proof.A_bar * proof.t + sum_ui_hi).into_affine();
    
    lhs == rhs
}
