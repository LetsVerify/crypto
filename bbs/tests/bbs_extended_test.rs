use ark_bn254::{Fr as Scalar, G1Affine as G1, G2Affine as G2};
use ark_std::UniformRand;
use ark_std::test_rng;
use bbs::extend::BBSPlusExtendedScheme;
use bbs::structs::{PublicKey, Messages, Params};
use bbs::pok::{nizk_prove_prefix, nizk_verify_prefix};
use ark_ec::{CurveGroup, AffineRepr};

#[test]
fn test_bbs_extended_scheme() {
    let mut rng = test_rng();

    // ---------------------------------------------------------
    // 0. Setup parameters (Assume Trusted Setup / Issuer)
    // ---------------------------------------------------------
    let g1 = G1::generator();
    let g2 = G2::generator();
    
    // We need 5 public messages (m0 to m4), + 2 extra messages (m_null, m_gamma)
    let num_public_messages = 5;
    let total_messages = num_public_messages + 2;
    
    let mut h_bases = Vec::with_capacity(total_messages);
    for _ in 0..total_messages {
        h_bases.push(G1::rand(&mut rng));
    }
    
    let params = Params {
        G1: g1,
        G2: g2,
        L: total_messages,
        H: h_bases.clone(),
    };

    // Signer keys
    let sk = Scalar::rand(&mut rng);
    let pk_point = (g2 * sk).into_affine();
    let pk = PublicKey { X: pk_point };

    // ---------------------------------------------------------
    // 1. User Application (Init & Blinding)
    // ---------------------------------------------------------
    // User attributes
    let mut messages_vec = Vec::with_capacity(total_messages);
    for _ in 0..num_public_messages {
        messages_vec.push(Scalar::rand(&mut rng)); // e.g., age=18, nationality="CN", etc.
    }
    let m_null = Scalar::rand(&mut rng);
    let m_gamma = Scalar::rand(&mut rng);
    let lambda = Scalar::rand(&mut rng);

    // Push m_null and m_gamma as the last two messages
    messages_vec.push(m_null);
    messages_vec.push(m_gamma);
    let messages = Messages(messages_vec.clone());

    // User commits to m_null and m_gamma
    let user_commitment = BBSPlusExtendedScheme::user_commit(
        &m_null, 
        &m_gamma, 
        &lambda, 
        &h_bases
    );

    // ---------------------------------------------------------
    // 2. Signer Generates Partial Signature
    // ---------------------------------------------------------
    // Signer checks public constraints, and issues partial sig
    let public_messages = &messages_vec[..num_public_messages];
    let partial_sig = BBSPlusExtendedScheme::signer_sign(
        &mut rng,
        &sk,
        public_messages,
        &h_bases,
        &g1,
        &user_commitment.C2,
    );

    // ---------------------------------------------------------
    // 3. User Unblinds the Partial Signature
    // ---------------------------------------------------------
    let full_signature = BBSPlusExtendedScheme::user_unblind(&partial_sig, &lambda);

    // ---------------------------------------------------------
    // 4. User Generates NIZK Proof (Prove ownership of valid sig)
    // ---------------------------------------------------------
    // Disclosed count: num_public_messages + 1 (m_null is disclosed to verifier)
    // The only hidden message is m_gamma at the end
    let disclosed_count = num_public_messages + 1;
    
    let proof = nizk_prove_prefix(
        &params,
        &pk,
        &messages,
        &full_signature,
        disclosed_count,
        &mut rng
    ).expect("nizk_prove_prefix failed");

    // ---------------------------------------------------------
    // 5. Verifier Validates the NIZK Proof
    // ---------------------------------------------------------
    let disclosed_msgs = &messages_vec[..disclosed_count];
    let is_valid = nizk_verify_prefix(
        &params,
        &pk,
        disclosed_msgs,
        &proof
    );

    assert!(is_valid, "The extended BBS scheme NIZK proof failed to verify!");
}
