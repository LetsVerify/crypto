mod utils;

use ark_std::{test_rng, UniformRand};
use bbs::bbs::{keygen as bbs_keygen, setup as bbs_setup, sign as bbs_sign, verify as bbs_verify};
use bbs::extend::BBSPlusExtendedScheme;
use bbs::extend_structs::{PartialSignature, UserCommitment};
use bbs::pok::{nizk_prove_prefix, nizk_verify_prefix};
use bbs::structs::{Messages, Params, PrivateKey, PublicKey, Signature};
use ark_bn254::Fr as Scalar;
use std::str::FromStr;
use rand::thread_rng;
use serde::Serialize;
use serde_wasm_bindgen::{from_value, to_value};
use std::convert::TryInto;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn init_panic_hook() {
    utils::set_panic_hook();
}

#[derive(Serialize)]
struct KeysJson {
    pk: utils::PublicKeyJson,
    sk: utils::PrivateKeyJson,
}

#[wasm_bindgen]
pub fn setup(l: usize) -> Result<JsValue, JsValue> {
    let mut rng = thread_rng();
    let params = bbs_setup(l, &mut rng);

    let params_dto: utils::ParamsJson = (&params).into();
    to_value(&params_dto).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn keygen() -> Result<JsValue, JsValue> {
    let mut rng = thread_rng();
    let (pk, sk) = bbs_keygen(&mut rng);

    let pk_dto: utils::PublicKeyJson = (&pk).into();
    let sk_dto: utils::PrivateKeyJson = (&sk).into();

    let keys = KeysJson {
        pk: pk_dto,
        sk: sk_dto,
    };

    to_value(&keys).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn sign(messages_js: JsValue, params_js: JsValue, sk_js: JsValue) -> Result<JsValue, JsValue> {
    let mut rng = thread_rng();

    let msgs_dto: utils::MessagesJson =
        from_value(messages_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let messages: Messages = (&msgs_dto)
        .try_into()
        .map_err(|e: String| JsValue::from_str(&e))?;

    let params_dto: utils::ParamsJson =
        from_value(params_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let params: Params = (&params_dto)
        .try_into()
        .map_err(|e: String| JsValue::from_str(&e))?;

    let sk_dto: utils::PrivateKeyJson =
        from_value(sk_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let sk: PrivateKey = (&sk_dto)
        .try_into()
        .map_err(|e: String| JsValue::from_str(&e))?;

    let sig = bbs_sign(&messages, &params, &sk, &mut rng)
        .map_err(|e| JsValue::from_str(&format!("Signing failed: {}", e)))?;

    let sig_dto: utils::SignatureJson = (&sig).into();
    to_value(&sig_dto).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn verify(
    messages_js: JsValue,
    signature_js: JsValue,
    params_js: JsValue,
    pk_js: JsValue,
) -> Result<bool, JsValue> {
    let msgs_dto: utils::MessagesJson =
        from_value(messages_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let messages: Messages = (&msgs_dto)
        .try_into()
        .map_err(|e: String| JsValue::from_str(&e))?;

    let sig_dto: utils::SignatureJson =
        from_value(signature_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let signature: Signature = (&sig_dto)
        .try_into()
        .map_err(|e: String| JsValue::from_str(&e))?;

    let params_dto: utils::ParamsJson =
        from_value(params_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let params: Params = (&params_dto)
        .try_into()
        .map_err(|e: String| JsValue::from_str(&e))?;

    let pk_dto: utils::PublicKeyJson =
        from_value(pk_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let pk: PublicKey = (&pk_dto)
        .try_into()
        .map_err(|e: String| JsValue::from_str(&e))?;

    Ok(bbs_verify(&messages, &signature, &params, &pk))
}

#[wasm_bindgen]
pub fn pok_nizk_prove(
    params_js: JsValue,
    pk_js: JsValue,
    messages_js: JsValue,
    signature_js: JsValue,
    disclosed_count: usize,
) -> Result<JsValue, JsValue> {
    let mut rng = thread_rng();

    let params_dto: utils::ParamsJson =
        from_value(params_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let params: Params = (&params_dto)
        .try_into()
        .map_err(|e: String| JsValue::from_str(&e))?;

    let pk_dto: utils::PublicKeyJson =
        from_value(pk_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let pk: PublicKey = (&pk_dto)
        .try_into()
        .map_err(|e: String| JsValue::from_str(&e))?;

    let msgs_dto: utils::MessagesJson =
        from_value(messages_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let messages: Messages = (&msgs_dto)
        .try_into()
        .map_err(|e: String| JsValue::from_str(&e))?;

    let sig_dto: utils::SignatureJson =
        from_value(signature_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let signature: Signature = (&sig_dto)
        .try_into()
        .map_err(|e: String| JsValue::from_str(&e))?;

    let proof = nizk_prove_prefix(
        &params,
        &pk,
        &messages,
        &signature,
        disclosed_count,
        &mut rng,
    )
    .map_err(|e| JsValue::from_str(&format!("NIZK Prove failed: {}", e)))?;

    let proof_dto: utils::NonInteractiveProofPrefixJson = (&proof).into();
    to_value(&proof_dto).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn pok_nizk_verify(
    params_js: JsValue,
    pk_js: JsValue,
    disclosed_msgs_js: JsValue,
    proof_js: JsValue,
) -> Result<bool, JsValue> {
    let params_dto: utils::ParamsJson =
        from_value(params_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let params: Params = (&params_dto)
        .try_into()
        .map_err(|e: String| JsValue::from_str(&e))?;

    let pk_dto: utils::PublicKeyJson =
        from_value(pk_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let pk: PublicKey = (&pk_dto)
        .try_into()
        .map_err(|e: String| JsValue::from_str(&e))?;

    let msgs_dto: utils::MessagesJson =
        from_value(disclosed_msgs_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let disclosed_msgs: Messages = (&msgs_dto)
        .try_into()
        .map_err(|e: String| JsValue::from_str(&e))?;

    let proof_dto: utils::NonInteractiveProofPrefixJson =
        from_value(proof_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let proof: utils::NonInteractiveProofPrefix = (&proof_dto)
        .try_into()
        .map_err(|e: String| JsValue::from_str(&e))?;

    Ok(nizk_verify_prefix(&params, &pk, &disclosed_msgs.0, &proof))
}

#[wasm_bindgen]
pub fn user_commit(
    m_null_str: String,
    m_gamma_str: String,
    lambda_str: String,
    params_js: JsValue,
) -> Result<JsValue, JsValue> {
    let params_dto: utils::ParamsJson =
        from_value(params_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let params: Params = (&params_dto)
        .try_into()
        .map_err(|e: String| JsValue::from_str(&e))?;

    let m_null = Scalar::from_str(&m_null_str).map_err(|_| JsValue::from_str("Invalid m_null"))?;
    let m_gamma = Scalar::from_str(&m_gamma_str).map_err(|_| JsValue::from_str("Invalid m_gamma"))?;
    let lambda = Scalar::from_str(&lambda_str).map_err(|_| JsValue::from_str("Invalid lambda"))?;

    let commitment = BBSPlusExtendedScheme::user_commit(&m_null, &m_gamma, &lambda, &params.H);

    let commit_dto: utils::UserCommitmentJson = (&commitment).into();
    to_value(&commit_dto).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn signer_sign(
    sk_js: JsValue,
    messages_js: JsValue,
    params_js: JsValue,
    user_commit_js: JsValue,
) -> Result<JsValue, JsValue> {
    let mut rng = thread_rng();

    let sk_dto: utils::PrivateKeyJson =
        from_value(sk_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let sk: PrivateKey = (&sk_dto)
        .try_into()
        .map_err(|e: String| JsValue::from_str(&e))?;

    let msgs_dto: utils::MessagesJson =
        from_value(messages_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let messages: Messages = (&msgs_dto)
        .try_into()
        .map_err(|e: String| JsValue::from_str(&e))?;

    let params_dto: utils::ParamsJson =
        from_value(params_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let params: Params = (&params_dto)
        .try_into()
        .map_err(|e: String| JsValue::from_str(&e))?;

    let commit_dto: utils::UserCommitmentJson =
        from_value(user_commit_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let commit: UserCommitment = (&commit_dto)
        .try_into()
        .map_err(|e: String| JsValue::from_str(&e))?;

    let partial_sig = BBSPlusExtendedScheme::signer_sign(
        &mut rng,
        &sk.x,
        &messages.0,
        &params.H,
        &params.G1,
        &commit.C2,
    );

    let partial_sig_dto: utils::PartialSignatureJson = (&partial_sig).into();
    to_value(&partial_sig_dto).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn user_unblind(
    partial_sig_js: JsValue,
    lambda_str: String,
) -> Result<JsValue, JsValue> {
    let partial_sig_dto: utils::PartialSignatureJson =
        from_value(partial_sig_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let partial_sig: PartialSignature = (&partial_sig_dto)
        .try_into()
        .map_err(|e: String| JsValue::from_str(&e))?;

    let lambda = Scalar::from_str(&lambda_str).map_err(|_| JsValue::from_str("Invalid lambda"))?;

    let full_sig = BBSPlusExtendedScheme::user_unblind(&partial_sig, &lambda);

    let sig_dto: utils::SignatureJson = (&full_sig).into();
    to_value(&sig_dto).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// debug only, gen fixed vec<H>
#[wasm_bindgen]
pub fn setup_debug(l: usize) -> Result<JsValue, JsValue> {
    let mut rng = test_rng();
    let params = bbs_setup(l, &mut rng);

    let params_dto: utils::ParamsJson = (&params).into();
    to_value(&params_dto).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// debug only, gen fixed pk/sk
#[wasm_bindgen]
pub fn keygen_debug() -> Result<JsValue, JsValue> {
    let mut rng = test_rng();
    let (pk, sk) = bbs_keygen(&mut rng);

    let pk_dto: utils::PublicKeyJson = (&pk).into();
    let sk_dto: utils::PrivateKeyJson = (&sk).into();

    let keys = KeysJson {
        pk: pk_dto,
        sk: sk_dto,
    };

    to_value(&keys).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// debug only, gen sig with test_rng
#[wasm_bindgen]
pub fn sign_debug(
    messages_js: JsValue,
    params_js: JsValue,
    sk_js: JsValue,
) -> Result<JsValue, JsValue> {
    let mut rng = test_rng();

    let msgs_dto: utils::MessagesJson =
        from_value(messages_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let messages: Messages = (&msgs_dto)
        .try_into()
        .map_err(|e: String| JsValue::from_str(&e))?;

    let params_dto: utils::ParamsJson =
        from_value(params_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let params: Params = (&params_dto)
        .try_into()
        .map_err(|e: String| JsValue::from_str(&e))?;

    let sk_dto: utils::PrivateKeyJson =
        from_value(sk_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let sk: PrivateKey = (&sk_dto)
        .try_into()
        .map_err(|e: String| JsValue::from_str(&e))?;

    let sig = bbs_sign(&messages, &params, &sk, &mut rng)
        .map_err(|e| JsValue::from_str(&format!("Signing failed: {}", e)))?;

    let sig_dto: utils::SignatureJson = (&sig).into();
    to_value(&sig_dto).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn pok_nizk_prove_debug(
    params_js: JsValue,
    pk_js: JsValue,
    messages_js: JsValue,
    signature_js: JsValue,
    disclosed_count: usize,
) -> Result<JsValue, JsValue> {
    let mut rng = test_rng();

    let params_dto: utils::ParamsJson =
        from_value(params_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let params: Params = (&params_dto)
        .try_into()
        .map_err(|e: String| JsValue::from_str(&e))?;

    let pk_dto: utils::PublicKeyJson =
        from_value(pk_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let pk: PublicKey = (&pk_dto)
        .try_into()
        .map_err(|e: String| JsValue::from_str(&e))?;

    let msgs_dto: utils::MessagesJson =
        from_value(messages_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let messages: Messages = (&msgs_dto)
        .try_into()
        .map_err(|e: String| JsValue::from_str(&e))?;

    let sig_dto: utils::SignatureJson =
        from_value(signature_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let signature: Signature = (&sig_dto)
        .try_into()
        .map_err(|e: String| JsValue::from_str(&e))?;

    let proof = nizk_prove_prefix(
        &params,
        &pk,
        &messages,
        &signature,
        disclosed_count,
        &mut rng,
    )
    .map_err(|e| JsValue::from_str(&format!("NIZK Prove failed: {}", e)))?;

    let proof_dto: utils::NonInteractiveProofPrefixJson = (&proof).into();
    to_value(&proof_dto).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Sample random Scalar
#[wasm_bindgen]
pub fn sample_random_scalar() -> String {
    let mut rng = thread_rng();
    let scalar = Scalar::rand(&mut rng);
    scalar.to_string()
}
