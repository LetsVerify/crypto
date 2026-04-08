mod utils;

use wasm_bindgen::prelude::*;
use ark_std::test_rng;
use rand::thread_rng;
use bbs::bbs::{keygen as bbs_keygen, setup as bbs_setup, sign as bbs_sign, verify as bbs_verify};
use bbs::pok::{nizk_prove_prefix, nizk_verify_prefix};
use bbs::structs::{Messages, Params, PrivateKey, PublicKey, Signature};
use std::convert::TryInto;
use serde_wasm_bindgen::{from_value, to_value};
use serde::Serialize;

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
        sk: sk_dto
    };
    
    to_value(&keys).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn sign(messages_js: JsValue, params_js: JsValue, sk_js: JsValue) -> Result<JsValue, JsValue> {
    let mut rng = thread_rng();
    
    let msgs_dto: utils::MessagesJson = from_value(messages_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let messages: Messages = (&msgs_dto).try_into().map_err(|e: String| JsValue::from_str(&e))?;
    
    let params_dto: utils::ParamsJson = from_value(params_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let params: Params = (&params_dto).try_into().map_err(|e: String| JsValue::from_str(&e))?;
    
    let sk_dto: utils::PrivateKeyJson = from_value(sk_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let sk: PrivateKey = (&sk_dto).try_into().map_err(|e: String| JsValue::from_str(&e))?;

    let sig = bbs_sign(&messages, &params, &sk, &mut rng)
        .map_err(|e| JsValue::from_str(&format!("Signing failed: {}", e)))?;
        
    let sig_dto: utils::SignatureJson = (&sig).into();
    to_value(&sig_dto).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn verify(messages_js: JsValue, signature_js: JsValue, params_js: JsValue, pk_js: JsValue) -> Result<bool, JsValue> {
    let msgs_dto: utils::MessagesJson = from_value(messages_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let messages: Messages = (&msgs_dto).try_into().map_err(|e: String| JsValue::from_str(&e))?;
    
    let sig_dto: utils::SignatureJson = from_value(signature_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let signature: Signature = (&sig_dto).try_into().map_err(|e: String| JsValue::from_str(&e))?;
    
    let params_dto: utils::ParamsJson = from_value(params_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let params: Params = (&params_dto).try_into().map_err(|e: String| JsValue::from_str(&e))?;
    
    let pk_dto: utils::PublicKeyJson = from_value(pk_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let pk: PublicKey = (&pk_dto).try_into().map_err(|e: String| JsValue::from_str(&e))?;

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
    
    let params_dto: utils::ParamsJson = from_value(params_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let params: Params = (&params_dto).try_into().map_err(|e: String| JsValue::from_str(&e))?;
    
    let pk_dto: utils::PublicKeyJson = from_value(pk_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let pk: PublicKey = (&pk_dto).try_into().map_err(|e: String| JsValue::from_str(&e))?;
    
    let msgs_dto: utils::MessagesJson = from_value(messages_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let messages: Messages = (&msgs_dto).try_into().map_err(|e: String| JsValue::from_str(&e))?;
    
    let sig_dto: utils::SignatureJson = from_value(signature_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let signature: Signature = (&sig_dto).try_into().map_err(|e: String| JsValue::from_str(&e))?;

    let proof = nizk_prove_prefix(&params, &pk, &messages, &signature, disclosed_count, &mut rng)
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
    let params_dto: utils::ParamsJson = from_value(params_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let params: Params = (&params_dto).try_into().map_err(|e: String| JsValue::from_str(&e))?;
    
    let pk_dto: utils::PublicKeyJson = from_value(pk_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let pk: PublicKey = (&pk_dto).try_into().map_err(|e: String| JsValue::from_str(&e))?;
    
    let msgs_dto: utils::MessagesJson = from_value(disclosed_msgs_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let disclosed_msgs: Messages = (&msgs_dto).try_into().map_err(|e: String| JsValue::from_str(&e))?;
    
    let proof_dto: utils::NonInteractiveProofPrefixJson = from_value(proof_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let proof: utils::NonInteractiveProofPrefix = (&proof_dto).try_into().map_err(|e: String| JsValue::from_str(&e))?;

    Ok(nizk_verify_prefix(&params, &pk, &disclosed_msgs.0, &proof))
}

#[wasm_bindgen]
pub fn setup_debug(l: usize) -> Result<JsValue, JsValue> {
    let mut rng = test_rng();
    let params = bbs_setup(l, &mut rng);
    
    let params_dto: utils::ParamsJson = (&params).into();
    to_value(&params_dto).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn keygen_debug() -> Result<JsValue, JsValue> {
    let mut rng = test_rng();
    let (pk, sk) = bbs_keygen(&mut rng);
    
    let pk_dto: utils::PublicKeyJson = (&pk).into();
    let sk_dto: utils::PrivateKeyJson = (&sk).into();
    
    let keys = KeysJson {
        pk: pk_dto,
        sk: sk_dto
    };
    
    to_value(&keys).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn sign_debug(messages_js: JsValue, params_js: JsValue, sk_js: JsValue) -> Result<JsValue, JsValue> {
    let mut rng = test_rng();
    
    let msgs_dto: utils::MessagesJson = from_value(messages_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let messages: Messages = (&msgs_dto).try_into().map_err(|e: String| JsValue::from_str(&e))?;
    
    let params_dto: utils::ParamsJson = from_value(params_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let params: Params = (&params_dto).try_into().map_err(|e: String| JsValue::from_str(&e))?;
    
    let sk_dto: utils::PrivateKeyJson = from_value(sk_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let sk: PrivateKey = (&sk_dto).try_into().map_err(|e: String| JsValue::from_str(&e))?;

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
    
    let params_dto: utils::ParamsJson = from_value(params_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let params: Params = (&params_dto).try_into().map_err(|e: String| JsValue::from_str(&e))?;
    
    let pk_dto: utils::PublicKeyJson = from_value(pk_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let pk: PublicKey = (&pk_dto).try_into().map_err(|e: String| JsValue::from_str(&e))?;
    
    let msgs_dto: utils::MessagesJson = from_value(messages_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let messages: Messages = (&msgs_dto).try_into().map_err(|e: String| JsValue::from_str(&e))?;
    
    let sig_dto: utils::SignatureJson = from_value(signature_js).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let signature: Signature = (&sig_dto).try_into().map_err(|e: String| JsValue::from_str(&e))?;

    let proof = nizk_prove_prefix(&params, &pk, &messages, &signature, disclosed_count, &mut rng)
        .map_err(|e| JsValue::from_str(&format!("NIZK Prove failed: {}", e)))?;
    
    let proof_dto: utils::NonInteractiveProofPrefixJson = (&proof).into();
    to_value(&proof_dto).map_err(|e| JsValue::from_str(&e.to_string()))
}

