mod utils;

use bbs::bbs_bn254::{
    utils::load_g1_from_json,
    BlindedCommitment, Parameters, PrivateKey, PublicKey, Signature, blind_with_rng, keygen, keygen_with_rng, sign_no_blind_with_rng, verify_no_blind
};
use rand::rngs::OsRng;
use serde_json::json;
use wasm_bindgen::prelude::*;

use utils::{load_from_js, parse_scalar_messages, to_js_json_compatible};

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn bbs_keygen_test(l: u32) -> Result<JsValue, JsValue> {
    let (params, pk, sk) = keygen(l as usize);

    let params_json: serde_json::Value = params.export_to_obj();
    let pk_json: serde_json::Value = pk.export_to_obj();
    let sk_json: serde_json::Value = sk.export_to_obj();
    let obj = json!({
        "params": params_json,
        "pk": pk_json,
        "sk": sk_json,
    });

    to_js_json_compatible(&obj)
}

#[wasm_bindgen]
pub fn bbs_keygen(l: u32) -> Result<JsValue, JsValue> {
    let mut rng = OsRng;
    let (params, pk, sk) = keygen_with_rng(l as usize, &mut rng);

    let params_json: serde_json::Value = params.export_to_obj();
    let pk_json: serde_json::Value = pk.export_to_obj();
    let sk_json: serde_json::Value = sk.export_to_obj();

    let obj = json!({
        "params": params_json,
        "pk": pk_json,
        "sk": sk_json,
    });

    to_js_json_compatible(&obj)
}

#[wasm_bindgen]
pub fn sign_no_blind(params: JsValue, sk: JsValue, messages: JsValue) -> Result<JsValue, JsValue> {
    let mut rng = OsRng;

    let params = load_from_js(params, "params", Parameters::load_from_json)?;
    let sk = load_from_js(sk, "sk", PrivateKey::load_from_json)?;
    let messages = parse_scalar_messages(messages)?;

    let signature = sign_no_blind_with_rng(&params, &sk, &messages, &mut rng)
        .map_err(|e| JsValue::from_str(&format!("signing failed: {e}")))?;

    let signature_json: serde_json::Value = signature.export_to_obj();

    to_js_json_compatible(&signature_json)
}

#[wasm_bindgen]
pub fn verify(
    params: JsValue,
    pk: JsValue,
    messages: JsValue,
    signature: JsValue,
) -> Result<bool, JsValue> {
    let params = load_from_js(params, "params", Parameters::load_from_json)?;
    let pk = load_from_js(pk, "pk", PublicKey::load_from_json)?;
    let signature = load_from_js(signature, "signature", Signature::load_from_json)?;
    let messages = parse_scalar_messages(messages)?;

    verify_no_blind(&params, &pk, &messages, &signature)
        .map_err(|e| JsValue::from_str(&format!("verify failed: {e}")))
}

#[wasm_bindgen]
pub fn blind(params: JsValue, messages: JsValue, blind_index: u32) -> Result<JsValue, JsValue> {
    let params = load_from_js(params, "params", Parameters::load_from_json)?;
    let messages = parse_scalar_messages(messages)?;
    let mut rng = OsRng;

    let blind_index_usize = blind_index as usize;
    let blinded_commitment = blind_with_rng(&params, &messages, &blind_index_usize, &mut rng)
        .map_err(|e| JsValue::from_str(&format!("blinding failed: {e}")))?;

    let blinded_commitment_json: serde_json::Value =
        serde_json::from_str(&blinded_commitment.export()).map_err(|e| {
            JsValue::from_str(&format!("failed to parse blinded commitment json: {e}"))
        })?;

    to_js_json_compatible(&blinded_commitment_json)
}

#[wasm_bindgen]
pub fn unblind(
    params: JsValue,
    signature: JsValue,
    commitment: JsValue,
) -> Result<JsValue, JsValue> {
    let params = load_from_js(params, "params", Parameters::load_from_json)?;
    let signature = load_from_js(signature, "signature", Signature::load_from_json)?;
    let commitment = load_from_js(commitment, "commitment", BlindedCommitment::load_from_json)?;

    let unblinded_signature =
        bbs::bbs_bn254::unblind(&params, &signature, &commitment).map_err(|e| {
            JsValue::from_str(&format!("unblinding failed: {e}"))
        })?;

    let unblinded_signature_json = unblinded_signature.export_to_obj();

    to_js_json_compatible(&unblinded_signature_json)
}

#[wasm_bindgen]
pub fn sign_with_blind(
    params: JsValue,
    sk: JsValue,
    bind_index: u32,
    visual_messages: JsValue,
    commitment: JsValue,
) -> Result<JsValue, JsValue> {
    let mut rng = OsRng;

    let params = load_from_js(params, "params", Parameters::load_from_json)?;
    let sk = load_from_js(sk, "sk", PrivateKey::load_from_json)?;
    let visual_messages = parse_scalar_messages(visual_messages)?;
    let commitment = load_from_js(commitment, "commitment", load_g1_from_json)?;
    let bind_index_usize = bind_index as usize;

    let signature = bbs::bbs_bn254::sign_with_blind_with_rng(&params, &sk, &bind_index_usize, &commitment, &visual_messages, &mut rng)
        .map_err(|e| JsValue::from_str(&format!("signing failed: {e}")))?;

    let signature_json: serde_json::Value = signature.export_to_obj();

    to_js_json_compatible(&signature_json)
}