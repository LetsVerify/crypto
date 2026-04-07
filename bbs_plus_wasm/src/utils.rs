use ark_bn254::Fr as Scalar;
use serde::Serialize;
use std::{fmt::Display, str::FromStr};
use wasm_bindgen::JsValue;

pub fn to_js_json_compatible<T: Serialize>(value: &T) -> Result<JsValue, JsValue> {
    let serializer = serde_wasm_bindgen::Serializer::json_compatible();
    value
        .serialize(&serializer)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

pub fn js_to_json(value: JsValue, name: &str) -> Result<serde_json::Value, JsValue> {
    serde_wasm_bindgen::from_value(value)
        .map_err(|e| JsValue::from_str(&format!("failed to deserialize {name}: {e}")))
}

pub fn load_from_js<T, F, E>(value: JsValue, name: &str, loader: F) -> Result<T, JsValue>
where
    F: FnOnce(&str) -> Result<T, E>,
    E: Display,
{
    let v = js_to_json(value, name)?;
    loader(&v.to_string()).map_err(|e| JsValue::from_str(&format!("failed to load {name}: {e}")))
}

pub fn parse_scalar_messages(messages: JsValue) -> Result<Vec<Scalar>, JsValue> {
    let message_values: Vec<serde_json::Value> = serde_wasm_bindgen::from_value(messages)
        .map_err(|e| JsValue::from_str(&format!("failed to deserialize messages: {e}")))?;

    message_values
        .iter()
        .enumerate()
        .map(|(idx, v)| {
            let raw = match v {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Number(n) => n.to_string(),
                _ => {
                    return Err(JsValue::from_str(&format!(
                        "message[{idx}] must be string/number"
                    )));
                }
            };

            Scalar::from_str(&raw)
                .map_err(|_| JsValue::from_str(&format!("invalid scalar at message[{idx}]")))
        })
        .collect::<Result<Vec<_>, _>>()
}
