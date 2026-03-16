//! Some useful tool funcs

#![allow(non_snake_case)]

use crate::bbs_bn254::structs::Parameters;
use ark_bn254::{Fq, Fq2, G1Affine as G1, G2Affine as G2};
use serde::{Deserialize, Serialize};
use serde_json::{from_str, json};
use std::str::FromStr;

#[derive(Debug)]
pub enum ParamsJsonError {
    InvalidJson(String),
    InvalidField(&'static str),
}

impl std::fmt::Display for ParamsJsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidJson(e) => write!(f, "invalid parameters json: {e}"),
            Self::InvalidField(name) => write!(f, "invalid field: {name}"),
        }
    }
}

impl std::error::Error for ParamsJsonError {}

#[derive(Serialize, Deserialize)]
struct G1Json {
    x: String,
    y: String,
}

#[derive(Serialize, Deserialize)]
struct Fq2Json {
    c0: String,
    c1: String,
}

#[derive(Serialize, Deserialize)]
struct G2Json {
    x: Fq2Json,
    y: Fq2Json,
}

#[derive(Serialize, Deserialize)]
struct ParametersJson {
    L: String,
    g1: G1Json,
    g2: G2Json,
    H: Vec<G1Json>,
}

fn g1_to_json(p: &G1) -> G1Json {
    G1Json {
        x: p.x.to_string(),
        y: p.y.to_string(),
    }
}

fn g1_from_json(p: &G1Json, field: &'static str) -> Result<G1, ParamsJsonError> {
    let x = Fq::from_str(&p.x).map_err(|_| ParamsJsonError::InvalidField(field))?;
    let y = Fq::from_str(&p.y).map_err(|_| ParamsJsonError::InvalidField(field))?;
    Ok(G1::new_unchecked(x, y))
}

impl Parameters {
    pub fn export_to_json(&self) -> String {
        let res = json!({
            "L": self.L.to_string(),
            "g1": {
                "x": self.g1.x.to_string(),
                "y": self.g1.y.to_string(),
            },
            "g2": {
                "x": {
                    "c0": self.g2.x.c0.to_string(),
                    "c1": self.g2.x.c1.to_string(),
                },
                "y": {
                    "c0": self.g2.y.c0.to_string(),
                    "c1": self.g2.y.c1.to_string(),
                },
            },
            "H": self.H.iter().map(g1_to_json).collect::<Vec<_>>()
        });

        res.to_string()
    }

    pub fn load_from_json(s: &str) -> Result<Self, ParamsJsonError> {
        let decoded: ParametersJson =
            from_str(s).map_err(|e| ParamsJsonError::InvalidJson(e.to_string()))?;

        let L = decoded
            .L
            .parse::<usize>()
            .map_err(|_| ParamsJsonError::InvalidField("L"))?;

        let g1 = g1_from_json(&decoded.g1, "g1")?;

        let g2_x_c0 =
            Fq::from_str(&decoded.g2.x.c0).map_err(|_| ParamsJsonError::InvalidField("g2.x.c0"))?;
        let g2_x_c1 =
            Fq::from_str(&decoded.g2.x.c1).map_err(|_| ParamsJsonError::InvalidField("g2.x.c1"))?;
        let g2_y_c0 =
            Fq::from_str(&decoded.g2.y.c0).map_err(|_| ParamsJsonError::InvalidField("g2.y.c0"))?;
        let g2_y_c1 =
            Fq::from_str(&decoded.g2.y.c1).map_err(|_| ParamsJsonError::InvalidField("g2.y.c1"))?;

        let g2 = G2::new_unchecked(Fq2::new(g2_x_c0, g2_x_c1), Fq2::new(g2_y_c0, g2_y_c1));

        let mut H = Vec::with_capacity(decoded.H.len());
        for item in &decoded.H {
            H.push(g1_from_json(item, "H[i]")?);
        }

        Ok(Parameters { L, g1, g2, H })
    }

    // 兼容旧调用：需要时可保留
    pub fn load_from_json_panic(s: &str) -> Self {
        Self::load_from_json(s).expect("failed to parse parameters json")
    }
}