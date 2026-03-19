//! Some useful tool funcs

#![allow(non_snake_case, dead_code)]

use crate::bbs_bn254::{
    PrivateKey,
    structs::{Parameters, Signature},
};
use ark_bn254::{Fq, Fq2, Fr as Scalar, G1Affine as G1, G2Affine as G2};
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

#[derive(Serialize, Deserialize)]
struct SignatureJson {
    A: G1Json,
    e: String,
    s: String,
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

fn fq2_to_json(p: &Fq2) -> Fq2Json {
    Fq2Json {
        c0: p.c0.to_string(),
        c1: p.c1.to_string(),
    }
}

fn fq2_from_json(p: &Fq2Json, field: &'static str) -> Result<Fq2, ParamsJsonError> {
    let c0 = Fq::from_str(&p.c0).map_err(|_| ParamsJsonError::InvalidField(field))?;
    let c1 = Fq::from_str(&p.c1).map_err(|_| ParamsJsonError::InvalidField(field))?;
    Ok(Fq2::new(c0, c1))
}

fn g2_to_json(p: &G2) -> G2Json {
    G2Json {
        x: fq2_to_json(&p.x),
        y: fq2_to_json(&p.y),
    }
}

fn g2_from_json(p: &G2Json, field: &'static str) -> Result<G2, ParamsJsonError> {
    let x_c0 = Fq::from_str(&p.x.c0).map_err(|_| ParamsJsonError::InvalidField(field))?;
    let x_c1 = Fq::from_str(&p.x.c1).map_err(|_| ParamsJsonError::InvalidField(field))?;
    let y_c0 = Fq::from_str(&p.y.c0).map_err(|_| ParamsJsonError::InvalidField(field))?;
    let y_c1 = Fq::from_str(&p.y.c1).map_err(|_| ParamsJsonError::InvalidField(field))?;
    Ok(G2::new_unchecked(
        Fq2::new(x_c0, x_c1),
        Fq2::new(y_c0, y_c1),
    ))
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

        let g2 = g2_from_json(&decoded.g2, "g2")?;

        let mut H = Vec::with_capacity(decoded.H.len());
        for item in &decoded.H {
            H.push(g1_from_json(item, "H[i]")?);
        }

        Ok(Parameters { L, g1, g2, H })
    }
}

impl Signature {
    pub fn export_to_json(&self) -> String {
        let res = json!({
            "A": {
                "x": self.A.x.to_string(),
                "y": self.A.y.to_string(),
            },
            "e": self.e.to_string(),
            "s": self.s.to_string(),
        });

        res.to_string()
    }

    pub fn load_from_json(s: &str) -> Result<Self, ParamsJsonError> {
        let decoded: SignatureJson =
            from_str(s).map_err(|e| ParamsJsonError::InvalidJson(e.to_string()))?;

        let A = g1_from_json(&decoded.A, "A")?;
        let e = decoded
            .e
            .parse::<Scalar>()
            .map_err(|_| ParamsJsonError::InvalidField("e"))?;
        let s = decoded
            .s
            .parse::<Scalar>()
            .map_err(|_| ParamsJsonError::InvalidField("s"))?;

        Ok(Signature { A, e, s })
    }
}

impl PrivateKey {
    pub fn export_to_json(&self) -> String {
        json!({
            "x": self.x.to_string(),
        })
        .to_string()
    }

    pub fn load_from_json(s: &str) -> Result<Self, ParamsJsonError> {
        let decoded: serde_json::Value =
            from_str(s).map_err(|e| ParamsJsonError::InvalidJson(e.to_string()))?;
        let x_str = decoded
            .get("x")
            .and_then(|v| v.as_str())
            .ok_or(ParamsJsonError::InvalidField("x"))?;
        let x = Scalar::from_str(x_str).unwrap();
        Ok(PrivateKey { x })
    }
}
