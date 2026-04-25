#![allow(non_snake_case, dead_code)]

use ark_bn254::{Fq, Fq2, Fr as Scalar, G1Affine as G1, G2Affine as G2};
use bbs::structs::{Messages, Params, PrivateKey, PublicKey, Signature};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    console_error_panic_hook::set_once();
}

#[derive(Serialize, Deserialize)]
pub struct G1Json {
    pub x: String,
    pub y: String,
}

#[derive(Serialize, Deserialize)]
pub struct Fq2Json {
    pub c0: String,
    pub c1: String,
}

#[derive(Serialize, Deserialize)]
pub struct G2Json {
    pub x: Fq2Json,
    pub y: Fq2Json,
}

pub fn g1_to_json(p: &G1) -> G1Json {
    G1Json {
        x: p.x.to_string(),
        y: p.y.to_string(),
    }
}

pub fn g1_from_json(p: &G1Json) -> Result<G1, String> {
    let x = Fq::from_str(&p.x).map_err(|_| format!("Invalid x: {}", p.x))?;
    let y = Fq::from_str(&p.y).map_err(|_| format!("Invalid y: {}", p.y))?;
    Ok(G1::new_unchecked(x, y))
#![allow(non_snake_case, dead_code)]

use ark_bn254::{Fq, Fq2, Fr as Scalar, G1Affine as G1, G2Affine as G2};
use bbs::structs::{Messages, Params, PrivateKey, PublicKey, Signature};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    console_error_panic_hook::set_once();
}

#[derive(Serialize, Deserialize)]
pub struct G1Json {
    pub x: String,
    pub y: String,
}

#[derive(Serialize, Deserialize)]
pub struct Fq2Json {
    pub c0: String,
    pub c1: String,
}

#[derive(Serialize, Deserialize)]
pub struct G2Json {
    pub x: Fq2Json,
    pub y: Fq2Json,
}

pub fn g1_to_json(p: &G1) -> G1Json {
    G1Json {
        x: p.x.to_string(),
        y: p.y.to_string(),
    }
}

pub fn g1_from_json(p: &G1Json) -> Result<G1, String> {
    let x = Fq::from_str(&p.x).map_err(|_| format!("Invalid x: {}", p.x))?;
    let y = Fq::from_str(&p.y).map_err(|_| format!("Invalid y: {}", p.y))?;
    Ok(G1::new_unchecked(x, y))
}

pub fn fq2_to_json(p: &Fq2) -> Fq2Json {
    Fq2Json {
        c0: p.c0.to_string(),
        c1: p.c1.to_string(),
    }
}

pub fn fq2_from_json(p: &Fq2Json) -> Result<Fq2, String> {
    let c0 = Fq::from_str(&p.c0).map_err(|_| "Invalid c0")?;
    let c1 = Fq::from_str(&p.c1).map_err(|_| "Invalid c1")?;
    Ok(Fq2::new(c0, c1))
}

pub fn g2_to_json(p: &G2) -> G2Json {
    G2Json {
        x: fq2_to_json(&p.x),
        y: fq2_to_json(&p.y),
    }
}

pub fn g2_from_json(p: &G2Json) -> Result<G2, String> {
    let x_c0 = Fq::from_str(&p.x.c0).map_err(|_| "Invalid x.c0")?;
    let x_c1 = Fq::from_str(&p.x.c1).map_err(|_| "Invalid x.c1")?;
    let y_c0 = Fq::from_str(&p.y.c0).map_err(|_| "Invalid y.c0")?;
    let y_c1 = Fq::from_str(&p.y.c1).map_err(|_| "Invalid y.c1")?;
    Ok(G2::new_unchecked(
        Fq2::new(x_c0, x_c1),
        Fq2::new(y_c0, y_c1),
    ))
}

#[derive(Serialize, Deserialize)]
pub struct ParamsJson {
    pub G1: G1Json,
    pub G2: G2Json,
    pub L: usize,
    pub H: Vec<G1Json>,
}

impl From<&Params> for ParamsJson {
    fn from(params: &Params) -> Self {
        Self {
            G1: g1_to_json(&params.G1),
            G2: g2_to_json(&params.G2),
            L: params.L,
            H: params.H.iter().map(g1_to_json).collect(),
        }
    }
}
impl TryFrom<&ParamsJson> for Params {
    type Error = String;
    fn try_from(dto: &ParamsJson) -> Result<Self, Self::Error> {
        Ok(Params {
            G1: g1_from_json(&dto.G1)?,
            G2: g2_from_json(&dto.G2)?,
            L: dto.L,
            H: dto
                .H
                .iter()
                .map(g1_from_json)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub struct PrivateKeyJson {
    pub x: String,
}

impl From<&PrivateKey> for PrivateKeyJson {
    fn from(sk: &PrivateKey) -> Self {
        Self {
            x: sk.x.to_string(),
        }
    }
}
impl TryFrom<&PrivateKeyJson> for PrivateKey {
    type Error = String;
    fn try_from(dto: &PrivateKeyJson) -> Result<Self, Self::Error> {
        Ok(PrivateKey {
            x: Scalar::from_str(&dto.x).map_err(|_| "Invalid x")?,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub struct PublicKeyJson {
    pub X: G2Json,
}

impl From<&PublicKey> for PublicKeyJson {
    fn from(pk: &PublicKey) -> Self {
        Self {
            X: g2_to_json(&pk.X),
        }
    }
}
impl TryFrom<&PublicKeyJson> for PublicKey {
    type Error = String;
    fn try_from(dto: &PublicKeyJson) -> Result<Self, Self::Error> {
        Ok(PublicKey {
            X: g2_from_json(&dto.X)?,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub struct SignatureJson {
    pub A: G1Json,
    pub e: String,
}

impl From<&Signature> for SignatureJson {
    fn from(sig: &Signature) -> Self {
        Self {
            A: g1_to_json(&sig.A),
            e: sig.e.to_string(),
        }
    }
}
impl TryFrom<&SignatureJson> for Signature {
    type Error = String;
    fn try_from(dto: &SignatureJson) -> Result<Self, Self::Error> {
        Ok(Signature {
            A: g1_from_json(&dto.A)?,
            e: Scalar::from_str(&dto.e).map_err(|_| "Invalid e")?,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub struct MessagesJson(pub Vec<String>);

impl From<&Messages> for MessagesJson {
    fn from(msgs: &Messages) -> Self {
        Self(msgs.0.iter().map(|s| s.to_string()).collect())
    }
}
impl TryFrom<&MessagesJson> for Messages {
    type Error = String;
    fn try_from(dto: &MessagesJson) -> Result<Self, Self::Error> {
        let scalars = dto
            .0
            .iter()
            .map(|s| Scalar::from_str(s).map_err(|_| format!("Invalid scalar {}", s)))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Messages(scalars))
    }
}

pub use bbs::pok::NonInteractiveProofPrefix;

#[derive(Serialize, Deserialize)]
pub struct NonInteractiveProofPrefixJson {
    pub A_bar: G1Json,
    pub B_bar: G1Json,
    pub U: G1Json,
    pub s: String,
    pub t: String,
    pub u_i: Vec<String>,
}

impl From<&NonInteractiveProofPrefix> for NonInteractiveProofPrefixJson {
    fn from(proof: &NonInteractiveProofPrefix) -> Self {
        Self {
            A_bar: g1_to_json(&proof.A_bar),
            B_bar: g1_to_json(&proof.B_bar),
            U: g1_to_json(&proof.U),
            s: proof.s.to_string(),
            t: proof.t.to_string(),
            u_i: proof.u_i.iter().map(|s| s.to_string()).collect(),
        }
    }
}
impl TryFrom<&NonInteractiveProofPrefixJson> for NonInteractiveProofPrefix {
    type Error = String;
    fn try_from(dto: &NonInteractiveProofPrefixJson) -> Result<Self, Self::Error> {
        Ok(NonInteractiveProofPrefix {
            A_bar: g1_from_json(&dto.A_bar)?,
            B_bar: g1_from_json(&dto.B_bar)?,
            U: g1_from_json(&dto.U)?,
            s: Scalar::from_str(&dto.s).map_err(|_| "Invalid s")?,
            t: Scalar::from_str(&dto.t).map_err(|_| "Invalid t")?,
            u_i: dto
                .u_i
                .iter()
                .map(|s| Scalar::from_str(s).map_err(|_| "Invalid u_i"))
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

use bbs::extend_structs::{UserCommitment, PartialSignature};

#[derive(Serialize, Deserialize)]
pub struct UserCommitmentJson {
    pub C2: G1Json,
}

impl From<&UserCommitment> for UserCommitmentJson {
    fn from(commit: &UserCommitment) -> Self {
        Self {
            C2: g1_to_json(&commit.C2),
        }
    }
}

impl TryFrom<&UserCommitmentJson> for UserCommitment {
    type Error = String;
    fn try_from(dto: &UserCommitmentJson) -> Result<Self, Self::Error> {
        Ok(UserCommitment {
            C2: g1_from_json(&dto.C2)?,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub struct PartialSignatureJson {
    pub A1: G1Json,
    pub A2_prime: G1Json,
    pub e: String,
}

impl From<&PartialSignature> for PartialSignatureJson {
    fn from(sig: &PartialSignature) -> Self {
        Self {
            A1: g1_to_json(&sig.A1),
            A2_prime: g1_to_json(&sig.A2_prime),
            e: sig.e.to_string(),
        }
    }
}

impl TryFrom<&PartialSignatureJson> for PartialSignature {
    type Error = String;
    fn try_from(dto: &PartialSignatureJson) -> Result<Self, Self::Error> {
        Ok(PartialSignature {
            A1: g1_from_json(&dto.A1)?,
            A2_prime: g1_from_json(&dto.A2_prime)?,
            e: Scalar::from_str(&dto.e).map_err(|_| "Invalid e")?,
        })
    }
}
