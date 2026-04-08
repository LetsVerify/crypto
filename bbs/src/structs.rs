//! Define the core data structures here.

#![allow(non_snake_case, dead_code, unused_imports)]
use ark_bn254::{Fr as Scalar, G1Affine as G1, G2Affine as G2, g2};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_ff::Field;
use serde::{Deserialize, Serialize, de};

use crate::modified_serde::*;

/// BBS signature params
/// + `G1` generator 
/// + `G2` generator
/// + `L` the length of messages
/// + `H` message base point
#[derive(Serialize,Deserialize, Debug)]
pub struct Params {
    #[serde(serialize_with = "serialize_g1", deserialize_with = "deserialize_g1")]
    pub G1: G1,
    #[serde(serialize_with = "serialize_g2",deserialize_with = "deserialize_g2")]
    pub G2: G2,
    pub L: usize,
    #[serde(serialize_with = "serialize_vec_g1",deserialize_with="deserialize_vec_g1")]
    pub H: Vec<G1>,
}

/// Private key
/// `x`: the secret, Scalar
#[derive(Serialize, Deserialize, Debug)]
pub struct PrivateKey {
    #[serde(serialize_with = "serialize_scalar", deserialize_with = "deserialize_scalar")]
    pub x: Scalar,
}


/// Publc key
/// `X`: the public key point in G2, X = x*G2
#[derive(Serialize, Deserialize, Debug)]
pub struct PublicKey {
    #[serde(serialize_with = "serialize_g2",deserialize_with = "deserialize_g2")]
    pub X: G2
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Messages (
    #[serde(serialize_with = "serialize_vec_scalar",deserialize_with="deserialize_vec_scalar")]
    pub Vec<Scalar>
);

/// Signature 
/// + `A`: the signature point in G1
/// + `e`: random scalar in Scalar
#[derive(Serialize, Deserialize, Debug)]
pub struct Signature {
    #[serde(serialize_with = "serialize_g1",deserialize_with = "deserialize_g1")]
    pub A: G1,
    #[serde(serialize_with = "serialize_scalar", deserialize_with = "deserialize_scalar")]
    pub e: Scalar,
}