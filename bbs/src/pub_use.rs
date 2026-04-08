//! Ark dependencies lazy import hare

#![allow(dead_code, unused_imports)]
pub use ark_bn254::{Fr as Scalar, G1Affine as G1, G2Affine as G2};
pub use ark_ec::{AffineRepr, CurveGroup};
pub use ark_ff::Field;
pub use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
