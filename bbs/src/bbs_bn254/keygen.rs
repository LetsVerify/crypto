/// This is the key generation module for the BBS+ signature scheme over the BN254 curve.
/// Provides functions to generate secret keys, public keys, and key pairs for signing and verification.

use ark_bn254::{G1Affine as G1, G2Affine as G2, Fr as Scalar};
use ark_ec::{AffineRepr, CurveGroup};
use ark_std::{rand::RngCore, UniformRand};

use super::structs::{Parameters, PrivateKey, PublicKey};

/// Generate public parameters, private key, and public key for BBS+.
///
/// Returns `(parameters, public_key, private_key)`.
pub fn keygen(message_count: usize) -> (Parameters, PublicKey, PrivateKey) {
	let mut rng = ark_std::test_rng();
	keygen_with_rng(message_count, &mut rng)
}

/// Same as `keygen`, but uses a caller-supplied RNG.
pub fn keygen_with_rng<R: RngCore>(message_count: usize, rng: &mut R) -> (Parameters, PublicKey, PrivateKey) {
	let g1 = G1::generator();
	let g2 = G2::generator();

	let mut h = Vec::with_capacity(message_count + 1);
	for _ in 0..=message_count {
		h.push(G1::rand(rng));
	}

	let x = Scalar::rand(rng);
	let w = (g2 * x).into_affine();

	let params = Parameters {
		L: message_count,
		g1,
		g2,
	H: h,
	};

	let pk = PublicKey { w };
	let sk = PrivateKey { x };

	(params, pk, sk)
}

#[cfg(test)]
mod tests {
	use super::*;
	use ark_std::Zero;

	#[test]
	fn keygen_produces_expected_sizes() {
		let (params, pk, sk) = keygen(3);
		assert_eq!(params.L, 3);
		assert_eq!(params.H.len(), 4);
		assert!(!params.g1.is_zero());
		assert!(!params.g2.is_zero());
		assert!(!pk.w.is_zero());
		assert!(!sk.x.is_zero());
	}
}