use ark_bn254::{Fr as Scalar, G1Affine as G1, G2Affine as G2};
use ark_ec::{AffineRepr, CurveGroup};
use ark_std::{test_rng, UniformRand};
use bbs::extend::BBSPlusExtendedScheme;
use bbs::pok::{nizk_prove_prefix, nizk_verify_prefix};
use bbs::structs::{Messages, Params, PublicKey};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

fn bench_bbs_phases(c: &mut Criterion) {
    let mut rng = test_rng();

    // Base parameters setup
    let g1 = G1::generator();
    let g2 = G2::generator();

    let mut group = c.benchmark_group("BBS_Extended_Scheme");

    // Evaluate over different numbers of public attributes (e.g. 5, 10, 20)
    for num_public_attributes in [5, 10, 20].iter() {
        let total_messages = num_public_attributes + 2; // +1 for m_null, +1 for m_gamma
        let mut h_bases = Vec::with_capacity(total_messages);
        for _ in 0..total_messages {
            h_bases.push(G1::rand(&mut rng));
        }

        let params = Params {
            G1: g1,
            G2: g2,
            L: total_messages,
            H: h_bases.clone(),
        };

        // ---------------------------------------------------------
        // 1. Key Generation
        // ---------------------------------------------------------
        group.bench_with_input(BenchmarkId::new("Key_Generation", num_public_attributes), num_public_attributes, |b, _| {
            b.iter(|| {
                let sk = Scalar::rand(&mut rng);
                let pk_point = (g2 * sk).into_affine();
                black_box(PublicKey { X: pk_point });
            });
        });

        // Initialize variables for the next phases
        let sk = Scalar::rand(&mut rng);
        let pk = PublicKey { X: (g2 * sk).into_affine() };

        let mut messages_vec = Vec::with_capacity(total_messages);
        for _ in 0..*num_public_attributes {
            messages_vec.push(Scalar::rand(&mut rng));
        }
        let m_null = Scalar::rand(&mut rng);
        let m_gamma = Scalar::rand(&mut rng);
        let lambda = Scalar::rand(&mut rng);

        messages_vec.push(m_null);
        messages_vec.push(m_gamma);
        let messages = Messages(messages_vec.clone());

        // ---------------------------------------------------------
        // 2. Issue Phase (Commit + Sign + Unblind)
        // ---------------------------------------------------------
        group.bench_with_input(BenchmarkId::new("Signature_Issuance", num_public_attributes), num_public_attributes, |b, num_pub| {
            b.iter(|| {
                let user_commitment = BBSPlusExtendedScheme::user_commit(
                    &m_null,
                    &m_gamma,
                    &lambda,
                    &h_bases,
                );

                let public_messages = &messages_vec[..*num_pub];
                let partial_sig = BBSPlusExtendedScheme::signer_sign(
                    &mut rng,
                    &sk,
                    public_messages,
                    &h_bases,
                    &g1,
                    &user_commitment.C2,
                );

                let full_signature = BBSPlusExtendedScheme::user_unblind(&partial_sig, &lambda);
                black_box(full_signature);
            });
        });

        // Pre-compute full signature for proof gen
        let user_commitment = BBSPlusExtendedScheme::user_commit(&m_null, &m_gamma, &lambda, &h_bases);
        let public_messages = &messages_vec[..*num_public_attributes];
        let partial_sig = BBSPlusExtendedScheme::signer_sign(&mut rng, &sk, public_messages, &h_bases, &g1, &user_commitment.C2);
        let full_signature = BBSPlusExtendedScheme::user_unblind(&partial_sig, &lambda);

        // ---------------------------------------------------------
        // 3. Proof Generation
        // ---------------------------------------------------------
        // Disclose all public messages + m_null. Hide m_gamma.
        let disclosed_count = *num_public_attributes + 1;
        let ctx = b"LetsVerify";

        group.bench_with_input(BenchmarkId::new("Proof_Generation", num_public_attributes), num_public_attributes, |b, _| {
            b.iter(|| {
                let proof = nizk_prove_prefix(
                    ctx,
                    &params,
                    &pk,
                    &messages,
                    &full_signature,
                    disclosed_count,
                    &mut rng,
                ).unwrap();
                black_box(proof);
            });
        });
        
        // ---------------------------------------------------------
        // 4. Proof Verification (Off-chain)
        // ---------------------------------------------------------
        let proof = nizk_prove_prefix(ctx, &params, &pk, &messages, &full_signature, disclosed_count, &mut rng).unwrap();
        let disclosed_msgs = &messages_vec[..disclosed_count];

        group.bench_with_input(BenchmarkId::new("Proof_Verification_OffChain", num_public_attributes), num_public_attributes, |b, _| {
            b.iter(|| {
                let is_valid = nizk_verify_prefix(
                    ctx,
                    &params,
                    &pk,
                    disclosed_msgs,
                    &proof,
                );
                black_box(is_valid);
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_bbs_phases);
criterion_main!(benches);