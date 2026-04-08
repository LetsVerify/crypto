use ark_bn254::Fr as Scalar;
use bbs_plus::bbs_bn254::{keygen, sign_no_blind, verify_no_blind};
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

fn sample_messages(count: usize) -> Vec<Scalar> {
    (0..count)
        .map(|i| Scalar::from((i as u64) + 1))
        .collect::<Vec<_>>()
}

fn bench_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("bbs_sign");

    for &msg_count in &[2usize, 4, 8, 16] {
        let (params, _pk, sk) = keygen(msg_count);
        let messages = sample_messages(msg_count);

        group.bench_with_input(
            BenchmarkId::from_parameter(msg_count),
            &msg_count,
            |b, _| {
                b.iter(|| {
                    let signature =
                        sign_no_blind(black_box(&params), black_box(&sk), black_box(&messages))
                            .expect("sign_no_blind should succeed for valid inputs");
                    black_box(signature);
                });
            },
        );
    }

    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("bbs_verify");

    for &msg_count in &[2usize, 4, 8, 16] {
        let (params, pk, sk) = keygen(msg_count);
        let messages = sample_messages(msg_count);
        let signature = sign_no_blind(&params, &sk, &messages)
            .expect("sign_no_blind should succeed for valid benchmark input");

        group.bench_with_input(
            BenchmarkId::from_parameter(msg_count),
            &msg_count,
            |b, _| {
                b.iter(|| {
                    let ok = verify_no_blind(
                        black_box(&params),
                        black_box(&pk),
                        black_box(&messages),
                        black_box(&signature),
                    )
                    .expect("verify_no_blind should not fail for valid benchmark input");
                    black_box(ok);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_sign, bench_verify);
criterion_main!(benches);
