use cggmp24::{
    backend,
    security_level::{SecurityLevel, SecurityLevel128},
};
use generic_ec::{curves::Secp256k1 as E, Point, Scalar};

fn criterion_benchmark(c: &mut criterion::Criterion) {
    let mut rng = rand_dev::DevRng::new();
    c.bench_function("scalar at point mult (secp256k1)", |b| {
        b.iter_batched(
            || {
                let base = Point::generator() * Scalar::<E>::random(&mut rng);
                let exp = Scalar::<E>::random(&mut rng);
                (base, exp)
            },
            |(base, exp)| base * exp,
            criterion::BatchSize::SmallInput,
        )
    });

    let primes = cggmp24_tests::CACHED_PRIMES
        .iter::<SecurityLevel128>()
        .next()
        .unwrap();
    let [p, q, _, _] = primes.into_primes();
    let n = p * q;

    let bits = [
        256, // something close to the curve order
        SecurityLevel128::ELL + SecurityLevel128::EPSILON,
        SecurityLevel128::ELL_PRIME + SecurityLevel128::EPSILON,
    ];
    for bits in bits {
        let bits: u32 = bits.try_into().unwrap();
        c.bench_function(&format!("x^e mod N, |e| = {bits}"), |b| {
            b.iter_batched(
                || {
                    let base = backend::Integer::random_below_ref(&n, &mut rng).into();
                    let exp = backend::Integer::random_bits(bits, &mut rng).into();
                    (base, exp)
                },
                |(base, exp): (backend::Integer, backend::Integer)| base.pow_mod(&exp, &n).unwrap(),
                criterion::BatchSize::SmallInput,
            )
        });
    }

    let bits = [
        256, // something close to the curve order
        // SecurityLevel128::ELL, -- don't need it, ell = 256 is a repetition
        SecurityLevel128::ELL + SecurityLevel128::EPSILON,
        n.significant_bits().try_into().unwrap(),
    ];
    let nn = n.square_ref();
    for bits in bits {
        let bits: u32 = bits.try_into().unwrap();
        c.bench_function(&format!("x^e mod N^2, |e| = {bits}"), |b| {
            b.iter_batched(
                || {
                    let x = backend::Integer::random_below_ref(&nn, &mut rng).into();
                    let e = backend::Integer::random_bits(bits, &mut rng).into();
                    (x, e)
                },
                |(x, e): (backend::Integer, backend::Integer)| x.pow_mod(&e, &nn).unwrap(),
                criterion::BatchSize::SmallInput,
            )
        });
    }
}

criterion::criterion_group!(benches, criterion_benchmark);
criterion::criterion_main!(benches);
