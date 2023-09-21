use anyhow::Context;
use cggmp21::{
    progress::PerfProfiler,
    security_level::{ReasonablySecure, SecurityLevel},
    signing::DataToSign,
    ExecutionId,
};
use rand::Rng;
use rand_dev::DevRng;
use round_based::simulation::Simulation;
use sha2::Sha256;

type E = generic_ec::curves::Secp256k1;
type D = sha2::Sha256;

struct Args {
    n: Vec<u16>,
    bench_primes_gen: bool,
    bench_non_threshold_keygen: bool,
    bench_threshold_keygen: bool,
    bench_aux_data_gen: bool,
    bench_signing: bool,
    optimize_multiexp: bool,
    custom_sec_level: bool,
}

fn args() -> Args {
    use bpaf::Parser;
    let n = bpaf::short('n')
        .help("Amount of parties, comma-separated")
        .argument::<String>("N")
        .parse(|s| s.split(',').map(std::str::FromStr::from_str).collect())
        .fallback(vec![3, 5, 7, 10]);
    let bench_primes_gen = bpaf::long("no-bench-primes-gen").switch().map(|b| !b);
    let bench_non_threshold_keygen = bpaf::long("no-bench-non-threshold-keygen")
        .switch()
        .map(|b| !b);
    let bench_threshold_keygen = bpaf::long("no-bench-threshold-keygen").switch().map(|b| !b);
    let bench_aux_data_gen = bpaf::long("no-bench-aux-data-gen").switch().map(|b| !b);
    let bench_signing = bpaf::long("no-bench-signing").switch().map(|b| !b);
    let optimize_multiexp = bpaf::long("optimize-multiexp").switch();
    let custom_sec_level = bpaf::long("custom-sec-level").switch();

    bpaf::construct!(Args {
        n,
        bench_primes_gen,
        bench_non_threshold_keygen,
        bench_threshold_keygen,
        bench_aux_data_gen,
        bench_signing,
        optimize_multiexp,
        custom_sec_level,
    })
    .to_options()
    .run()
}
#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = args();
    if args.custom_sec_level {
        do_becnhmarks::<CustomSecLevel>(args).await
    } else {
        do_becnhmarks::<ReasonablySecure>(args).await
    }
}

async fn do_becnhmarks<L: SecurityLevel>(args: Args) {
    let mut rng = DevRng::new();

    for n in args.n {
        println!("n = {n}");
        println!();

        if args.bench_primes_gen {
            let start = std::time::Instant::now();
            let _primes =
                std::iter::repeat_with(|| cggmp21::PregeneratedPrimes::<L>::generate(&mut rng))
                    .take(n.into())
                    .collect::<Vec<_>>();
            let took = std::time::Instant::now().duration_since(start);

            println!("Primes generation (avg): {:?}", took / n.into());
            println!();
        }

        let non_threshold_key_shares: Option<Vec<cggmp21::IncompleteKeyShare<E>>> =
            if args.bench_non_threshold_keygen || args.bench_signing {
                let eid: [u8; 32] = rng.gen();
                let eid = ExecutionId::new(&eid);

                let mut simulation =
                    Simulation::<cggmp21::keygen::msg::non_threshold::Msg<E, L, D>>::new();

                let outputs = (0..n).map(|i| {
                    let party = simulation.add_party();
                    let mut party_rng = rng.fork();

                    let mut profiler = PerfProfiler::new();

                    async move {
                        let key_share = cggmp21::keygen(eid, i, n)
                            .set_progress_tracer(&mut profiler)
                            .set_security_level::<L>()
                            .start(&mut party_rng, party)
                            .await
                            .context("keygen failed")?;
                        let report = profiler.get_report().context("get perf report")?;
                        Ok::<_, anyhow::Error>((key_share, report))
                    }
                });

                let outputs = futures::future::try_join_all(outputs)
                    .await
                    .expect("non-threshold keygen failed");

                if args.bench_non_threshold_keygen {
                    println!("Non-threshold DKG");
                    println!("{}", outputs[0].1.clone().display_io(false));
                    println!();
                }

                Some(outputs.into_iter().map(|(k, _)| k).collect())
            } else {
                None
            };

        let _threshold_key_shares: Option<Vec<cggmp21::IncompleteKeyShare<E>>> =
            if args.bench_threshold_keygen {
                let t = n - 1;

                let eid: [u8; 32] = rng.gen();
                let eid = ExecutionId::new(&eid);

                let mut simulation =
                    Simulation::<cggmp21::keygen::msg::threshold::Msg<E, L, D>>::with_capacity(
                        (2 * n * n).into(),
                    );

                let outputs = (0..n).map(|i| {
                    let party = simulation.add_party();
                    let mut party_rng = rng.fork();

                    let mut profiler = PerfProfiler::new();

                    async move {
                        let key_share = cggmp21::keygen(eid, i, n)
                            .set_threshold(t)
                            .set_progress_tracer(&mut profiler)
                            .set_security_level::<L>()
                            .start(&mut party_rng, party)
                            .await
                            .context("keygen failed")?;
                        let report = profiler.get_report().context("get perf report")?;
                        Ok::<_, anyhow::Error>((key_share, report))
                    }
                });

                let outputs = futures::future::try_join_all(outputs)
                    .await
                    .expect("threshold keygen failed");

                println!("Threshold DKG");
                println!("{}", outputs[0].1.clone().display_io(false));
                println!();

                Some(outputs.into_iter().map(|(k, _)| k).collect())
            } else {
                None
            };

        let mut aux_data: Option<Vec<cggmp21::key_share::AuxInfo<L>>> =
            if args.bench_aux_data_gen || args.bench_signing {
                let eid: [u8; 32] = rng.gen();
                let eid = ExecutionId::new(&eid);

                let mut simulation = Simulation::<cggmp21::key_refresh::AuxOnlyMsg<D, L>>::new();

                let mut primes = cggmp21_tests::CACHED_PRIMES.iter::<L>();

                let outputs = (0..n).map(|i| {
                    let party = simulation.add_party();
                    let mut party_rng = rng.fork();
                    let pregen = primes.next().expect("Can't get pregenerated prime");

                    let mut profiler = PerfProfiler::new();

                    async move {
                        let aux_data = cggmp21::aux_info_gen(eid, i, n, pregen)
                            .set_progress_tracer(&mut profiler)
                            .start(&mut party_rng, party)
                            .await
                            .context("aux data gen failed")?;
                        let report = profiler.get_report().context("get perf report")?;
                        Ok::<_, anyhow::Error>((aux_data, report))
                    }
                });

                let outputs = futures::future::try_join_all(outputs)
                    .await
                    .expect("key refresh failed");

                if args.bench_aux_data_gen {
                    println!("Auxiliary data generation protocol");
                    println!("{}", outputs[0].1.clone().display_io(false));
                    println!();
                }

                Some(outputs.into_iter().map(|(a, _)| a).collect())
            } else {
                None
            };

        if aux_data.is_some() && args.optimize_multiexp {
            let aux_data = aux_data.as_mut().unwrap();
            let start = std::time::Instant::now();
            aux_data
                .iter_mut()
                .for_each(|aux_i| aux_i.precompute_multiexp_tables().unwrap());
            let took = std::time::Instant::now().duration_since(start);

            println!("Precompute multiexp tables (avg): {:?}", took / n.into());
            println!(
                "Size of multiexp tables per key share: {} bytes",
                aux_data[0].multiexp_tables_size()
            );
            println!(
                "Size of exponents: {:?}",
                cggmp21::security_level::max_exponents_size::<L>()
            );
            println!();
        }

        if args.bench_signing {
            // Note that we don't parametrize signing performance tests by `t` as it doesn't make much sense
            // since performance of t-out-of-n protocol should be roughly the same as t-out-of-t
            let shares = non_threshold_key_shares
                .expect("non threshold key shares are not generated")
                .into_iter()
                .zip(aux_data.expect("aux data is not generated"))
                .map(|(key_share, aux_data)| cggmp21::KeyShare::make(key_share, aux_data))
                .collect::<Result<Vec<_>, _>>()
                .expect("couldn't complete a share");

            let eid: [u8; 32] = rng.gen();
            let eid = ExecutionId::new(&eid);

            let signers_indexes_at_keygen = &(0..n).collect::<Vec<_>>();

            let message_to_sign = b"Dfns rules!";
            let message_to_sign = DataToSign::digest::<Sha256>(message_to_sign);

            use cggmp21::signing::msg::Msg;
            let mut simulation = Simulation::<Msg<E, D>>::new();

            let mut outputs = vec![];
            for (i, share) in (0..).zip(&shares) {
                let party = simulation.add_party();
                let mut party_rng = rng.fork();

                let mut profiler = PerfProfiler::new();

                outputs.push(async move {
                    let _signature = cggmp21::signing(eid, i, signers_indexes_at_keygen, share)
                        .set_progress_tracer(&mut profiler)
                        .sign(&mut party_rng, party, message_to_sign)
                        .await
                        .context("signing failed")?;
                    profiler.get_report().context("get perf report")
                })
            }

            let perf_reports = futures::future::try_join_all(outputs)
                .await
                .expect("signing failed");

            println!("Signing protocol");
            println!("{}", perf_reports[0].clone().display_io(false));
            println!();
        }
    }
}

#[derive(Clone, Copy)]
struct CustomSecLevel;
cggmp21::define_security_level!(CustomSecLevel {
    security_bits = 384,
    epsilon = 220,
    ell = 256,
    ell_prime = 824,
    m = 128,
    q = cggmp21::rug::Integer::ONE.clone() << 128,
});
