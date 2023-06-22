use anyhow::Context;
use cggmp21::{progress::PerfProfiler, signing::DataToSign, ExecutionId};
use rand::Rng;
use rand_dev::DevRng;
use round_based::simulation::Simulation;
use sha2::Sha256;

type E = generic_ec::curves::Secp256k1;
type L = cggmp21::security_level::ReasonablySecure;
type D = sha2::Sha256;

struct Args {
    n: Vec<u16>,
    bench_non_threshold_keygen: bool,
    bench_threshold_keygen: bool,
    bench_refresh: bool,
    bench_signing: bool,
}

fn args() -> Args {
    use bpaf::Parser;
    let n = bpaf::short('n')
        .help("Amount of parties, comma-separated")
        .argument::<String>("N")
        .parse(|s| s.split(',').map(std::str::FromStr::from_str).collect())
        .fallback(vec![3, 5, 7, 10]);
    let bench_non_threshold_keygen = bpaf::long("no-bench-non-threshold-keygen")
        .switch()
        .map(|b| !b);
    let bench_threshold_keygen = bpaf::long("no-bench-threshold-keygen").switch().map(|b| !b);
    let bench_refresh = bpaf::long("no-bench-refresh").switch().map(|b| !b);
    let bench_signing = bpaf::long("no-bench-signing").switch().map(|b| !b);

    bpaf::construct!(Args {
        n,
        bench_non_threshold_keygen,
        bench_threshold_keygen,
        bench_refresh,
        bench_signing
    })
    .to_options()
    .run()
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = args();
    let mut rng = DevRng::new();

    for n in args.n {
        println!("n = {n}");
        println!();

        if args.bench_non_threshold_keygen {
            let eid: [u8; 32] = rng.gen();
            let eid = ExecutionId::new(&eid);

            let mut simulation =
                Simulation::<cggmp21::keygen::msg::non_threshold::Msg<E, L, D>>::new();

            let outputs = (0..n).map(|i| {
                let party = simulation.add_party();
                let mut party_rng = rng.fork();

                let mut profiler = PerfProfiler::new();

                async move {
                    let _key_share = cggmp21::keygen(eid, i, n)
                        .set_progress_tracer(&mut profiler)
                        .start(&mut party_rng, party)
                        .await
                        .context("keygen failed")?;
                    profiler.get_report().context("get perf report")
                }
            });

            let perf_reports = futures::future::try_join_all(outputs)
                .await
                .expect("non-threshold keygen failed");

            println!("Non-threshold DKG");
            println!("{}", perf_reports[0].clone().display_io(false));
            println!();
        }

        if args.bench_threshold_keygen && n > 2 {
            let t = n - 1;

            let eid: [u8; 32] = rng.gen();
            let eid = ExecutionId::new(&eid);

            let mut simulation = Simulation::<cggmp21::keygen::msg::threshold::Msg<E, L, D>>::new();

            let outputs = (0..n).map(|i| {
                let party = simulation.add_party();
                let mut party_rng = rng.fork();

                let mut profiler = PerfProfiler::new();

                async move {
                    let _key_share = cggmp21::keygen(eid, i, n)
                        .set_threshold(t)
                        .set_progress_tracer(&mut profiler)
                        .start(&mut party_rng, party)
                        .await
                        .context("keygen failed")?;
                    profiler.get_report().context("get perf report")
                }
            });

            let perf_reports = futures::future::try_join_all(outputs)
                .await
                .expect("threshold keygen failed");

            println!("Threshold DKG");
            println!("{}", perf_reports[0].clone().display_io(false));
            println!();
        }

        if args.bench_refresh {
            let shares = cggmp21_tests::CACHED_SHARES
                .get_shares::<E, L>(None, n)
                .expect("retrieve key shares from cache");

            let eid: [u8; 32] = rng.gen();
            let eid = ExecutionId::new(&eid);

            let mut simulation =
                Simulation::<cggmp21::key_refresh::NonThresholdMsg<E, D, L>>::new();

            let mut primes = cggmp21_tests::CACHED_PRIMES.iter();

            let outputs = shares.iter().map(|share| {
                let party = simulation.add_party();
                let mut party_rng = rng.fork();
                let pregen = primes.next().expect("Can't get pregenerated prime");

                let mut profiler = PerfProfiler::new();

                async move {
                    let _new_share = cggmp21::key_refresh(eid, share, pregen)
                        .set_progress_tracer(&mut profiler)
                        .start(&mut party_rng, party)
                        .await
                        .context("refresh failed")?;
                    profiler.get_report().context("get perf report")
                }
            });

            let perf_reports = futures::future::try_join_all(outputs)
                .await
                .expect("key refresh failed");

            println!("Key refresh protocol");
            println!("{}", perf_reports[0].clone().display_io(false));
            println!();
        }

        if args.bench_signing {
            // Note that we don't parametrize signing performance tests by `t` as it doesn't make much sense
            // since performance of t-out-of-n protocol should be roughly the same as t-out-of-t
            let shares = cggmp21_tests::CACHED_SHARES
                .get_shares::<E, L>(None, n)
                .expect("retrieve key shares from cache");

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
