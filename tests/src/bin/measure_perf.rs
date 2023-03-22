use anyhow::Context;
use cggmp21::{progress::PerfProfiler, signing::Message, ExecutionId};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rand_dev::DevRng;
use round_based::simulation::Simulation;
use sha2::Sha256;

type E = generic_ec::curves::Secp256r1;
type L = cggmp21::security_level::ReasonablySecure;
type D = sha2::Sha256;

struct Args {
    n: Vec<u16>,
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
    let bench_refresh = bpaf::long("no-bench-refresh").switch().map(|b| !b);
    let bench_signing = bpaf::long("no-bench-signing").switch().map(|b| !b);

    bpaf::construct!(Args {
        n,
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

    // Note that we don't parametrize performance tests by `t` as it doesn't make much sense
    // since performance of t-out-of-n protocol should be roughly the same as t-out-of-t
    for n in args.n {
        println!("n = {n}");
        let shares = cggmp21_tests::CACHED_SHARES
            .get_shares::<E>(None, n)
            .expect("retrieve key shares from cache");

        if args.bench_refresh {
            let refresh_execution_id: [u8; 32] = rng.gen();
            let refresh_execution_id = ExecutionId::<E, L>::from_bytes(&refresh_execution_id);

            use cggmp21::key_refresh::Msg;
            let mut simulation = Simulation::<Msg<E, D>>::new();

            let mut primes = cggmp21_tests::CACHED_PRIMES.iter();

            let outputs = shares.iter().map(|share| {
                let party = simulation.add_party();
                let refresh_execution_id = refresh_execution_id.clone();
                let mut party_rng = ChaCha20Rng::from_seed(rng.gen());
                let pregen = primes.next().expect("Can't get pregenerated prime");

                let mut profiler = PerfProfiler::new();

                async move {
                    let _new_share = cggmp21::key_refresh(share)
                        .set_execution_id(refresh_execution_id)
                        .set_progress_tracer(&mut profiler)
                        .set_pregenerated_data(pregen)
                        .start(&mut party_rng, party)
                        .await
                        .context("refresh failed")?;
                    profiler.get_report().context("get perf report")
                }
            });

            let perf_reports = futures::future::try_join_all(outputs)
                .await
                .expect("signing failed");

            println!("Key refresh protocol");
            println!("{}", perf_reports[0].clone().display_io(false));
        }

        if args.bench_signing {
            let signing_execution_id: [u8; 32] = rng.gen();
            let signing_execution_id = ExecutionId::<E, L>::from_bytes(&signing_execution_id);

            let signers_indexes_at_keygen = &(0..n).collect::<Vec<_>>();

            let message_to_sign = b"Dfns rules!";
            let message_to_sign = Message::new::<Sha256>(message_to_sign);

            use cggmp21::signing::Msg;
            let mut simulation = Simulation::<Msg<E, D>>::new();

            let mut outputs = vec![];
            for (i, share) in (0..).zip(&shares) {
                let party = simulation.add_party();
                let signing_execution_id = signing_execution_id.clone();
                let mut party_rng = ChaCha20Rng::from_seed(rng.gen());

                let mut profiler = PerfProfiler::new();

                outputs.push(async move {
                    let _signature = cggmp21::signing(i, &signers_indexes_at_keygen, share)
                        .set_execution_id(signing_execution_id)
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
        }
    }
}
