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
        .help("Amount of parties")
        .argument::<u16>("N")
        .many()
        .map(|ns| if ns.is_empty() { vec![3, 5, 7, 10] } else { ns });
    let bench_refresh = bpaf::long("bench-refresh")
        .argument::<bool>("true|false")
        .fallback(true);
    let bench_signing = bpaf::long("bench-signing")
        .argument::<bool>("true|false")
        .fallback(true);

    bpaf::construct!(Args {
        n,
        bench_refresh,
        bench_signing
    })
    .to_options()
    .run()
}

#[ignore = "performance tests are ignored by default"]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = args();
    let mut rng = DevRng::new();

    for n in args.n {
        println!("n = {n}");
        let shares = cggmp21_tests::CACHED_SHARES
            .get_shares::<E>(n)
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

            let message_to_sign = b"Dfns rules!";
            let message_to_sign = Message::new::<Sha256>(message_to_sign);

            use cggmp21::signing::Msg;
            let mut simulation = Simulation::<Msg<E, D>>::new();

            let mut outputs = vec![];
            for share in &shares {
                let party = simulation.add_party();
                let signing_execution_id = signing_execution_id.clone();
                let mut party_rng = ChaCha20Rng::from_seed(rng.gen());

                let mut profiler = PerfProfiler::new();

                outputs.push(async move {
                    let _signature = cggmp21::signing(share)
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
