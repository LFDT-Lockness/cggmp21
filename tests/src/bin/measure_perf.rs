use anyhow::Context;
use cggmp21::{
    progress::PerfProfiler,
    signing::{Message, Msg},
    ExecutionId,
};
use cggmp21_tests::PrecomputedKeyShares;
use clap::Parser;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rand_dev::DevRng;
use round_based::simulation::Simulation;
use sha2::Sha256;

type E = generic_ec::curves::Secp256r1;
type L = cggmp21::security_level::ReasonablySecure;
type D = sha2::Sha256;

lazy_static::lazy_static! {
    static ref CACHED_SHARES: PrecomputedKeyShares =
        PrecomputedKeyShares::from_str(include_str!("../../../test-data/precomputed_shares.json")).unwrap();
}

#[derive(Debug, Parser)]
struct Args {
    #[clap(short, default_value = "3,5,7,10")]
    n: Vec<u16>,
}

#[ignore = "performance tests are ignored by default"]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = Args::parse();
    let mut rng = DevRng::new();

    for n in args.n {
        println!("n = {n}");
        let shares = CACHED_SHARES
            .get_shares::<E>(n)
            .expect("retrieve key shares from cache");

        let signing_execution_id: [u8; 32] = rng.gen();
        let signing_execution_id = ExecutionId::<E, L>::from_bytes(&signing_execution_id);

        let message_to_sign = b"Dfns rules!";
        let message_to_sign = Message::new::<Sha256>(message_to_sign);

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

        println!("{}", perf_reports[0].clone().display_io(false));
    }
}
