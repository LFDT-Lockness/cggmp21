use anyhow::{Context, Result};
use cggmp24::{backend::Integer, key_share::Validate as _};
use generic_ec::Curve;
use rand::RngCore;
use serde_json::Value;

/// Wraps a sink to buffer the messages. Used in [`buffer_outgoing`]
#[pin_project::pin_project]
pub struct BufferedSink<M, Inner> {
    #[pin]
    messages: std::collections::VecDeque<M>,
    #[pin]
    inner: Inner,
}
type BufferedDelivery<M, D> = (
    <D as round_based::Delivery<M>>::Receive,
    BufferedSink<round_based::Outgoing<M>, <D as round_based::Delivery<M>>::Send>,
);

impl<M: Unpin, Inner: futures::Sink<M>> futures::Sink<M> for BufferedSink<M, Inner> {
    type Error = Inner::Error;

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        // Always ready to buffer
        std::task::Poll::Ready(Ok(()))
    }

    fn start_send(self: std::pin::Pin<&mut Self>, item: M) -> Result<(), Self::Error> {
        self.project().messages.get_mut().push_back(item);
        Ok(())
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        // Feed all buffered messages one by one
        while !self.messages.is_empty() {
            let mut projection = self.as_mut().project();
            let mut inner = projection.inner;
            // In case the inner sink wasn't ready, this method will be retried.
            // We rely on this and don't modify any internal state before this
            // point
            std::task::ready!(inner.as_mut().poll_ready(cx))?;
            if let Some(item) = projection.messages.pop_front() {
                inner.as_mut().start_send(item)?;
            }
        }
        self.project().inner.poll_flush(cx)
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.project().inner.poll_close(cx)
    }
}

/// Modified 'Delivery' of the party to buffer outgoing messages. The messages
/// fed to the 'Delivery' sink will be buffered indefinitely until `flush` is
/// called
///
/// This is useful since the delivery used in round-based simulation doesn't do
/// buffering at all, however we want to verify that we don't forget to flush
/// the messages in our protocols. When this function is used, forgetting to
/// flush will cause the test to get stuck.
pub fn buffer_outgoing<M, D, R>(
    party: round_based::MpcParty<M, D, R>,
) -> round_based::MpcParty<M, BufferedDelivery<M, D>, R>
where
    M: Unpin,
    D: round_based::Delivery<M>,
    R: round_based::runtime::AsyncRuntime,
{
    party.map_delivery(|delivery| {
        let (incoming, outgoing) = delivery.split();
        let buffered_outgoing = BufferedSink::<round_based::Outgoing<M>, D::Send> {
            messages: std::collections::VecDeque::new(),
            inner: outgoing,
        };
        (incoming, buffered_outgoing)
    })
}

pub mod external_verifier;

pub mod cached {
    // we've decided to load cached data in runtime to avoid exploding the tests binary size
    fn read_cached<T>(relative_path: &(impl AsRef<std::path::Path> + ?Sized)) -> T
    where
        T: serde::de::DeserializeOwned,
    {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push(relative_path);

        let file = std::fs::File::open(path).unwrap();
        let reader = std::io::BufReader::new(file);
        serde_json::from_reader(reader).unwrap()
    }

    lazy_static::lazy_static! {
        pub static ref SHARES: super::PrecomputedKeyShares =
            read_cached("../test-data/precomputed_shares.json");
        pub static ref PRIMES: super::PregeneratedPrimes =
            read_cached("../test-data/pregenerated_primes.json");
    }
}

#[serde_with::serde_as]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct PrecomputedKeyShares {
    shares: std::collections::BTreeMap<String, Value>,
    aux: std::collections::BTreeMap<String, Vec<PrecomputedAux>>,
    #[serde_as(as = "serde_with::hex::Hex")]
    chain_code: [u8; 32],

    #[serde(skip)]
    aux_128bits: std::sync::OnceLock<
        Vec<cggmp24::key_share::DirtyAuxInfo<cggmp24::security_level::SecurityLevel128>>,
    >,
    #[serde(skip)]
    aux_192bits: std::sync::OnceLock<
        Vec<cggmp24::key_share::DirtyAuxInfo<cggmp24::security_level::SecurityLevel192>>,
    >,
}

#[serde_with::serde_as]
#[derive(serde::Serialize, serde::Deserialize)]
struct PrecomputedCoreShares<E: generic_ec::Curve> {
    #[serde_as(as = "generic_ec::serde::Compact")]
    public_key: generic_ec::NonZero<generic_ec::Point<E>>,
    #[serde_as(as = "Vec<generic_ec::serde::Compact>")]
    shares: Vec<generic_ec::NonZero<generic_ec::SecretScalar<E>>>,
}
#[derive(serde::Serialize, serde::Deserialize)]
struct PrecomputedAux {
    p: Integer,
    q: Integer,
    hat_p: Integer,
    hat_q: Integer,
    s: Integer,
    t: Integer,
}

impl PrecomputedKeyShares {
    pub fn get_shares<E>(
        &self,
        t: Option<u16>,
        n: u16,
        hd_enabled: bool,
    ) -> Vec<cggmp24::key_share::KeyShare<E, E::SecurityLevel>>
    where
        E: Curve + CurveParams,
        Self: HasAuxOfLevel<E::SecurityLevel>,
    {
        #[cfg(not(feature = "hd-wallet"))]
        assert!(!hd_enabled);

        let core = self
            .shares
            .get(&Self::key::<E>(t, n))
            .expect("key shares not found");
        let core: PrecomputedCoreShares<E> = serde_json::from_value(core.clone()).unwrap();

        let public_shares: Vec<generic_ec::NonZero<generic_ec::Point<E>>> = core
            .shares
            .iter()
            .map(|s| s * generic_ec::Point::generator())
            .collect();

        let vss = match t {
            None => None,
            Some(t) => Some(cggmp24::key_share::VssSetup::<E> {
                min_signers: t,
                I: (1u16..=n)
                    .map(|i| generic_ec::NonZero::from_scalar(generic_ec::Scalar::from(i)).unwrap())
                    .collect(),
            }),
        };

        let core_shares = (0..).zip(core.shares).map(|(i, x)| {
            cggmp24::key_share::DirtyIncompleteKeyShare {
                i,
                key_info: cggmp24::key_share::DirtyKeyInfo {
                    curve: Default::default(),
                    shared_public_key: core.public_key,
                    public_shares: public_shares.clone(),
                    vss_setup: vss.clone(),
                    #[cfg(feature = "hd-wallet")]
                    chain_code: if hd_enabled {
                        Some(self.chain_code)
                    } else {
                        None
                    },
                },
                x,
            }
            .validate()
            .unwrap()
        });

        let aux = self.get_aux().iter().map(|aux| {
            let mut aux = aux.clone();
            aux.N.truncate(usize::from(n));
            aux.pedersen_params.truncate(usize::from(n));
            aux.validate().unwrap()
        });

        core_shares
            .zip(aux)
            .map(|(core, aux)| cggmp24::KeyShare::from_parts((core, aux)).unwrap())
            .collect()
    }
    fn key<E: Curve>(t: Option<u16>, n: u16) -> String {
        format!("t={t:?},n={n},curve={}", E::CURVE_NAME)
    }

    #[allow(non_snake_case)]
    fn get_aux_inner<'l, L>(
        lock: &'l std::sync::OnceLock<Vec<cggmp24::key_share::DirtyAuxInfo<L>>>,
        aux: &std::collections::BTreeMap<String, Vec<PrecomputedAux>>,
        aux_key: &'static str,
    ) -> &'l [cggmp24::key_share::DirtyAuxInfo<L>]
    where
        L: cggmp24::security_level::SecurityLevel,
    {
        lock.get_or_init(|| {
            let aux = aux.get(aux_key).expect("no primes of appropriate size");

            let pedersen_params = aux
                .iter()
                .map(|aux| {
                    let mut params = cggmp24::key_share::PedersenParams {
                        hat_N: &aux.hat_p * &aux.hat_q,
                        s: aux.s.clone(),
                        t: aux.t.clone(),
                        multiexp: None,
                        crt: None,
                    };
                    params.precompute_crt(&aux.hat_p, &aux.hat_q).unwrap();
                    params
                        .precompute_multiexp_table::<cggmp24::security_level::SecurityLevel128>()
                        .unwrap();
                    params
                })
                .collect::<Vec<_>>();

            let N = aux.iter().map(|aux| &aux.p * &aux.q).collect::<Vec<_>>();

            aux.iter()
                .map(|aux| cggmp24::key_share::DirtyAuxInfo {
                    p: aux.p.clone(),
                    q: aux.q.clone(),
                    N: N.clone(),
                    pedersen_params: pedersen_params.clone(),
                    security_level: std::marker::PhantomData,
                })
                .collect()
        })
    }

    pub fn precompute_aux<L>(&mut self, rng: &mut (impl rand::RngCore + rand::CryptoRng), n: usize)
    where
        L: cggmp24::security_level::SecurityLevel,
    {
        let primes = (0..n)
            .map(|_| {
                [
                    generate_blum_prime(rng, L::RSA_PRIME_BITLEN),
                    generate_blum_prime(rng, L::RSA_PRIME_BITLEN),
                    generate_blum_prime(rng, L::RSA_PRIME_BITLEN),
                    generate_blum_prime(rng, L::RSA_PRIME_BITLEN),
                ]
            })
            .collect::<Vec<_>>();
        let aux = cggmp24::trusted_dealer::generate_aux_data_with_primes::<L, _>(
            rng,
            primes
                .iter()
                .cloned()
                .map(|primes| cggmp24::key_refresh::PregeneratedPrimes::try_from(primes).unwrap())
                .collect(),
            false,
        )
        .unwrap();
        let s_t = aux[0]
            .pedersen_params
            .iter()
            .map(|p| (p.s.clone(), p.t.clone()));

        let aux = s_t
            .zip(primes)
            .map(|((s, t), [p, q, hat_p, hat_q])| PrecomputedAux {
                p,
                q,
                hat_p,
                hat_q,
                s,
                t,
            })
            .collect();

        let security_bits = L::KAPPA_BITS / 2;
        self.aux.insert(security_bits.to_string(), aux);
    }

    pub fn add_shares<E>(
        &mut self,
        t: Option<u16>,
        n: u16,
        shares: &[cggmp24::key_share::IncompleteKeyShare<E>],
    ) where
        E: Curve,
    {
        assert_eq!(shares.len(), usize::from(n));
        let shares = PrecomputedCoreShares::<E> {
            public_key: shares[0].shared_public_key,
            shares: shares.iter().map(|s| s.x.clone()).collect(),
        };
        let shares = serde_json::to_value(shares).unwrap();

        self.shares.insert(Self::key::<E>(t, n), shares);
    }

    pub fn empty(chain_code: [u8; 32]) -> Self {
        Self {
            shares: Default::default(),
            aux: Default::default(),
            chain_code,
            aux_128bits: Default::default(),
            aux_192bits: Default::default(),
        }
    }
}

pub trait HasAuxOfLevel<L: cggmp24::security_level::SecurityLevel> {
    fn get_aux(&self) -> &[cggmp24::key_share::DirtyAuxInfo<L>];
}
impl HasAuxOfLevel<cggmp24::security_level::SecurityLevel128> for PrecomputedKeyShares {
    fn get_aux(
        &self,
    ) -> &[cggmp24::key_share::DirtyAuxInfo<cggmp24::security_level::SecurityLevel128>] {
        Self::get_aux_inner(&self.aux_128bits, &self.aux, "128")
    }
}
impl HasAuxOfLevel<cggmp24::security_level::SecurityLevel192> for PrecomputedKeyShares {
    fn get_aux(
        &self,
    ) -> &[cggmp24::key_share::DirtyAuxInfo<cggmp24::security_level::SecurityLevel192>] {
        Self::get_aux_inner(&self.aux_192bits, &self.aux, "192")
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PregeneratedPrimes {
    /// Primes of appropriate size that can be used as Paillier private key meeting 128 bits of security
    primes_1536bits: Vec<Integer>,
    /// Primes of appropriate size that can be used as Paillier private key meeting 192 bits of security
    primes_3840bits: Vec<Integer>,
}

impl PregeneratedPrimes {
    pub fn to_serialized(&self) -> Result<String> {
        serde_json::to_string_pretty(self).context("serialize primes")
    }

    /// Iterate over numbers, producing pregenerated pairs for key refresh
    pub fn iter<L>(&self) -> impl Iterator<Item = cggmp24::key_refresh::PregeneratedPrimes<L>> + '_
    where
        L: cggmp24::security_level::SecurityLevel,
    {
        match L::RSA_PRIME_BITLEN {
            1536 => Self::iter_inner::<L>(&self.primes_1536bits),
            3840 => Self::iter_inner::<L>(&self.primes_3840bits),
            x => {
                panic!("we did not pregenerate {x} bits primes")
            }
        }
    }

    fn iter_inner<L>(
        primes: &[Integer],
    ) -> impl Iterator<Item = cggmp24::key_refresh::PregeneratedPrimes<L>> + '_
    where
        L: cggmp24::security_level::SecurityLevel,
    {
        primes.chunks(4).map(|primes| {
            let primes = [
                primes[0].clone(),
                primes[1].clone(),
                primes[2].clone(),
                primes[3].clone(),
            ];
            cggmp24::key_refresh::PregeneratedPrimes::try_from(primes)
                .expect("primes have wrong bit size")
        })
    }

    /// Generate enough primes so that you can do `amount` of key refreshes
    pub fn generate<R>(amount: usize, rng: &mut R) -> Self
    where
        R: RngCore,
    {
        Self {
            primes_1536bits: (0..amount * 4)
                .map(|_| generate_blum_prime(rng, 1536))
                .collect(),
            primes_3840bits: (0..amount * 4)
                .map(|_| generate_blum_prime(rng, 3840))
                .collect(),
        }
    }
}

/// Generates a blum prime
///
/// CGGMP24 requires using safe primes, however blum primes do not break correctness of the protocol
/// and they can be generated faster.
///
/// Only to be used in the tests.
pub fn generate_blum_prime(rng: &mut impl rand::RngCore, bits_size: u32) -> Integer {
    loop {
        let n: Integer = Integer::generate_prime(rng, bits_size);
        if n.mod_u(4) == 3 {
            break n;
        }
    }
}

pub fn convert_stark_scalar(
    x: &generic_ec::Scalar<cggmp24::supported_curves::Stark>,
) -> anyhow::Result<starknet_crypto::FieldElement> {
    let bytes = x.to_be_bytes();
    debug_assert_eq!(bytes.len(), 32);
    let mut buffer = [0u8; 32];
    buffer.copy_from_slice(bytes.as_bytes());
    starknet_crypto::FieldElement::from_bytes_be(&buffer)
        .map_err(|e| anyhow::Error::msg(format!("Can't convert scalar: {e}")))
}

pub fn convert_from_stark_scalar(
    x: &starknet_crypto::FieldElement,
) -> anyhow::Result<generic_ec::Scalar<generic_ec::curves::Stark>> {
    let bytes = x.to_bytes_be();
    generic_ec::Scalar::from_be_bytes(bytes).context("Can't read bytes")
}

#[cfg(feature = "hd-wallet")]
pub fn random_derivation_path(rng: &mut impl rand::RngCore) -> Vec<u32> {
    use rand::Rng;
    let len = rng.gen_range(1..=3);
    std::iter::repeat_with(|| rng.gen_range(0..cggmp24::hd_wallet::H))
        .take(len)
        .collect::<Vec<_>>()
}

/// Parameters per each curve that are needed in tests
pub trait CurveParams: Curve {
    /// External verifier for signatures on this curve
    type ExVerifier: external_verifier::ExternalVerifier<Self>;
    /// Security level appropriate to the curve
    type SecurityLevel: cggmp24::security_level::SecurityLevel;

    /// Hash function that should be used with this curve
    ///
    /// Note that we need digest output to be Unpin for protocol messages to be Unpin. It's not easy
    /// to express that requirement in traits, we do that by introducing two dummy associated types:
    /// [`CurveParams::DigestOutSize`] and [`CurveParams::DigestOutArray`]
    type Digest: digest::Digest<OutputSize = Self::DigestOutSize> + Clone + 'static;
    /// Dummy associated type to express that digest output must be `Unpin`
    ///
    /// Implementation should always write:
    /// ```rust,ignore
    /// type DigestOutSize = <Self::Digest as digest::OutputSizeUser>::OutputSize;
    /// ```
    type DigestOutSize: digest::generic_array::ArrayLength<u8, ArrayType = Self::DigestOutArray>;
    /// Dummy associated type to express that digest output must be `Unpin`
    ///
    /// Implementation should always write:
    /// ```rust,ignore
    /// type DigestOutArray =
    ///     <Self::DigestOutSize as digest::generic_array::ArrayLength<u8>>::ArrayType;
    /// ```
    type DigestOutArray: Unpin;
}

impl CurveParams for cggmp24::supported_curves::Secp256k1 {
    type ExVerifier = external_verifier::blockchains::Bitcoin;
    type SecurityLevel = cggmp24::security_level::SecurityLevel128;
    type Digest = sha2::Sha256;
    type DigestOutSize = <Self::Digest as digest::OutputSizeUser>::OutputSize;
    type DigestOutArray =
        <Self::DigestOutSize as digest::generic_array::ArrayLength<u8>>::ArrayType;
}

impl CurveParams for cggmp24::supported_curves::Secp256r1 {
    type ExVerifier = external_verifier::Noop;
    type SecurityLevel = cggmp24::security_level::SecurityLevel128;
    type Digest = sha2::Sha256;
    type DigestOutSize = <Self::Digest as digest::OutputSizeUser>::OutputSize;
    type DigestOutArray =
        <Self::DigestOutSize as digest::generic_array::ArrayLength<u8>>::ArrayType;
}

impl CurveParams for cggmp24::supported_curves::Secp384r1 {
    type ExVerifier = external_verifier::blockchains::NistP384;
    type SecurityLevel = cggmp24::security_level::SecurityLevel192;
    type Digest = sha2::Sha384;
    type DigestOutSize = <Self::Digest as digest::OutputSizeUser>::OutputSize;
    type DigestOutArray =
        <Self::DigestOutSize as digest::generic_array::ArrayLength<u8>>::ArrayType;
}

impl CurveParams for cggmp24::supported_curves::Stark {
    type ExVerifier = external_verifier::blockchains::StarkNet;
    type SecurityLevel = cggmp24::security_level::SecurityLevel128;
    type Digest = sha2::Sha256;
    type DigestOutSize = <Self::Digest as digest::OutputSizeUser>::OutputSize;
    type DigestOutArray =
        <Self::DigestOutSize as digest::generic_array::ArrayLength<u8>>::ArrayType;
}

/// Trait used by the tests to enable/disable HD wallets
///
/// Motivation for this trait is to have one test function that tests the code (keygen or signing)
/// with and without HD derivation, with and without `feature = "hd-wallet"`, taking into account
/// that some curves do not have support of HD derivation at all
///
/// Two structs implement this trait:
/// - [`HdDisabled`] that does no HD. All trait methods are no-op.
/// - [`HdEnabled<Algo>`](HdEnabled) that does HD derivation with `Algo`.
pub trait OptionalHd<E: Curve>: Clone {
    /// Indicates whether HD derivation is enabled
    const ENABLED: bool;

    /// Generates derivation path if HD is enabled
    fn generate_derivation_path(rng: &mut impl RngCore) -> Self;

    /// Applies derivation path (if enabled) to the signing builder
    fn apply<'r, L, D>(
        &self,
        builder: cggmp24::signing::SigningBuilder<'r, E, L, D>,
    ) -> cggmp24::signing::SigningBuilder<'r, E, L, D>
    where
        generic_ec::NonZero<generic_ec::Point<E>>: generic_ec::coords::AlwaysHasAffineX<E>,
        L: cggmp24::security_level::SecurityLevel,
        D: digest::Digest + Clone + 'static;

    /// Uses derivation path to derive a child public key
    ///
    /// If HD is disabled, this function returns the public key as is.
    fn derive_child_pk(
        &self,
        share: &cggmp24::key_share::DirtyIncompleteKeyShare<E>,
    ) -> generic_ec::NonZero<generic_ec::Point<E>>;
}

#[derive(Clone)]
pub struct HdDisabled;
impl<E: Curve> OptionalHd<E> for HdDisabled {
    const ENABLED: bool = false;
    fn generate_derivation_path(_rng: &mut impl RngCore) -> Self {
        Self
    }

    fn apply<'r, L, D>(
        &self,
        builder: cggmp24::signing::SigningBuilder<'r, E, L, D>,
    ) -> cggmp24::signing::SigningBuilder<'r, E, L, D>
    where
        generic_ec::NonZero<generic_ec::Point<E>>: generic_ec::coords::AlwaysHasAffineX<E>,
        L: cggmp24::security_level::SecurityLevel,
        D: digest::Digest + Clone + 'static,
    {
        builder
    }

    fn derive_child_pk(
        &self,
        share: &cggmp24::key_share::DirtyIncompleteKeyShare<E>,
    ) -> generic_ec::NonZero<generic_ec::Point<E>> {
        share.shared_public_key
    }
}

#[cfg(feature = "hd-wallet")]
pub struct HdEnabled<Algo> {
    path: Vec<hd_wallet::NonHardenedIndex>,
    _algo: core::marker::PhantomData<Algo>,
}
#[cfg(feature = "hd-wallet")]
impl<E, Algo> OptionalHd<E> for HdEnabled<Algo>
where
    E: Curve,
    Algo: hd_wallet::DeriveShift<E>,
{
    const ENABLED: bool = true;

    fn generate_derivation_path(rng: &mut impl RngCore) -> Self {
        use rand::Rng;
        let len = rng.gen_range(1..=3);
        let path = std::iter::repeat_with(|| rng.gen_range(0..cggmp24::hd_wallet::H))
            .take(len)
            .map(|index| index.try_into())
            .collect::<Result<Vec<_>, _>>()
            .expect("generated hardened index");
        eprintln!("derivation path: {path:?}");
        Self {
            path,
            _algo: core::marker::PhantomData,
        }
    }

    fn apply<'r, L, D>(
        &self,
        builder: cggmp24::signing::SigningBuilder<'r, E, L, D>,
    ) -> cggmp24::signing::SigningBuilder<'r, E, L, D>
    where
        generic_ec::NonZero<generic_ec::Point<E>>: generic_ec::coords::AlwaysHasAffineX<E>,
        L: cggmp24::security_level::SecurityLevel,
        D: digest::Digest + Clone + 'static,
    {
        builder
            .set_derivation_path_with_algo::<Algo, _>(self.path.iter().copied())
            .expect("hd is disabled for this key")
    }

    fn derive_child_pk(
        &self,
        share: &cggmp24::key_share::DirtyIncompleteKeyShare<E>,
    ) -> generic_ec::NonZero<generic_ec::Point<E>> {
        generic_ec::NonZero::from_point(
            share
                .derive_child_public_key::<Algo, _>(self.path.iter().copied())
                .expect("hd is disabled for this key")
                .public_key,
        )
        .unwrap()
    }
}
#[cfg(feature = "hd-wallet")]
impl<Algo> Clone for HdEnabled<Algo> {
    fn clone(&self) -> Self {
        Self {
            path: self.path.clone(),
            _algo: core::marker::PhantomData,
        }
    }
}

#[macro_export]
macro_rules! test_suite {
    (
        $(async_test: $async_test:ident,)?
        $(test: $test:ident,)?
        generics: all_curves,
        suites: {$($suites:tt)*}
        $(,)?
    ) => {
        $crate::test_suite! {
            $(async_test: $async_test,)?
            $(test: $test,)?
            generics: {
                secp256k1: <cggmp24::supported_curves::Secp256k1>,
                secp256r1: <cggmp24::supported_curves::Secp256r1>,
                secp384r1: <cggmp24::supported_curves::Secp384r1>,
                stark: <cggmp24::supported_curves::Stark>,
            },
            suites: {$($suites)*}
        }
    };
    (
        $(async_test: $async_test:ident,)?
        $(test: $test:ident,)?
        generics: all_curves_and_hd,
        suites: {$($suites:tt)*}
        $(,)?
    ) => {
        $crate::test_suite! {
            $(async_test: $async_test,)?
            $(test: $test,)?
            generics: {
                secp256k1: <cggmp24::supported_curves::Secp256k1, cggmp24_tests::HdDisabled>,
                secp256r1: <cggmp24::supported_curves::Secp256r1, cggmp24_tests::HdDisabled>,
                secp384r1: <cggmp24::supported_curves::Secp384r1, cggmp24_tests::HdDisabled>,
                stark: <cggmp24::supported_curves::Stark, cggmp24_tests::HdDisabled>,

                #[cfg(feature = "hd-wallet")]
                secp256k1_hd: <cggmp24::supported_curves::Secp256k1, cggmp24_tests::HdEnabled<hd_wallet::Slip10>>,
                #[cfg(feature = "hd-wallet")]
                secp256r1_hd: <cggmp24::supported_curves::Secp256r1, cggmp24_tests::HdEnabled<hd_wallet::Slip10>>,
                #[cfg(feature = "hd-wallet")]
                stark_hd: <cggmp24::supported_curves::Stark, cggmp24_tests::HdEnabled<hd_wallet::Stark>>,
            },
            suites: {$($suites)*}
        }
    };
    (
        $(async_test: $async_test:ident,)?
        $(test: $test:ident,)?
        generics: {$(
            $(#[$attr:meta])*
            $gmod:ident: <$($generic:path),*>
        ),+$(,)?},
        suites: {$($suites:tt)*}
        $(,)?
    ) => {
        mod $($test)? $($async_test)? {
            use super::$($test)? $($async_test)?;
            $crate::test_suite_traverse! {
                $(async_test: $async_test,)?
                $(test: $test,)?
                generics: {$($(#[$attr])* $gmod: <$($generic),+>),+},
                suites: {$($suites)*}
            }
        }
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! test_suite_traverse {
    (
        // Either `$async_test` or `$test` must be present, but not at the same time
        $(async_test: $async_test:ident,)?
        $(test: $test:ident,)?
        // we traverse over `generics`
        generics: {
            $(#[$attr:meta])*
            $gmod:ident: <$($generic:path),*>
            $(, $($generics_rest:tt)*)?
        },
        suites: {$($suites:tt)*}
    ) => {
        $(#[$attr])*
        mod $gmod {
            use super::$($test)? $($async_test)?;
            $crate::test_suite_traverse! {
                $(async_test: $async_test,)?
                $(test: $test,)?
                generics: <$($generic),+>,
                suites: {$($suites)*}
            }
        }
        $crate::test_suite_traverse! {
            $(async_test: $async_test,)?
            $(test: $test,)?
            generics: {
                $($($generics_rest)*)?
            },
            suites: {$($suites)*}
        }
    };
    (
        $(async_test: $async_test:ident,)?
        $(test: $test:ident,)?
        // generics list is empty - nothing to traverse
        generics: {},
        suites: {$($suites:tt)*}
    ) => {};

    (
        async_test: $test:ident,
        generics: <$($generic:path),*>,
        // we traverse async suites
        suites: {
            $(#[$attr:meta])*
            $suite_name:ident: ($($args:tt)*)
            $(, $($rest:tt)*)?
        }
    ) => {
        $(#[$attr])*
        #[tokio::test]
        async fn $suite_name() {
            $test::<$($generic),+>($($args)*).await
        }

        $crate::test_suite_traverse! {
            async_test: $test,
            generics: <$($generic),*>,
            suites: {$($($rest)*)?}
        }
    };
    (
        test: $test:ident,
        generics: <$($generic:path),*>,
        // we traverse sync suites
        suites: {
            $(#[$attr:meta])*
            $suite_name:ident: ($($args:tt)*)
            $(, $($rest:tt)*)?
        }
    ) => {
        $(#[$attr])*
        #[test]
        fn $suite_name() {
            $test::<$($generic),+>($($args)*)
        }

        $crate::test_suite_traverse! {
            test: $test,
            generics: <$($generic),*>,
            suites: {$($($rest)*)?}
        }
    };
    (
        $(async_test: $async_test:ident,)?
        $(test: $test:ident,)?
        generics: <$($generic:path),*>,
        // suites list is empty - nothing to traverse
        suites: {}
    ) => {};
}
