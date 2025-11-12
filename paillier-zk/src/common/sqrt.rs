use fast_paillier::backend::Integer;
use rand_core::RngCore;

/// Find principal square root in a Blum modulus quotient ring.
///
/// Pre-requisites:
/// - x is a quadratic residue in Zn
/// - `n = pq`, p and q are Blum primes
///
/// If these don't hold, the result is a bogus number in Zn
pub fn blum_sqrt(x: &Integer, p: &Integer, q: &Integer, n: &Integer) -> Integer {
    // Exponent in pq Blum modulus to obtain the principal square root.
    // Described in [Handbook of Applied cryptography, p. 75, Fact
    // 2.160](https://cacr.uwaterloo.ca/hac/about/chap2.pdf)
    let e = ((p - 1) * (q - 1) + 4) / 8;

    // e guaranteed to be non-negative by the prerequisite that p and q are blum primes
    #[allow(clippy::expect_used)]
    x.pow_mod_ref(&e, n)
        .expect("e guaranteed to be non-negative")
}

/// Find `(y' = (-1)^a w^b y, a, b)` such that y' is a quadratic residue in Zn.
///
/// a and b are treated as false = 0, true = 1
///
/// Pre-requisites:
/// - `n = pq`, p and q are Blum primes
/// - `jacobi(w, n) = -1`, that is w is quadratic non-residue in Zn with jacobi
///   symbol of -1
///
/// If these don't hold, the y' might not exist. In this case, returns `None`
pub fn find_residue(
    y: &Integer,
    w: &Integer,
    p: &Integer,
    q: &Integer,
    n: &Integer,
) -> Option<(bool, bool, Integer)> {
    let jp = y.modulo_ref(p).jacobi(p);
    let jq = y.modulo_ref(q).jacobi(q);
    match (jp, jq) {
        (1, 1) => return Some((false, false, y.clone())),
        (-1, -1) => return Some((true, false, n - y)),
        _ => (),
    }

    let y = (y * w).modulo(n);
    let jp = y.modulo_ref(p).jacobi(p);
    let jq = y.modulo_ref(q).jacobi(q);
    match (jp, jq) {
        (1, 1) => Some((false, true, y)),
        (-1, -1) => Some((true, true, n - y)),
        _ => None,
    }
}

/// Finds a element in Z*n that has jacobi symbol of -1
pub fn sample_invertible_with_neg_jacobi<R: RngCore>(n: &Integer, rng: &mut R) -> Integer {
    loop {
        let w = Integer::sample_in_mult_group_of(rng, n);
        if w.jacobi(n) == -1 {
            break w;
        }
    }
}
