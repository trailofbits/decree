//! Small-Factor Proof Example
//!
//! This example demonstrates a proof that an RSA modulus N₀ = pq has factors
//! that are not too small. Specifically, it proves that both p and q are
//! greater than 2^ℓ.
//!
//! This is useful in protocols where RSA key generation needs to be verified,
//! such as threshold RSA signatures or verifiable delay functions.
//!
//! The proof uses Pedersen commitments in an auxiliary RSA group Ñ and follows
//! the protocol from Canetti et al. 2024, Figure 26.

#![deny(warnings)]
#![cfg_attr(not(test), allow(dead_code))]

use decree::error::Error;
use decree::Inscribe;
use decree::decree::{Decree, FSInput};
use num_bigint::{BigInt, BigUint, RandBigInt, Sign};
use num_traits::{One, Zero};
use rand::rngs::OsRng;
use rand::Rng;

/// Security parameter for statistical distance
const EPSILON: u32 = 128;

/// Miller-Rabin primality test
fn is_probably_prime(n: &BigUint, rounds: u32) -> bool {
    if n < &BigUint::from(2u32) {
        return false;
    }
    if n == &BigUint::from(2u32) || n == &BigUint::from(3u32) {
        return true;
    }
    if !n.bit(0) {
        return false;  // even number
    }

    // Write n-1 as 2^r · d
    let n_minus_1 = n - BigUint::one();
    let mut d = n_minus_1.clone();
    let mut r = 0u32;
    while !d.bit(0) {
        d >>= 1;
        r += 1;
    }

    let mut rng = OsRng;

    'witness: for _ in 0..rounds {
        let a = rng.gen_biguint_range(&BigUint::from(2u32), &(n - BigUint::from(2u32)));
        let mut x = a.modpow(&d, n);

        if x == BigUint::one() || x == n_minus_1 {
            continue 'witness;
        }

        for _ in 0..(r - 1) {
            x = x.modpow(&BigUint::from(2u32), n);
            if x == n_minus_1 {
                continue 'witness;
            }
        }

        return false;
    }

    true
}

/// Generate a random prime of specified bit length
fn generate_prime(bits: usize) -> BigUint {
    let mut rng = OsRng;
    loop {
        // Generate random odd number of specified bit length
        let mut candidate = rng.gen_biguint(bits as u64);

        // Set high bit to ensure correct bit length
        candidate.set_bit(bits as u64 - 1, true);

        // Make it odd
        candidate.set_bit(0, true);

        // Test for primality
        if is_probably_prime(&candidate, 20) {
            return candidate;
        }
    }
}

/// Wrapper for BigInt with proper domain separation for Inscribe
struct BigIntWrapper(BigInt);

impl Inscribe for BigIntWrapper {
    const MARK: &'static str = "BigInt";

    fn get_inscription(&self) -> Result<FSInput, Error> {
        let bytes = self.0.to_signed_bytes_le();
        Ok(bytes)
    }

    fn get_additional(&self) -> Result<FSInput, Error> {
        Ok(b"small-factor-proof-bigint".to_vec())
    }
}

/// Wrapper for BigUint with proper domain separation for Inscribe
struct BigUintWrapper(BigUint);

impl Inscribe for BigUintWrapper {
    const MARK: &'static str = "BigUint";

    fn get_inscription(&self) -> Result<FSInput, Error> {
        let bytes = self.0.to_bytes_le();
        Ok(bytes)
    }

    fn get_additional(&self) -> Result<FSInput, Error> {
        Ok(b"small-factor-proof-biguint".to_vec())
    }
}

/// Pedersen commitment parameters in RSA group
struct PedersenParameters {
    n_tilde: BigUint,  // Ñ: auxiliary RSA modulus
    s: BigUint,        // first generator
    t: BigUint,        // second generator
}

/// Generate Pedersen parameters with auxiliary RSA modulus
fn generate_pedersen_parameters(bits: usize) -> PedersenParameters {
    let mut rng = OsRng;

    // Generate two random primes for Ñ
    let p_tilde = generate_prime(bits / 2);
    let q_tilde = generate_prime(bits / 2);
    let n_tilde = &p_tilde * &q_tilde;

    // Generate random generators s and t in Z*_Ñ
    let s = rng.gen_biguint_range(&BigUint::from(2u32), &n_tilde);
    let t = rng.gen_biguint_range(&BigUint::from(2u32), &n_tilde);

    PedersenParameters { n_tilde, s, t }
}

/// Commitment phase of the small-factor proof
#[derive(Inscribe)]
struct SmallFactorCommitment {
    p_commit: BigUintWrapper,  // P = s^p · t^μ
    q_commit: BigUintWrapper,  // Q = s^q · t^ν
    a_commit: BigUintWrapper,  // A = s^α · t^x
    b_commit: BigUintWrapper,  // B = s^β · t^y
    t_commit: BigUintWrapper,  // T = Q^α · t^r
}

/// Response phase of the small-factor proof
#[derive(Inscribe)]
struct SmallFactorResponse {
    z1: BigIntWrapper,  // z₁ = α + ep
    z2: BigIntWrapper,  // z₂ = β + eq
    w1: BigIntWrapper,  // w₁ = x + eμ
    w2: BigIntWrapper,  // w₂ = y + eν
    v: BigIntWrapper,   // v = r - e·νp
}

/// Complete small-factor proof
#[derive(Inscribe)]
struct SmallFactorProof {
    commitment: SmallFactorCommitment,
    #[inscribe(skip)]
    response: SmallFactorResponse,
}

/// Modular exponentiation with signed exponent
/// Computes base^exp mod modulus, where exp can be negative
fn modpow_signed(base: &BigUint, exp: &BigInt, modulus: &BigUint) -> BigUint {
    if exp.sign() == Sign::Minus {
        // For negative exponent, compute (base^(-1))^|exp| mod modulus
        // base^(-1) mod modulus using extended GCD
        let base_int = BigInt::from_biguint(Sign::Plus, base.clone());
        let modulus_int = BigInt::from_biguint(Sign::Plus, modulus.clone());

        // Extended GCD to find modular inverse
        let (gcd, inv, _) = extended_gcd(&base_int, &modulus_int);
        if gcd != BigInt::one() {
            panic!("Base is not invertible mod modulus");
        }

        // Ensure inverse is positive
        let inv_pos = if inv.sign() == Sign::Minus {
            &modulus_int + inv
        } else {
            inv
        };

        inv_pos.to_biguint().unwrap().modpow(exp.magnitude(), modulus)
    } else {
        base.modpow(exp.magnitude(), modulus)
    }
}

/// Extended GCD algorithm
fn extended_gcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    if b.is_zero() {
        return (a.clone(), BigInt::one(), BigInt::zero());
    }

    let (gcd, x1, y1) = extended_gcd(b, &(a % b));
    let x = y1.clone();
    let y = x1 - (a / b) * y1;

    (gcd, x, y)
}

/// Sample a signed BigInt uniformly from [-bound, bound]
fn sample_pm_range(bound: &BigUint) -> BigInt {
    let mut rng = OsRng;
    let magnitude = rng.gen_biguint_range(&BigUint::zero(), bound);
    let sign = if rng.gen::<bool>() {
        Sign::Plus
    } else {
        Sign::Minus
    };
    BigInt::from_biguint(sign, magnitude)
}

/// Generate RSA modulus for testing
fn generate_rsa_modulus(bits: usize) -> (BigUint, BigUint, BigUint) {
    let p = generate_prime(bits / 2);
    let q = generate_prime(bits / 2);
    let n = &p * &q;
    (n, p, q)
}

/// Compute ceiling of integer square root
fn isqrt_ceil(n: &BigUint) -> BigUint {
    if n <= &BigUint::one() {
        return n.clone();
    }

    // Newton's method for integer sqrt
    let mut x = n.clone();
    loop {
        let x_new = (&x + (n / &x)) >> 1;
        if x_new >= x {
            // Check if we need ceiling
            if &(&x * &x) < n {
                return &x + BigUint::one();
            }
            return x;
        }
        x = x_new;
    }
}

/// Generate a small-factor proof
fn prove(
    params: &PedersenParameters,
    n0: &BigUint,
    p: &BigUint,
    q: &BigUint,
    ell: u32,
) -> SmallFactorProof {
    // Compute bounds for sampling
    let sqrt_n0 = isqrt_ceil(n0);
    let two_ell = BigUint::from(2u32).pow(ell);
    let two_ell_eps = BigUint::from(2u32).pow(ell + EPSILON);
    let bound_alpha = &two_ell_eps * &sqrt_n0;  // ±2^(ℓ+ε) · √N₀
    let bound_mu = &two_ell * &params.n_tilde;  // ±2^ℓ · Ñ
    let bound_r = &two_ell_eps * n0 * &params.n_tilde;  // ±2^(ℓ+ε) · N₀ · Ñ
    let bound_x = &two_ell_eps * &params.n_tilde;  // ±2^(ℓ+ε) · Ñ

    // Sample randomness for Pedersen commitments
    let mu = sample_pm_range(&bound_mu);
    let nu = sample_pm_range(&bound_mu);

    // Compute P = s^p · t^μ mod Ñ
    let p_commit = (&params.s.modpow(p, &params.n_tilde)
        * &modpow_signed(&params.t, &mu, &params.n_tilde))
        % &params.n_tilde;

    // Compute Q = s^q · t^ν mod Ñ
    let q_commit = (&params.s.modpow(q, &params.n_tilde)
        * &modpow_signed(&params.t, &nu, &params.n_tilde))
        % &params.n_tilde;

    // Sample masking values
    let alpha = sample_pm_range(&bound_alpha);
    let beta = sample_pm_range(&bound_alpha);
    let x = sample_pm_range(&bound_x);
    let y = sample_pm_range(&bound_x);
    let r = sample_pm_range(&bound_r);

    // Compute A = s^α · t^x mod Ñ
    let a_commit = (&modpow_signed(&params.s, &alpha, &params.n_tilde)
        * &modpow_signed(&params.t, &x, &params.n_tilde))
        % &params.n_tilde;

    // Compute B = s^β · t^y mod Ñ
    let b_commit = (&modpow_signed(&params.s, &beta, &params.n_tilde)
        * &modpow_signed(&params.t, &y, &params.n_tilde))
        % &params.n_tilde;

    // Compute T = Q^α · t^r mod Ñ
    let t_commit = (&modpow_signed(&q_commit, &alpha, &params.n_tilde)
        * &modpow_signed(&params.t, &r, &params.n_tilde))
        % &params.n_tilde;

    let commitment = SmallFactorCommitment {
        p_commit: BigUintWrapper(p_commit),
        q_commit: BigUintWrapper(q_commit.clone()),
        a_commit: BigUintWrapper(a_commit),
        b_commit: BigUintWrapper(b_commit),
        t_commit: BigUintWrapper(t_commit),
    };

    // Create transcript for challenge generation
    let mut transcript = Decree::new(
        "small-factor-proof",
        &["commitment"],
        &["challenge"],
    ).unwrap();
    transcript.add("commitment", &commitment).unwrap();

    // Get challenge e ← ±2^ℓ
    let mut challenge_bytes = vec![0u8; (ell as usize).div_ceil(8)];
    transcript.get_challenge("challenge", &mut challenge_bytes).unwrap();
    let e_magnitude = BigUint::from_bytes_le(&challenge_bytes) % BigUint::from(2u32).pow(ell);
    let e = BigInt::from_biguint(Sign::Plus, e_magnitude);

    // Compute responses
    let z1 = &alpha + (&e * BigInt::from_biguint(Sign::Plus, p.clone()));
    let z2 = &beta + (&e * BigInt::from_biguint(Sign::Plus, q.clone()));
    let w1 = &x + (&e * &mu);
    let w2 = &y + (&e * &nu);
    let v = &r - (&e * &nu * BigInt::from_biguint(Sign::Plus, p.clone()));

    let response = SmallFactorResponse {
        z1: BigIntWrapper(z1),
        z2: BigIntWrapper(z2),
        w1: BigIntWrapper(w1),
        w2: BigIntWrapper(w2),
        v: BigIntWrapper(v),
    };

    SmallFactorProof {
        commitment,
        response,
    }
}

/// Verify a small-factor proof
fn verify(
    params: &PedersenParameters,
    proof: &SmallFactorProof,
    n0: &BigUint,
    ell: u32,
) -> bool {
    // Recreate challenge from commitment
    let mut transcript = Decree::new(
        "small-factor-proof",
        &["commitment"],
        &["challenge"],
    ).unwrap();
    transcript.add("commitment", &proof.commitment).unwrap();

    let mut challenge_bytes = vec![0u8; (ell as usize).div_ceil(8)];
    transcript.get_challenge("challenge", &mut challenge_bytes).unwrap();
    let e_magnitude = BigUint::from_bytes_le(&challenge_bytes) % BigUint::from(2u32).pow(ell);
    let e = BigInt::from_biguint(Sign::Plus, e_magnitude);

    // Range check: z₁, z₂ ∈ ±√N₀ · 2^(ℓ+ε)
    let sqrt_n0 = isqrt_ceil(n0);
    let two_ell_eps = BigUint::from(2u32).pow(ell + EPSILON);
    let range_bound = &sqrt_n0 * &two_ell_eps;

    if proof.response.z1.0.magnitude() > &range_bound
        || proof.response.z2.0.magnitude() > &range_bound
    {
        return false;
    }

    // Equality checks
    // Compute R = s^N₀ mod Ñ
    let r_val = params.s.modpow(n0, &params.n_tilde);

    // Check 1: s^z₁ · t^w₁ = A · P^e mod Ñ
    let lhs1 = (&modpow_signed(&params.s, &proof.response.z1.0, &params.n_tilde)
        * &modpow_signed(&params.t, &proof.response.w1.0, &params.n_tilde))
        % &params.n_tilde;

    let rhs1 = (&proof.commitment.a_commit.0
        * &modpow_signed(&proof.commitment.p_commit.0, &e, &params.n_tilde))
        % &params.n_tilde;

    if lhs1 != rhs1 {
        return false;
    }

    // Check 2: s^z₂ · t^w₂ = B · Q^e mod Ñ
    let lhs2 = (&modpow_signed(&params.s, &proof.response.z2.0, &params.n_tilde)
        * &modpow_signed(&params.t, &proof.response.w2.0, &params.n_tilde))
        % &params.n_tilde;

    let rhs2 = (&proof.commitment.b_commit.0
        * &modpow_signed(&proof.commitment.q_commit.0, &e, &params.n_tilde))
        % &params.n_tilde;

    if lhs2 != rhs2 {
        return false;
    }

    // Check 3: Q^z₁ · t^v = T · R^e mod Ñ
    let lhs3 = (&modpow_signed(&proof.commitment.q_commit.0, &proof.response.z1.0, &params.n_tilde)
        * &modpow_signed(&params.t, &proof.response.v.0, &params.n_tilde))
        % &params.n_tilde;

    let rhs3 = (&proof.commitment.t_commit.0 * &modpow_signed(&r_val, &e, &params.n_tilde))
        % &params.n_tilde;

    if lhs3 != rhs3 {
        return false;
    }

    true
}

fn main() {
    // This example demonstrates the small-factor proof in the tests below
    println!("Run `cargo test --example small_factor_proof` to see the proof in action");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_proof() {
        // Generate Pedersen parameters with 2048-bit modulus
        let params = generate_pedersen_parameters(2048);

        // Generate RSA modulus with proper-sized factors
        // Use ℓ = 1000 to ensure 1024-bit primes are above 2^ℓ
        let ell = 1000;
        let (n0, p, q) = generate_rsa_modulus(2048);

        // Verify p and q are above the threshold
        let threshold = BigUint::from(2u32).pow(ell);
        assert!(p > threshold);
        assert!(q > threshold);

        // Generate and verify proof
        let proof = prove(&params, &n0, &p, &q, ell);
        assert!(verify(&params, &proof, &n0, ell));
    }

    #[test]
    fn test_proof_with_different_sizes() {
        // Test with 1536-bit modulus
        let params = generate_pedersen_parameters(1536);
        let ell = 750;  // Below 768 to ensure 768-bit primes exceed threshold
        let (n0, p, q) = generate_rsa_modulus(1536);

        let threshold = BigUint::from(2u32).pow(ell);
        assert!(p > threshold);
        assert!(q > threshold);

        let proof = prove(&params, &n0, &p, &q, ell);
        assert!(verify(&params, &proof, &n0, ell));
    }

    #[test]
    fn test_multiple_proofs() {
        // Generate parameters once
        let params = generate_pedersen_parameters(2048);
        let ell = 1000;

        // Generate and verify multiple proofs
        for _ in 0..3 {
            let (n0, p, q) = generate_rsa_modulus(2048);
            let proof = prove(&params, &n0, &p, &q, ell);
            assert!(verify(&params, &proof, &n0, ell));
        }
    }

    #[test]
    fn test_wrong_modulus() {
        // Generate proof for one modulus
        let params = generate_pedersen_parameters(2048);
        let ell = 1000;
        let (n0, p, q) = generate_rsa_modulus(2048);
        let proof = prove(&params, &n0, &p, &q, ell);

        // Try to verify with different modulus
        let (n0_wrong, _, _) = generate_rsa_modulus(2048);
        assert!(!verify(&params, &proof, &n0_wrong, ell));
    }

    #[test]
    fn test_modified_commitment() {
        let params = generate_pedersen_parameters(2048);
        let ell = 1000;
        let (n0, p, q) = generate_rsa_modulus(2048);
        let mut proof = prove(&params, &n0, &p, &q, ell);

        // Modify one commitment value
        proof.commitment.a_commit.0 = (&proof.commitment.a_commit.0 + BigUint::one()) % &params.n_tilde;

        // Verification should fail
        assert!(!verify(&params, &proof, &n0, ell));
    }

    #[test]
    fn test_modified_response() {
        let params = generate_pedersen_parameters(2048);
        let ell = 1000;
        let (n0, p, q) = generate_rsa_modulus(2048);
        let mut proof = prove(&params, &n0, &p, &q, ell);

        // Modify one response value
        proof.response.z1.0 = &proof.response.z1.0 + BigInt::one();

        // Verification should fail
        assert!(!verify(&params, &proof, &n0, ell));
    }
}
