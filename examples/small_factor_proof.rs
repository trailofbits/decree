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

mod crypto_helpers;

use decree::error::Error;
use decree::Inscribe;
use decree::decree::{Decree, FSInput};
use crypto_helpers::{extended_gcd, generate_prime};
use num_bigint::{BigInt, BigUint, RandBigInt, Sign};
use num_traits::{One, Zero};
use rand::rngs::OsRng;
use rand::Rng;

/// Statistical hiding parameter for small-factor proof
const SMALL_FACTOR_EPSILON: u32 = 524;

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
    let two_ell_eps = BigUint::from(2u32).pow(ell + SMALL_FACTOR_EPSILON);
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
    let mut challenge_bytes = vec![0u8; (ell as usize).div_ceil(8) + 1];
    transcript.get_challenge("challenge", &mut challenge_bytes).unwrap();
    let e_magnitude = BigUint::from_bytes_le(&challenge_bytes[..challenge_bytes.len()-1]) % BigUint::from(2u32).pow(ell);
    let sign = if challenge_bytes[challenge_bytes.len()-1] & 1 == 0 { Sign::Plus } else { Sign::Minus };
    let e = BigInt::from_biguint(sign, e_magnitude);

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
) -> Result<(), Error> {
    // Check protocol preconditions
    // Requirement 1: N₀ > 2^4ℓ
    let four_ell = 4 * ell;
    if n0.bits() as u32 <= four_ell {
        return Err(Error::new_general("N₀ must be > 2^4ℓ"));
    }

    // Requirement 2: 2^(ℓ+ε) ≈ √N₀
    // Check that |2^(ℓ+ε) - √N₀| is reasonable (within factor of 2)
    let sqrt_n0 = isqrt_ceil(n0);
    let sqrt_n0_bits = sqrt_n0.bits() as u32;
    let ell_plus_epsilon = ell + SMALL_FACTOR_EPSILON;
    if sqrt_n0_bits < ell_plus_epsilon.saturating_sub(1) || sqrt_n0_bits > ell_plus_epsilon + 1 {
        return Err(Error::new_general("2^(ℓ+ε) must approximate √N₀"));
    }

    // Recreate challenge from commitment
    let mut transcript = Decree::new(
        "small-factor-proof",
        &["commitment"],
        &["challenge"],
    ).unwrap();
    transcript.add("commitment", &proof.commitment).unwrap();

    let mut challenge_bytes = vec![0u8; (ell as usize).div_ceil(8) + 1];
    transcript.get_challenge("challenge", &mut challenge_bytes).unwrap();
    let e_magnitude = BigUint::from_bytes_le(&challenge_bytes[..challenge_bytes.len()-1]) % BigUint::from(2u32).pow(ell);
    let sign = if challenge_bytes[challenge_bytes.len()-1] & 1 == 0 { Sign::Plus } else { Sign::Minus };
    let e = BigInt::from_biguint(sign, e_magnitude);

    // Range check: z₁, z₂ ∈ ±√N₀ · 2^(ℓ+ε)
    let sqrt_n0 = isqrt_ceil(n0);
    let two_ell_eps = BigUint::from(2u32).pow(ell + SMALL_FACTOR_EPSILON);
    let range_bound = &sqrt_n0 * &two_ell_eps;

    if proof.response.z1.0.magnitude() > &range_bound
        || proof.response.z2.0.magnitude() > &range_bound
    {
        return Err(Error::new_general("Range check failed"));
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
        return Err(Error::new_general("Equality check 1 failed"));
    }

    // Check 2: s^z₂ · t^w₂ = B · Q^e mod Ñ
    let lhs2 = (&modpow_signed(&params.s, &proof.response.z2.0, &params.n_tilde)
        * &modpow_signed(&params.t, &proof.response.w2.0, &params.n_tilde))
        % &params.n_tilde;

    let rhs2 = (&proof.commitment.b_commit.0
        * &modpow_signed(&proof.commitment.q_commit.0, &e, &params.n_tilde))
        % &params.n_tilde;

    if lhs2 != rhs2 {
        return Err(Error::new_general("Equality check 2 failed"));
    }

    // Check 3: Q^z₁ · t^v = T · R^e mod Ñ
    let lhs3 = (&modpow_signed(&proof.commitment.q_commit.0, &proof.response.z1.0, &params.n_tilde)
        * &modpow_signed(&params.t, &proof.response.v.0, &params.n_tilde))
        % &params.n_tilde;

    let rhs3 = (&proof.commitment.t_commit.0 * &modpow_signed(&r_val, &e, &params.n_tilde))
        % &params.n_tilde;

    if lhs3 != rhs3 {
        return Err(Error::new_general("Equality check 3 failed"));
    }

    Ok(())
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
        // For 2048-bit N₀: need N₀ > 2^4ℓ and 2^(ℓ+524) ≈ 2^1024
        // So ℓ ≈ 500
        let ell = 500;
        let (n0, p, q) = generate_rsa_modulus(2048);

        // Verify p and q are above the threshold
        let threshold = BigUint::from(2u32).pow(ell);
        assert!(p > threshold);
        assert!(q > threshold);

        // Generate and verify proof
        let proof = prove(&params, &n0, &p, &q, ell);
        assert!(verify(&params, &proof, &n0, ell).is_ok());
    }

    #[test]
    fn test_proof_with_different_sizes() {
        // Test with 1536-bit modulus
        let params = generate_pedersen_parameters(1536);
        // For 1536-bit N₀: √N₀ ≈ 2^768, so ℓ + 524 ≈ 768, so ℓ ≈ 244
        let ell = 244;
        let (n0, p, q) = generate_rsa_modulus(1536);

        let threshold = BigUint::from(2u32).pow(ell);
        assert!(p > threshold);
        assert!(q > threshold);

        let proof = prove(&params, &n0, &p, &q, ell);
        assert!(verify(&params, &proof, &n0, ell).is_ok());
    }

    #[test]
    fn test_multiple_proofs() {
        // Generate parameters once
        let params = generate_pedersen_parameters(2048);
        let ell = 500;

        // Generate and verify multiple proofs
        for _ in 0..3 {
            let (n0, p, q) = generate_rsa_modulus(2048);
            let proof = prove(&params, &n0, &p, &q, ell);
            assert!(verify(&params, &proof, &n0, ell).is_ok());
        }
    }

    #[test]
    fn test_wrong_modulus() {
        // Generate proof for one modulus
        let params = generate_pedersen_parameters(2048);
        let ell = 500;
        let (n0, p, q) = generate_rsa_modulus(2048);
        let proof = prove(&params, &n0, &p, &q, ell);

        // Try to verify with different modulus
        let (n0_wrong, _, _) = generate_rsa_modulus(2048);
        assert!(verify(&params, &proof, &n0_wrong, ell).is_err());
    }

    #[test]
    fn test_modified_commitment() {
        let params = generate_pedersen_parameters(2048);
        let ell = 500;
        let (n0, p, q) = generate_rsa_modulus(2048);
        let mut proof = prove(&params, &n0, &p, &q, ell);

        // Modify one commitment value
        proof.commitment.a_commit.0 = (&proof.commitment.a_commit.0 + BigUint::one()) % &params.n_tilde;

        // Verification should fail
        assert!(verify(&params, &proof, &n0, ell).is_err());
    }

    #[test]
    fn test_modified_response() {
        let params = generate_pedersen_parameters(2048);
        let ell = 500;
        let (n0, p, q) = generate_rsa_modulus(2048);
        let mut proof = prove(&params, &n0, &p, &q, ell);

        // Modify one response value
        proof.response.z1.0 = &proof.response.z1.0 + BigInt::one();

        // Verification should fail
        assert!(verify(&params, &proof, &n0, ell).is_err());
    }

    #[test]
    fn test_invalid_ell_too_large() {
        let params = generate_pedersen_parameters(2048);
        let (n0, p, q) = generate_rsa_modulus(2048);

        // Use ℓ that violates N₀ > 2^4ℓ (2048 ≤ 4*512 = 2048)
        let ell = 512;
        let proof = prove(&params, &n0, &p, &q, ell);

        // Verification should fail parameter check
        assert!(verify(&params, &proof, &n0, ell).is_err());
    }

    #[test]
    fn test_invalid_ell_wrong_approximation() {
        let params = generate_pedersen_parameters(2048);
        let (n0, p, q) = generate_rsa_modulus(2048);

        // Use ℓ that violates 2^(ℓ+ε) ≈ √N₀ approximation
        let ell = 300;  // 2^(300+524) = 2^824, but √N₀ ≈ 2^1024
        let proof = prove(&params, &n0, &p, &q, ell);

        // Verification should fail approximation check
        assert!(verify(&params, &proof, &n0, ell).is_err());
    }
}
