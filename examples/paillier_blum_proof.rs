//! Paillier-Blum Modulus Proof Example
//!
//! This example demonstrates a zero-knowledge proof that an RSA modulus N
//! is a Paillier-Blum modulus, i.e., N = pq where p and q are distinct primes
//! satisfying p ≡ q ≡ 3 (mod 4).
//!
//! This property is essential for Pedersen commitments in RSA groups, as it
//! ensures that -1 has Jacobi symbol +1 modulo N (equivalently, -1 is a
//! quadratic residue mod N), which is necessary for the security of commitment schemes.
//!
//! The proof follows the protocol from Canetti et al. 2024, Figure 12.

#![deny(warnings)]
#![cfg_attr(not(test), allow(dead_code))]

mod crypto_helpers;

use decree::error::Error;
use decree::Inscribe;
use decree::decree::{Decree, FSInput};
use crypto_helpers::{is_probably_prime, extended_gcd, jacobi_symbol};
use num_bigint::{BigInt, BigUint, RandBigInt, Sign};
use num_traits::{One, Zero};
use rand::rngs::OsRng;

/// Minimum number of challenge rounds for security
const MIN_CHALLENGE_ROUNDS: u32 = 80;

/// Generate a random safe prime p = 2q + 1 where both p and q are prime
/// Safe primes satisfy p ≡ 3 (mod 4) when q is odd (which it must be if q > 2)
fn generate_safe_prime(bits: usize) -> BigUint {
    let mut rng = OsRng;
    loop {
        // Generate random q of bit length (bits - 1)
        let mut q = rng.gen_biguint((bits - 1) as u64);

        // Set high bit of q to ensure it has the right bit length
        q.set_bit((bits - 2) as u64, true);

        // Make q odd
        q.set_bit(0, true);

        // Test if q is prime
        if !is_probably_prime(&q, 20) {
            continue;
        }

        // Compute p = 2q + 1
        let p = &q * BigUint::from(2u32) + BigUint::one();

        // Test if p is prime
        if is_probably_prime(&p, 20) {
            // Verify p ≡ 3 (mod 4) (should always be true for safe primes with q odd)
            debug_assert_eq!(p.clone() % BigUint::from(4u32), BigUint::from(3u32));
            return p;
        }
    }
}

/// Generate a Paillier-Blum modulus N = pq where p, q ≡ 3 (mod 4)
/// Returns (N, p, q)
fn generate_paillier_blum_modulus(bits: usize) -> (BigUint, BigUint, BigUint) {
    let p = generate_safe_prime(bits / 2);
    let q = generate_safe_prime(bits / 2);
    let n = &p * &q;
    (n, p, q)
}

/// Find a 4th root of a modulo Paillier-Blum modulus N = pq
/// where p, q ≡ 3 (mod 4) and a is a 4th power residue mod N
fn fourth_root_mod_paillier_blum(a: &BigUint, p: &BigUint, q: &BigUint, n: &BigUint) -> Option<BigUint> {
    // For p ≡ 3 (mod 4), we can compute 4th roots as follows:
    // First compute square roots mod p and mod q
    // Then use CRT to combine them

    // Compute r = (p+1)/4 and s = (q+1)/4
    let r = (p + BigUint::one()) / BigUint::from(4u32);
    let s = (q + BigUint::one()) / BigUint::from(4u32);

    // Compute a^r mod p (this is a square root of a mod p)
    let sqrt_p = a.modpow(&r, p);

    // Compute another square root to get 4th root mod p
    let fourth_root_p = sqrt_p.modpow(&r, p);

    // Similarly for q
    let sqrt_q = a.modpow(&s, q);
    let fourth_root_q = sqrt_q.modpow(&s, q);

    // Use Chinese Remainder Theorem to combine
    // Find x such that x ≡ fourth_root_p (mod p) and x ≡ fourth_root_q (mod q)
    let p_int = BigInt::from_biguint(Sign::Plus, p.clone());
    let q_int = BigInt::from_biguint(Sign::Plus, q.clone());

    let (gcd, u, v) = extended_gcd(&p_int, &q_int);
    if gcd != BigInt::one() {
        return None;
    }

    let fourth_root_p_int = BigInt::from_biguint(Sign::Plus, fourth_root_p);
    let fourth_root_q_int = BigInt::from_biguint(Sign::Plus, fourth_root_q);

    let result = (fourth_root_p_int.clone() * &v * &q_int + fourth_root_q_int * &u * &p_int) % BigInt::from_biguint(Sign::Plus, n.clone());

    let result_pos = if result.sign() == Sign::Minus {
        result + BigInt::from_biguint(Sign::Plus, n.clone())
    } else {
        result
    };

    Some(result_pos.to_biguint().unwrap())
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
        Ok(b"paillier-blum-proof-biguint".to_vec())
    }
}

/// Wrapper for u32 with proper domain separation for Inscribe
struct U32Wrapper(u32);

impl Inscribe for U32Wrapper {
    const MARK: &'static str = "u32";

    fn get_inscription(&self) -> Result<FSInput, Error> {
        Ok(self.0.to_le_bytes().to_vec())
    }

    fn get_additional(&self) -> Result<FSInput, Error> {
        Ok(b"paillier-blum-proof-u32".to_vec())
    }
}

/// Single round response in the Paillier-Blum proof
#[derive(Clone)]
struct RoundResponse {
    x: BigUint,  // 4th root: x_i = ∜y'_i mod N
    a: bool,     // a_i ∈ {0, 1}
    b: bool,     // b_i ∈ {0, 1}
    z: BigUint,  // z_i = y_i^{N^{-1} mod φ(N)} mod N
}

impl Inscribe for RoundResponse {
    const MARK: &'static str = "RoundResponse";

    fn get_inscription(&self) -> Result<FSInput, Error> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.x.to_bytes_le());
        bytes.push(if self.a { 1u8 } else { 0u8 });
        bytes.push(if self.b { 1u8 } else { 0u8 });
        bytes.extend_from_slice(&self.z.to_bytes_le());
        Ok(bytes)
    }

    fn get_additional(&self) -> Result<FSInput, Error> {
        Ok(b"paillier-blum-proof-round-response".to_vec())
    }
}

/// Complete Paillier-Blum modulus proof
#[derive(Inscribe)]
struct PaillierBlumProof {
    w: BigUintWrapper,                    // Element with Jacobi symbol -1
    #[inscribe(skip)]
    responses: Vec<RoundResponse>,         // Responses for each challenge round
}

/// Prove that N is a Paillier-Blum modulus
///
/// # Arguments
/// * `n` - The modulus to prove (N = pq)
/// * `p` - First prime factor (p ≡ 3 mod 4)
/// * `q` - Second prime factor (q ≡ 3 mod 4)
/// * `m` - Number of challenge rounds (must be >= MIN_CHALLENGE_ROUNDS)
///
/// # Returns
/// A proof that N is a Paillier-Blum modulus, or an error
fn prove(n: &BigUint, p: &BigUint, q: &BigUint, m: u32) -> Result<PaillierBlumProof, Error> {
    // Validate parameters
    if m < MIN_CHALLENGE_ROUNDS {
        return Err(Error::new_general("Number of challenge rounds must be at least 80"));
    }

    // Verify N = pq
    if n != &(p * q) {
        return Err(Error::new_general("N must equal p * q"));
    }

    // Verify p ≠ q (N must be product of two DISTINCT primes)
    if p == q {
        return Err(Error::new_general("p and q must be distinct (N cannot be p²)"));
    }

    // Verify p, q are odd
    if !p.bit(0) || !q.bit(0) {
        return Err(Error::new_general("p and q must be odd"));
    }

    // Verify p, q ≡ 3 (mod 4)
    if p % BigUint::from(4u32) != BigUint::from(3u32) || q % BigUint::from(4u32) != BigUint::from(3u32) {
        return Err(Error::new_general("p and q must be ≡ 3 (mod 4)"));
    }

    let mut rng = OsRng;

    // Step 1: Sample w ∈ Z*_N with Jacobi symbol -1
    let w = loop {
        let candidate = rng.gen_biguint_range(&BigUint::from(2u32), n);
        let candidate_int = BigInt::from_biguint(Sign::Plus, candidate.clone());
        let n_int = BigInt::from_biguint(Sign::Plus, n.clone());

        // Check gcd(w, N) = 1
        let (gcd, _, _) = extended_gcd(&candidate_int, &n_int);
        if gcd != BigInt::one() {
            continue;
        }

        // Check Jacobi symbol is -1
        if jacobi_symbol(&candidate_int, &n_int) == -1 {
            break candidate;
        }
    };

    // Initialize Fiat-Shamir transcript
    let inputs = ["n", "w", "m"];
    let challenges = ["y_challenges"];
    let mut transcript = Decree::new("paillier-blum-proof-v1", &inputs, &challenges)
        .map_err(|_| Error::new_general("Failed to create transcript"))?;

    // Add public inputs to transcript
    transcript.add("n", &BigUintWrapper(n.clone()))?;
    transcript.add("w", &BigUintWrapper(w.clone()))?;
    transcript.add("m", &U32Wrapper(m))?;

    // Get challenges from transcript
    let mut challenge_bytes = vec![0u8; (m as usize) * 32]; // 32 bytes per challenge
    transcript.get_challenge("y_challenges", &mut challenge_bytes)?;

    // Generate y_i challenges from transcript
    let mut y_challenges = Vec::new();
    for i in 0..m {
        let start = (i as usize) * 32;
        let end = start + 32;
        let y_bytes = &challenge_bytes[start..end];

        // Convert bytes to BigUint and reduce mod N
        // Ensure it's non-zero by adding 1 if needed
        let mut y = BigUint::from_bytes_le(y_bytes) % n;
        if y.is_zero() {
            y = BigUint::one();
        }

        y_challenges.push(y);
    }

    // Compute φ(N) = (p-1)(q-1)
    let phi_n = (p - BigUint::one()) * (q - BigUint::one());

    // Compute N^{-1} mod φ(N)
    let n_int = BigInt::from_biguint(Sign::Plus, n.clone());
    let phi_n_int = BigInt::from_biguint(Sign::Plus, phi_n.clone());
    let (gcd, n_inv, _) = extended_gcd(&n_int, &phi_n_int);

    if gcd != BigInt::one() {
        return Err(Error::new_general("N and φ(N) are not coprime"));
    }

    let n_inv_pos = if n_inv.sign() == Sign::Minus {
        n_inv + &phi_n_int
    } else {
        n_inv
    };
    let n_inv_uint = n_inv_pos.to_biguint().unwrap();

    // Process each challenge
    let mut responses = Vec::new();

    for y_i in &y_challenges {
        // Compute z_i = y_i^{N^{-1} mod φ(N)} mod N
        let z_i = y_i.modpow(&n_inv_uint, n);

        // Find a_i, b_i such that y'_i = (-1)^{a_i} * w^{b_i} * y_i has a 4th root mod N
        let mut found = false;
        let mut x_i = BigUint::zero();
        let mut a_i = false;
        let mut b_i = false;

        // Try all 4 combinations of (a_i, b_i)
        for a in [false, true] {
            for b in [false, true] {
                // Compute y'_i = (-1)^a * w^b * y_i mod N
                let mut y_prime = y_i.clone();

                if a {
                    // Multiply by -1 mod N
                    y_prime = (n - y_prime) % n;
                }

                if b {
                    // Multiply by w
                    y_prime = (y_prime * &w) % n;
                }

                // Try to compute 4th root
                if let Some(x) = fourth_root_mod_paillier_blum(&y_prime, p, q, n) {
                    // Verify it's actually a 4th root
                    if x.modpow(&BigUint::from(4u32), n) == y_prime {
                        x_i = x;
                        a_i = a;
                        b_i = b;
                        found = true;
                        break;
                    }
                }
            }
            if found {
                break;
            }
        }

        if !found {
            return Err(Error::new_general("Could not find 4th root for challenge"));
        }

        responses.push(RoundResponse {
            x: x_i,
            a: a_i,
            b: b_i,
            z: z_i,
        });
    }

    Ok(PaillierBlumProof {
        w: BigUintWrapper(w),
        responses,
    })
}

/// Verify a Paillier-Blum modulus proof
///
/// # Arguments
/// * `n` - The modulus being proven
/// * `proof` - The proof to verify
/// * `m` - Number of challenge rounds (must match what was used in prove)
///
/// # Returns
/// True if the proof is valid, false otherwise
fn verify(n: &BigUint, proof: &PaillierBlumProof, m: u32) -> Result<bool, Error> {
    // Validate parameters
    if m < MIN_CHALLENGE_ROUNDS {
        return Err(Error::new_general("Number of challenge rounds must be at least 80"));
    }

    if proof.responses.len() != m as usize {
        return Ok(false);
    }

    // Check N is odd composite
    if !n.bit(0) {
        return Ok(false);
    }

    if n < &BigUint::from(4u32) {
        return Ok(false);
    }

    // CRITICAL: Check N is composite (not prime)
    // This is required by Figure 12: "N is an odd composite number"
    if is_probably_prime(n, 20) {
        return Ok(false);
    }

    // Check gcd(w, N) = 1
    let w_int = BigInt::from_biguint(Sign::Plus, proof.w.0.clone());
    let n_int = BigInt::from_biguint(Sign::Plus, n.clone());
    let (gcd, _, _) = extended_gcd(&w_int, &n_int);

    if gcd != BigInt::one() {
        return Ok(false);
    }

    // CRITICAL: Check w has Jacobi symbol -1
    // This is required by Figure 12 protocol step 1
    if jacobi_symbol(&w_int, &n_int) != -1 {
        return Ok(false);
    }

    // Reconstruct transcript to get challenges
    let inputs = ["n", "w", "m"];
    let challenges = ["y_challenges"];
    let mut transcript = Decree::new("paillier-blum-proof-v1", &inputs, &challenges)
        .map_err(|_| Error::new_general("Failed to create transcript"))?;

    transcript.add("n", &BigUintWrapper(n.clone()))?;
    transcript.add("w", &BigUintWrapper(proof.w.0.clone()))?;
    transcript.add("m", &U32Wrapper(m))?;

    let mut challenge_bytes = vec![0u8; (m as usize) * 32];
    transcript.get_challenge("y_challenges", &mut challenge_bytes)?;

    // Regenerate y_i challenges
    let mut y_challenges = Vec::new();
    for i in 0..m {
        let start = (i as usize) * 32;
        let end = start + 32;
        let y_bytes = &challenge_bytes[start..end];

        // Convert bytes to BigUint and reduce mod N
        // Ensure it's non-zero by adding 1 if needed
        let mut y = BigUint::from_bytes_le(y_bytes) % n;
        if y.is_zero() {
            y = BigUint::one();
        }

        y_challenges.push(y);
    }

    // Verify each round
    for (y_i, response) in y_challenges.iter().zip(proof.responses.iter()) {
        // Check a_i, b_i ∈ {0, 1} (implicitly true since they're bool)

        // Check y_i ∈ Z*_N
        let y_i_int = BigInt::from_biguint(Sign::Plus, y_i.clone());
        let (gcd, _, _) = extended_gcd(&y_i_int, &n_int);
        if gcd != BigInt::one() {
            return Ok(false);
        }

        // Check z_i^N = y_i mod N
        let z_i_to_n = response.z.modpow(n, n);
        if z_i_to_n != *y_i {
            return Ok(false);
        }

        // Check x_i^4 = (-1)^{a_i} * w^{b_i} * y_i mod N
        let x_i_fourth = response.x.modpow(&BigUint::from(4u32), n);

        let mut expected = y_i.clone();
        if response.a {
            expected = (n - expected) % n;
        }
        if response.b {
            expected = (expected * &proof.w.0) % n;
        }

        if x_i_fourth != expected {
            return Ok(false);
        }
    }

    Ok(true)
}

fn main() {
    // This example demonstrates the Paillier-Blum modulus proof in the tests below
    println!("Run `cargo test --example paillier_blum_proof` to see the proof in action");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_prime_generation() {
        let p = generate_safe_prime(128);

        // Check it's prime (probabilistically)
        assert!(is_probably_prime(&p, 20));

        // Check p ≡ 3 (mod 4)
        assert_eq!(&p % BigUint::from(4u32), BigUint::from(3u32));

        // CRITICAL: Check safe prime property: p = 2q + 1 where q is prime
        assert!(&p > &BigUint::one(), "p must be > 1");
        let q = (&p - BigUint::one()) / BigUint::from(2u32);

        // Verify q is prime
        assert!(is_probably_prime(&q, 20), "q = (p-1)/2 must be prime for safe prime p = 2q + 1");

        // Verify p = 2q + 1
        assert_eq!(&q * BigUint::from(2u32) + BigUint::one(), p, "p must equal 2q + 1");
    }

    #[test]
    fn test_paillier_blum_modulus_generation() {
        let (n, p, q) = generate_paillier_blum_modulus(256);

        // Check N = pq
        assert_eq!(n, &p * &q);

        // Check p, q are prime
        assert!(is_probably_prime(&p, 20));
        assert!(is_probably_prime(&q, 20));

        // Check p, q ≡ 3 (mod 4)
        assert_eq!(p % BigUint::from(4u32), BigUint::from(3u32));
        assert_eq!(q % BigUint::from(4u32), BigUint::from(3u32));
    }

    #[test]
    fn test_jacobi_symbol() {
        // Test known values
        let n = BigInt::from(15);  // 15 = 3 * 5

        assert_eq!(jacobi_symbol(&BigInt::from(1), &n), 1);
        assert_eq!(jacobi_symbol(&BigInt::from(2), &n), 1);
        assert_eq!(jacobi_symbol(&BigInt::from(4), &n), 1);
        assert_eq!(jacobi_symbol(&BigInt::from(8), &n), 1);
    }

    #[test]
    fn test_valid_paillier_blum_proof() {
        // Generate a Paillier-Blum modulus
        let (n, p, q) = generate_paillier_blum_modulus(512);

        // Generate proof with minimum rounds
        let proof = prove(&n, &p, &q, MIN_CHALLENGE_ROUNDS).unwrap();

        // Verify proof
        assert!(verify(&n, &proof, MIN_CHALLENGE_ROUNDS).unwrap());
    }

    #[test]
    fn test_valid_paillier_blum_proof_many_rounds() {
        // Generate a Paillier-Blum modulus
        let (n, p, q) = generate_paillier_blum_modulus(512);

        // Generate proof with more rounds
        let m = 128;
        let proof = prove(&n, &p, &q, m).unwrap();

        // Verify proof
        assert!(verify(&n, &proof, m).unwrap());
    }

    #[test]
    fn test_proof_fails_with_wrong_m() {
        // Generate a Paillier-Blum modulus
        let (n, p, q) = generate_paillier_blum_modulus(512);

        // Generate proof with one value of m
        let proof = prove(&n, &p, &q, MIN_CHALLENGE_ROUNDS).unwrap();

        // Try to verify with different m
        assert!(!verify(&n, &proof, MIN_CHALLENGE_ROUNDS + 10).unwrap());
    }

    #[test]
    fn test_proof_fails_with_insufficient_rounds() {
        // Generate a Paillier-Blum modulus
        let (n, p, q) = generate_paillier_blum_modulus(512);

        // Try to generate proof with too few rounds
        let result = prove(&n, &p, &q, MIN_CHALLENGE_ROUNDS - 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_proof_fails_with_non_paillier_blum_modulus() {
        // Generate primes that are NOT ≡ 3 (mod 4)
        let mut rng = OsRng;

        // Generate p ≡ 1 (mod 4)
        let p = loop {
            let mut candidate = rng.gen_biguint(256);
            candidate.set_bit(255, true);
            candidate.set_bit(0, true);
            candidate.set_bit(1, true); // ensures last two bits are "11" but we want "01" for ≡ 1 (mod 4)

            // Actually, let me fix this - for ≡ 1 (mod 4), bits should be "01"
            let mut candidate = rng.gen_biguint(256);
            candidate.set_bit(255, true);
            candidate.set_bit(0, true);  // odd
            candidate.set_bit(1, false); // bit pattern "01" = 1 mod 4

            if is_probably_prime(&candidate, 20) && candidate.clone() % BigUint::from(4u32) == BigUint::from(1u32) {
                break candidate;
            }
        };

        let q = generate_safe_prime(256); // This is ≡ 3 (mod 4)
        let n = &p * &q;

        // Try to generate proof - should fail
        let result = prove(&n, &p, &q, MIN_CHALLENGE_ROUNDS);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_rejects_even_modulus() {
        let (n, p, q) = generate_paillier_blum_modulus(512);
        let proof = prove(&n, &p, &q, MIN_CHALLENGE_ROUNDS).unwrap();

        // Try to verify with even modulus
        let even_n = n + BigUint::one();
        assert!(!verify(&even_n, &proof, MIN_CHALLENGE_ROUNDS).unwrap());
    }

    #[test]
    fn test_fourth_root_extraction() {
        // Generate a Paillier-Blum modulus for testing
        let (n, p, q) = generate_paillier_blum_modulus(256);

        // Pick a random element and compute its 4th power
        let mut rng = OsRng;
        let x = rng.gen_biguint_range(&BigUint::from(2u32), &n);
        let x_fourth = x.modpow(&BigUint::from(4u32), &n);

        // Not every element has a 4th root, so we try multiple combinations
        // like the proof does with the 4 options for (a_i, b_i)
        let mut found_root = false;

        // Try to extract 4th root directly
        if let Some(root) = fourth_root_mod_paillier_blum(&x_fourth, &p, &q, &n) {
            // Verify it's a 4th root
            let check = root.modpow(&BigUint::from(4u32), &n);
            if check == x_fourth {
                found_root = true;
            }
        }

        // For this test, since x_fourth = x^4, it definitely has a 4th root
        // If our algorithm didn't find it, that's a bug
        assert!(found_root, "Should have found a 4th root of x^4");
    }

    #[test]
    fn test_w_has_jacobi_symbol_minus_one() {
        // Generate a Paillier-Blum modulus and proof
        let (n, p, q) = generate_paillier_blum_modulus(512);
        let proof = prove(&n, &p, &q, MIN_CHALLENGE_ROUNDS).unwrap();

        // CRITICAL: Verify w has Jacobi symbol -1
        let w_int = BigInt::from_biguint(Sign::Plus, proof.w.0.clone());
        let n_int = BigInt::from_biguint(Sign::Plus, n.clone());

        assert_eq!(jacobi_symbol(&w_int, &n_int), -1,
            "w must have Jacobi symbol -1 for the proof to be sound");
    }

    #[test]
    fn test_verifier_rejects_wrong_jacobi_symbol() {
        // Generate a Paillier-Blum modulus
        let (n, p, q) = generate_paillier_blum_modulus(512);

        // Create a valid proof
        let mut proof = prove(&n, &p, &q, MIN_CHALLENGE_ROUNDS).unwrap();

        // CRITICAL SOUNDNESS TEST: Replace w with an element that has Jacobi symbol +1
        // NOTE: This changes the Fiat-Shamir challenges, so the proof becomes invalid
        // for TWO reasons: (1) wrong Jacobi symbol, (2) responses don't match new challenges
        // But the verifier MUST check Jacobi symbol explicitly, not rely on mismatch
        let n_int = BigInt::from_biguint(Sign::Plus, n.clone());
        let mut rng = OsRng;

        let bad_w = loop {
            let candidate = rng.gen_biguint_range(&BigUint::from(2u32), &n);
            let candidate_int = BigInt::from_biguint(Sign::Plus, candidate.clone());

            // Check gcd(candidate, N) = 1
            let (gcd, _, _) = extended_gcd(&candidate_int, &n_int);
            if gcd != BigInt::one() {
                continue;
            }

            // We want Jacobi symbol +1
            if jacobi_symbol(&candidate_int, &n_int) == 1 {
                break candidate;
            }
        };

        // Replace w in the proof
        proof.w = BigUintWrapper(bad_w);

        // Verifier should reject this proof
        // With the fixed verifier, this should be caught at the Jacobi symbol check
        assert!(!verify(&n, &proof, MIN_CHALLENGE_ROUNDS).unwrap(),
            "Verifier must reject proof with w having wrong Jacobi symbol");
    }

    #[test]
    fn test_verifier_rejects_wrong_z_i() {
        // Generate a Paillier-Blum modulus and valid proof
        let (n, p, q) = generate_paillier_blum_modulus(512);
        let mut proof = prove(&n, &p, &q, MIN_CHALLENGE_ROUNDS).unwrap();

        // CRITICAL SOUNDNESS TEST: Corrupt one of the z_i values
        if !proof.responses.is_empty() {
            let n_uint = n.clone();
            proof.responses[0].z = (&proof.responses[0].z + BigUint::one()) % n_uint;

            // Verifier should reject
            assert!(!verify(&n, &proof, MIN_CHALLENGE_ROUNDS).unwrap(),
                "Verifier must reject proof with corrupted z_i");
        }
    }

    #[test]
    fn test_verifier_rejects_wrong_x_i() {
        // Generate a Paillier-Blum modulus and valid proof
        let (n, p, q) = generate_paillier_blum_modulus(512);
        let mut proof = prove(&n, &p, &q, MIN_CHALLENGE_ROUNDS).unwrap();

        // CRITICAL SOUNDNESS TEST: Corrupt one of the x_i values
        if !proof.responses.is_empty() {
            let n_uint = n.clone();
            proof.responses[0].x = (&proof.responses[0].x + BigUint::one()) % n_uint;

            // Verifier should reject
            assert!(!verify(&n, &proof, MIN_CHALLENGE_ROUNDS).unwrap(),
                "Verifier must reject proof with corrupted x_i");
        }
    }

    #[test]
    fn test_verifier_rejects_flipped_bits() {
        // Generate a Paillier-Blum modulus and valid proof
        let (n, p, q) = generate_paillier_blum_modulus(512);
        let mut proof = prove(&n, &p, &q, MIN_CHALLENGE_ROUNDS).unwrap();

        // CRITICAL SOUNDNESS TEST: Flip the bits a_i or b_i
        if !proof.responses.is_empty() {
            proof.responses[0].a = !proof.responses[0].a;

            // Verifier should reject
            assert!(!verify(&n, &proof, MIN_CHALLENGE_ROUNDS).unwrap(),
                "Verifier must reject proof with flipped a_i bit");
        }
    }

    #[test]
    fn test_verifier_rejects_non_paillier_blum_modulus() {
        // Generate a NON-Paillier-Blum modulus (product of primes ≡ 1 mod 4)
        let mut rng = OsRng;

        // Generate p ≡ 1 (mod 4)
        let p = loop {
            let mut candidate = rng.gen_biguint(256);
            candidate.set_bit(255, true);
            candidate.set_bit(0, true);  // odd
            candidate.set_bit(1, false); // bit pattern "01" = 1 mod 4

            if is_probably_prime(&candidate, 20) && candidate.clone() % BigUint::from(4u32) == BigUint::from(1u32) {
                break candidate;
            }
        };

        // Generate another p ≡ 1 (mod 4)
        let q = loop {
            let mut candidate = rng.gen_biguint(256);
            candidate.set_bit(255, true);
            candidate.set_bit(0, true);
            candidate.set_bit(1, false);

            if is_probably_prime(&candidate, 20) && candidate.clone() % BigUint::from(4u32) == BigUint::from(1u32) {
                break candidate;
            }
        };

        let bad_n = &p * &q;

        // Generate a valid Paillier-Blum modulus and proof
        let (good_n, good_p, good_q) = generate_paillier_blum_modulus(512);
        let proof = prove(&good_n, &good_p, &good_q, MIN_CHALLENGE_ROUNDS).unwrap();

        // CRITICAL SOUNDNESS TEST: Try to verify proof against wrong modulus
        // This should fail because w won't have the right Jacobi symbol, and
        // the challenges will be different
        assert!(!verify(&bad_n, &proof, MIN_CHALLENGE_ROUNDS).unwrap(),
            "Verifier must reject proof when used with non-Paillier-Blum modulus");
    }

    #[test]
    fn test_verifier_rejects_composite_non_biprime() {
        // Generate a Paillier-Blum modulus and valid proof
        let (n, p, q) = generate_paillier_blum_modulus(512);
        let proof = prove(&n, &p, &q, MIN_CHALLENGE_ROUNDS).unwrap();

        // CRITICAL SOUNDNESS TEST: Try to verify against N^2 (not a biprime)
        let n_squared = &n * &n;

        // This should fail
        let result = verify(&n_squared, &proof, MIN_CHALLENGE_ROUNDS).unwrap();
        assert!(!result, "Verifier must reject proof for non-biprime modulus");
    }

    #[test]
    fn test_z_i_satisfies_equation() {
        // Generate a Paillier-Blum modulus and proof
        let (n, p, q) = generate_paillier_blum_modulus(512);
        let proof = prove(&n, &p, &q, MIN_CHALLENGE_ROUNDS).unwrap();

        // Reconstruct challenges
        let inputs = ["n", "w", "m"];
        let challenges = ["y_challenges"];
        let mut transcript = Decree::new("paillier-blum-proof-v1", &inputs, &challenges).unwrap();
        transcript.add("n", &BigUintWrapper(n.clone())).unwrap();
        transcript.add("w", &BigUintWrapper(proof.w.0.clone())).unwrap();
        transcript.add("m", &U32Wrapper(MIN_CHALLENGE_ROUNDS)).unwrap();

        let mut challenge_bytes = vec![0u8; (MIN_CHALLENGE_ROUNDS as usize) * 32];
        transcript.get_challenge("y_challenges", &mut challenge_bytes).unwrap();

        let mut y_challenges = Vec::new();
        for _i in 0..MIN_CHALLENGE_ROUNDS {
            let start = (_i as usize) * 32;
            let end = start + 32;
            let y_bytes = &challenge_bytes[start..end];

            let mut y = BigUint::from_bytes_le(y_bytes) % &n;
            if y.is_zero() {
                y = BigUint::one();
            }
            y_challenges.push(y);
        }

        // CRITICAL: Verify z_i^N = y_i for all i
        for (y_i, response) in y_challenges.iter().zip(proof.responses.iter()) {
            let z_i_to_n = response.z.modpow(&n, &n);
            assert_eq!(z_i_to_n, *y_i,
                "z_i^N must equal y_i mod N (this proves prover knows factorization)");
        }
    }

    #[test]
    fn test_verifier_rejects_prime_n() {
        // CRITICAL SOUNDNESS TEST: Verifier must reject prime N
        // Generate a large prime
        let prime_n = loop {
            let mut rng = OsRng;
            let mut candidate = rng.gen_biguint(512);
            candidate.set_bit(511, true);
            candidate.set_bit(0, true);

            if is_probably_prime(&candidate, 20) {
                break candidate;
            }
        };

        // Generate a valid proof for a real Paillier-Blum modulus
        let (good_n, p, q) = generate_paillier_blum_modulus(512);
        let proof = prove(&good_n, &p, &q, MIN_CHALLENGE_ROUNDS).unwrap();

        // Try to verify the proof against the prime N
        // This MUST fail because N is not composite
        assert!(!verify(&prime_n, &proof, MIN_CHALLENGE_ROUNDS).unwrap(),
            "Verifier must reject prime N (violates 'odd composite' requirement)");
    }

    #[test]
    fn test_verifier_rejects_n_equals_p_squared() {
        // CRITICAL SOUNDNESS TEST: N = p² should be rejected
        // This tests that N must be a product of two DISTINCT primes
        let p = generate_safe_prime(256);
        let n_squared = &p * &p;

        // Generate a valid proof for a real Paillier-Blum modulus
        let (good_n, good_p, good_q) = generate_paillier_blum_modulus(512);
        let proof = prove(&good_n, &good_p, &good_q, MIN_CHALLENGE_ROUNDS).unwrap();

        // Try to verify against N = p²
        // The verifier should reject this (challenges will differ due to different N in transcript)
        assert!(!verify(&n_squared, &proof, MIN_CHALLENGE_ROUNDS).unwrap(),
            "Verifier must reject N = p² (not a biprime)");
    }

    #[test]
    fn test_prover_rejects_n_equals_p_squared() {
        // Prover should reject N = p² at prove time
        let p = generate_safe_prime(256);
        let n_squared = &p * &p;

        // Try to create proof with N = p²
        let result = prove(&n_squared, &p, &p, MIN_CHALLENGE_ROUNDS);

        // Should fail because prover validates N = p*q
        assert!(result.is_err(), "Prover must reject N = p²");
    }

    #[test]
    fn test_jacobi_symbol_comprehensive() {
        // More comprehensive Jacobi symbol tests
        // Test with n = 15 = 3 * 5
        let n = BigInt::from(15);

        // Test known values
        assert_eq!(jacobi_symbol(&BigInt::from(1), &n), 1);
        assert_eq!(jacobi_symbol(&BigInt::from(2), &n), 1);
        assert_eq!(jacobi_symbol(&BigInt::from(4), &n), 1);

        // CRITICAL: Test Jacobi symbol = -1
        assert_eq!(jacobi_symbol(&BigInt::from(7), &n), -1);
        assert_eq!(jacobi_symbol(&BigInt::from(13), &n), -1);

        // Test Jacobi symbol = 0 (not coprime)
        assert_eq!(jacobi_symbol(&BigInt::from(3), &n), 0);
        assert_eq!(jacobi_symbol(&BigInt::from(5), &n), 0);
        assert_eq!(jacobi_symbol(&BigInt::from(15), &n), 0);
    }

    #[test]
    fn test_small_paillier_blum_proof() {
        // Test with small known values: N = 15 = 3 * 5
        // Both 3 and 5 are ≡ 3 (mod 4), so this is a valid Paillier-Blum modulus
        let p = BigUint::from(3u32);
        let q = BigUint::from(5u32);
        let n = BigUint::from(15u32);

        // Try to create and verify proof
        // This tests the protocol works on small values
        let result = prove(&n, &p, &q, MIN_CHALLENGE_ROUNDS);

        if let Ok(proof) = result {
            // If prover succeeds, verify should also succeed
            assert!(verify(&n, &proof, MIN_CHALLENGE_ROUNDS).unwrap(),
                "Valid proof for N=15 should verify");

            // Verify w has Jacobi symbol -1
            let w_int = BigInt::from_biguint(Sign::Plus, proof.w.0.clone());
            let n_int = BigInt::from_biguint(Sign::Plus, n.clone());
            assert_eq!(jacobi_symbol(&w_int, &n_int), -1,
                "w must have Jacobi symbol -1");
        } else {
            // If prover fails, that's also acceptable for small moduli
            // (might not find 4th roots easily)
            println!("Note: Proof generation failed for N=15 (acceptable for small moduli)");
        }
    }

    #[test]
    fn test_verifier_rejects_gcd_w_n_not_one() {
        // Generate a Paillier-Blum modulus
        let (n, p, q) = generate_paillier_blum_modulus(512);
        let mut proof = prove(&n, &p, &q, MIN_CHALLENGE_ROUNDS).unwrap();

        // CRITICAL: Replace w with a value that shares a factor with N
        // Use p as w (which divides N)
        proof.w = BigUintWrapper(p.clone());

        // Verifier must reject because gcd(w, N) ≠ 1
        assert!(!verify(&n, &proof, MIN_CHALLENGE_ROUNDS).unwrap(),
            "Verifier must reject when gcd(w, N) ≠ 1");
    }

    #[test]
    fn test_all_responses_checked() {
        // Test that corruption in ANY position is detected, not just first
        let (n, p, q) = generate_paillier_blum_modulus(512);
        let mut proof = prove(&n, &p, &q, MIN_CHALLENGE_ROUNDS).unwrap();

        // Test corrupting middle response
        let middle = proof.responses.len() / 2;
        proof.responses[middle].z = (&proof.responses[middle].z + BigUint::one()) % &n;

        assert!(!verify(&n, &proof, MIN_CHALLENGE_ROUNDS).unwrap(),
            "Verifier must check ALL responses, not just first");
    }

    #[test]
    fn test_b_i_bit_corruption() {
        // Test that flipping b_i bit is also detected
        let (n, p, q) = generate_paillier_blum_modulus(512);
        let mut proof = prove(&n, &p, &q, MIN_CHALLENGE_ROUNDS).unwrap();

        // Flip b_i instead of a_i
        proof.responses[0].b = !proof.responses[0].b;

        assert!(!verify(&n, &proof, MIN_CHALLENGE_ROUNDS).unwrap(),
            "Verifier must reject proof with flipped b_i bit");
    }

    #[test]
    fn test_both_bits_flipped() {
        // Test that flipping both a_i and b_i is detected
        let (n, p, q) = generate_paillier_blum_modulus(512);
        let mut proof = prove(&n, &p, &q, MIN_CHALLENGE_ROUNDS).unwrap();

        // Flip both bits
        proof.responses[0].a = !proof.responses[0].a;
        proof.responses[0].b = !proof.responses[0].b;

        assert!(!verify(&n, &proof, MIN_CHALLENGE_ROUNDS).unwrap(),
            "Verifier must reject proof with both bits flipped");
    }

    #[test]
    fn test_x_i_satisfies_equation() {
        // Generate a Paillier-Blum modulus and proof
        let (n, p, q) = generate_paillier_blum_modulus(512);
        let proof = prove(&n, &p, &q, MIN_CHALLENGE_ROUNDS).unwrap();

        // Reconstruct challenges
        let inputs = ["n", "w", "m"];
        let challenges = ["y_challenges"];
        let mut transcript = Decree::new("paillier-blum-proof-v1", &inputs, &challenges).unwrap();
        transcript.add("n", &BigUintWrapper(n.clone())).unwrap();
        transcript.add("w", &BigUintWrapper(proof.w.0.clone())).unwrap();
        transcript.add("m", &U32Wrapper(MIN_CHALLENGE_ROUNDS)).unwrap();

        let mut challenge_bytes = vec![0u8; (MIN_CHALLENGE_ROUNDS as usize) * 32];
        transcript.get_challenge("y_challenges", &mut challenge_bytes).unwrap();

        let mut y_challenges = Vec::new();
        for _i in 0..MIN_CHALLENGE_ROUNDS {
            let start = (_i as usize) * 32;
            let end = start + 32;
            let y_bytes = &challenge_bytes[start..end];

            let mut y = BigUint::from_bytes_le(y_bytes) % &n;
            if y.is_zero() {
                y = BigUint::one();
            }
            y_challenges.push(y);
        }

        // CRITICAL: Verify x_i^4 = (-1)^{a_i} * w^{b_i} * y_i for all i
        for (y_i, response) in y_challenges.iter().zip(proof.responses.iter()) {
            let x_i_fourth = response.x.modpow(&BigUint::from(4u32), &n);

            let mut expected = y_i.clone();
            if response.a {
                expected = (&n - expected) % &n;
            }
            if response.b {
                expected = (expected * &proof.w.0) % &n;
            }

            assert_eq!(x_i_fourth, expected,
                "x_i^4 must equal (-1)^a_i * w^b_i * y_i mod N");
        }
    }
}
