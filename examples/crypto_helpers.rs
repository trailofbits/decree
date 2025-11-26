//! Cryptographic helper functions shared between zero-knowledge proof examples
//!
//! This module provides common utilities including primality testing,
//! extended GCD, and Jacobi symbol computation.

#![allow(dead_code)]

use num_bigint::{BigInt, BigUint, RandBigInt};
use num_traits::{One, Zero};
use rand::rngs::OsRng;

/// Miller-Rabin primality test
///
/// Returns true if n is probably prime after the given number of rounds.
/// The probability of a false positive decreases exponentially with rounds.
pub fn is_probably_prime(n: &BigUint, rounds: u32) -> bool {
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

/// Extended GCD algorithm
///
/// Returns (gcd, x, y) such that gcd = a*x + b*y
pub fn extended_gcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    if b.is_zero() {
        return (a.clone(), BigInt::one(), BigInt::zero());
    }

    let (gcd, x1, y1) = extended_gcd(b, &(a % b));
    let x = y1.clone();
    let y = x1 - (a / b) * y1;

    (gcd, x, y)
}

/// Compute Jacobi symbol (a/n)
///
/// Returns -1, 0, or 1.
/// Panics if n is not a positive odd integer.
pub fn jacobi_symbol(a: &BigInt, n: &BigInt) -> i8 {
    if n <= &BigInt::zero() || !n.bit(0) {
        panic!("n must be a positive odd integer");
    }

    let mut a = a.clone() % n;
    let mut n = n.clone();
    let mut result = 1i8;

    while !a.is_zero() {
        // Remove factors of 2 from a
        while !a.bit(0) {
            a >>= 1;
            let n_mod_8 = &n % BigInt::from(8);
            if n_mod_8 == BigInt::from(3) || n_mod_8 == BigInt::from(5) {
                result = -result;
            }
        }

        // Swap a and n
        std::mem::swap(&mut a, &mut n);

        // Quadratic reciprocity
        if &a % BigInt::from(4) == BigInt::from(3) && &n % BigInt::from(4) == BigInt::from(3) {
            result = -result;
        }

        a %= &n;
    }

    if n == BigInt::one() {
        result
    } else {
        0
    }
}

/// Generate a random prime of specified bit length
///
/// The prime will have the specified number of bits (i.e., 2^(bits-1) <= p < 2^bits).
pub fn generate_prime(bits: usize) -> BigUint {
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
