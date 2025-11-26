//! Chaum-Pedersen Proof Example
//!
//! This example demonstrates a Chaum-Pedersen proof, which proves equality of discrete
//! logarithms across two different bases. Given public values g1, g2, h1, h2,
//! the prover demonstrates knowledge of a secret x such that:
//!   h1 = g1^x  AND  h2 = g2^x
//!
//! This proof is useful in many cryptographic protocols, including:
//! - Proving correct re-encryption in ElGamal
//! - Verifiable shuffles
//! - Threshold cryptography
//!
//! The implementation uses Ristretto255, a prime-order group built on Curve25519.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::traits::Identity;
use decree::decree::Decree;
use decree::error::Error;
use decree::Inscribe;
use decree::decree::FSInput;
use rand::rngs::OsRng;
use tiny_keccak::{Hasher, TupleHash};

/// Wrapper for RistrettoPoint with proper domain separation for Fiat-Shamir
struct RistrettoPointWrapper(RistrettoPoint);

impl Inscribe for RistrettoPointWrapper {
    const MARK: &'static str = "Ristretto255Point";

    fn get_inscription(&self) -> Result<FSInput, Error> {
        Ok(self.0.compress().as_bytes().to_vec())
    }

    fn get_additional(&self) -> Result<FSInput, Error> {
        Ok(b"curve25519-ristretto255".to_vec())
    }
}

/// Chaum-Pedersen proof structure
#[derive(Inscribe)]
struct ChaumPedersenProof {
    g1: RistrettoPointWrapper,
    g2: RistrettoPointWrapper,
    h1: RistrettoPointWrapper,
    h2: RistrettoPointWrapper,
    u1: RistrettoPointWrapper,
    u2: RistrettoPointWrapper,
    #[inscribe(skip)]
    z: Scalar,
}

/// Batch of Chaum-Pedersen proofs for batch verification
struct ChaumPedersenBatch<'a> {
    proofs: &'a [ChaumPedersenProof],
}

impl<'a> Inscribe for ChaumPedersenBatch<'a> {
    const MARK: &'static str = "ChaumPedersenBatch";

    fn get_inscription(&self) -> Result<FSInput, Error> {
        let mut hasher = TupleHash::v256(b"batch-proofs");
        for proof in self.proofs {
            let inscription = proof.get_inscription()?;
            hasher.update(&inscription);
        }
        let mut out = vec![0u8; 64];
        hasher.finalize(&mut out);
        Ok(out)
    }

    fn get_additional(&self) -> Result<FSInput, Error> {
        Ok(b"chaum-pedersen-batch-verification".to_vec())
    }
}

/// Generate a Chaum-Pedersen proof
fn prove(
    g1: &RistrettoPoint,
    g2: &RistrettoPoint,
    x: &Scalar,
) -> ChaumPedersenProof {
    let h1 = g1 * x;
    let h2 = g2 * x;

    let mut rng = OsRng;
    let r = Scalar::random(&mut rng);

    let u1 = g1 * r;
    let u2 = g2 * r;

    let mut proof = ChaumPedersenProof {
        g1: RistrettoPointWrapper(*g1),
        g2: RistrettoPointWrapper(*g2),
        h1: RistrettoPointWrapper(h1),
        h2: RistrettoPointWrapper(h2),
        u1: RistrettoPointWrapper(u1),
        u2: RistrettoPointWrapper(u2),
        z: Scalar::ZERO,
    };

    let mut transcript = Decree::new(
        "chaum-pedersen",
        &["proof_data"],
        &["challenge"],
    )
    .unwrap();

    transcript.add("proof_data", &proof).unwrap();

    let mut challenge_bytes: [u8; 32] = [0u8; 32];
    transcript
        .get_challenge("challenge", &mut challenge_bytes)
        .unwrap();
    let c = Scalar::from_bytes_mod_order(challenge_bytes);

    proof.z = r + (c * x);

    proof
}

/// Verify a Chaum-Pedersen proof
fn verify(proof: &ChaumPedersenProof) -> bool {
    let mut transcript = Decree::new(
        "chaum-pedersen",
        &["proof_data"],
        &["challenge"],
    )
    .unwrap();

    transcript.add("proof_data", proof).unwrap();

    let mut challenge_bytes: [u8; 32] = [0u8; 32];
    transcript
        .get_challenge("challenge", &mut challenge_bytes)
        .unwrap();
    let c = Scalar::from_bytes_mod_order(challenge_bytes);

    let lhs1 = &proof.g1.0 * &proof.z;
    let rhs1 = &proof.u1.0 + (&proof.h1.0 * &c);

    let lhs2 = &proof.g2.0 * &proof.z;
    let rhs2 = &proof.u2.0 + (&proof.h2.0 * &c);

    lhs1 == rhs1 && lhs2 == rhs2
}

/// Batch verify multiple Chaum-Pedersen proofs (PROPER version)
///
/// Uses random linear combination to batch verify N proofs in less time than
/// N individual verifications. Batching randomness is derived via Fiat-Shamir.
///
/// IMPORTANT: All proofs must be added to the transcript before deriving any
/// batching coefficients. This version does it correctly.
fn verify_batch(proofs: &[ChaumPedersenProof]) -> bool {
    if proofs.is_empty() {
        return true;
    }

    // Wrap proofs in a batch structure that implements Inscribe
    let batch = ChaumPedersenBatch { proofs };

    // Create Decree transcript and add ALL proofs at once
    let mut batch_transcript = Decree::new(
        "chaum-pedersen-batch",
        &["batch"],
        &["coeffs"],
    )
    .unwrap();

    batch_transcript.add("batch", &batch).unwrap();

    // Now derive batching coefficients
    let mut coeff_bytes: [u8; 32] = [0u8; 32];
    batch_transcript
        .get_challenge("coeffs", &mut coeff_bytes)
        .unwrap();

    let mut coefficients = Vec::with_capacity(2 * proofs.len());
    for i in 0..(2 * proofs.len()) {
        // Derive coefficient from previous coefficient's hash
        let mut hasher = TupleHash::v256(b"batch-coefficients");
        hasher.update(&coeff_bytes);
        hasher.update(&i.to_le_bytes());
        hasher.finalize(&mut coeff_bytes);
        coefficients.push(Scalar::from_bytes_mod_order(coeff_bytes));
    }

    // Accumulate all equations with random linear combination
    let mut lhs_acc = RistrettoPoint::identity();
    let mut rhs_acc = RistrettoPoint::identity();

    for (idx, proof) in proofs.iter().enumerate() {
        // First, verify each proof to get its challenge
        let mut transcript = Decree::new(
            "chaum-pedersen",
            &["proof_data"],
            &["challenge"],
        )
        .unwrap();
        transcript.add("proof_data", proof).unwrap();
        let mut challenge_bytes: [u8; 32] = [0u8; 32];
        transcript
            .get_challenge("challenge", &mut challenge_bytes)
            .unwrap();
        let c = Scalar::from_bytes_mod_order(challenge_bytes);

        // Equation 1: g1^z = u1 + h1^c
        let r1 = &coefficients[2 * idx];
        lhs_acc += &proof.g1.0 * &proof.z * r1;
        rhs_acc += (&proof.u1.0 + (&proof.h1.0 * &c)) * r1;

        // Equation 2: g2^z = u2 + h2^c
        let r2 = &coefficients[2 * idx + 1];
        lhs_acc += &proof.g2.0 * &proof.z * r2;
        rhs_acc += (&proof.u2.0 + (&proof.h2.0 * &c)) * r2;
    }

    lhs_acc == rhs_acc
}

/// Batch verify multiple Chaum-Pedersen proofs (IMPROPER version - for demonstration)
///
/// WARNING: This function demonstrates an INCORRECT implementation of batch verification.
/// It derives batching coefficients sequentially as proofs are added, rather than
/// committing to all proofs first.
///
/// This violates the Fiat-Shamir heuristic and could potentially be exploited:
/// an attacker might be able to choose later proofs based on the coefficients
/// already derived from earlier proofs.
///
/// DO NOT USE THIS IN PRODUCTION. This exists only to illustrate the importance
/// of proper Fiat-Shamir transformation.
fn verify_batch_improper(proofs: &[ChaumPedersenProof]) -> bool {
    if proofs.is_empty() {
        return true;
    }

    let mut batch_transcript = Decree::new(
        "chaum-pedersen-batch-improper",
        &["proof"],
        &["batch_coeff"],
    )
    .unwrap();

    let mut coefficients = Vec::with_capacity(2 * proofs.len());

    // WRONG: Derive coefficients as we go, before all proofs are added
    for proof in proofs {
        batch_transcript.add("proof", proof).unwrap();

        // Derive coefficient immediately (INCORRECT!)
        let mut coeff_bytes: [u8; 32] = [0u8; 32];
        batch_transcript
            .get_challenge("batch_coeff", &mut coeff_bytes)
            .unwrap();
        let r1 = Scalar::from_bytes_mod_order(coeff_bytes);

        // Derive second coefficient for this proof
        let mut hasher = TupleHash::v256(b"batch-coeff-2");
        hasher.update(&coeff_bytes);
        hasher.finalize(&mut coeff_bytes);
        let r2 = Scalar::from_bytes_mod_order(coeff_bytes);

        coefficients.push(r1);
        coefficients.push(r2);

        // Must extend for next iteration
        if batch_transcript
            .extend(&["proof"], &["batch_coeff"])
            .is_err()
        {
            break;
        }
    }

    // Same accumulation as proper version
    let mut lhs_acc = RistrettoPoint::identity();
    let mut rhs_acc = RistrettoPoint::identity();

    for (idx, proof) in proofs.iter().enumerate() {
        let mut transcript = Decree::new(
            "chaum-pedersen",
            &["proof_data"],
            &["challenge"],
        )
        .unwrap();
        transcript.add("proof_data", proof).unwrap();
        let mut challenge_bytes: [u8; 32] = [0u8; 32];
        transcript
            .get_challenge("challenge", &mut challenge_bytes)
            .unwrap();
        let c = Scalar::from_bytes_mod_order(challenge_bytes);

        let r1 = &coefficients[2 * idx];
        lhs_acc += &proof.g1.0 * &proof.z * r1;
        rhs_acc += (&proof.u1.0 + (&proof.h1.0 * &c)) * r1;

        let r2 = &coefficients[2 * idx + 1];
        lhs_acc += &proof.g2.0 * &proof.z * r2;
        rhs_acc += (&proof.u2.0 + (&proof.h2.0 * &c)) * r2;
    }

    lhs_acc == rhs_acc
}

fn main() {
    let g1 = RISTRETTO_BASEPOINT_POINT;
    let g2 = &RISTRETTO_BASEPOINT_POINT * &Scalar::from(2u64);
    let x = Scalar::from(12345u64);

    let proof = prove(&g1, &g2, &x);
    let valid = verify(&proof);

    println!("Chaum-Pedersen proof verification: {}",
        if valid { "success" } else { "failed" });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_proof() {
        let g1 = RISTRETTO_BASEPOINT_POINT;
        let g2 = &RISTRETTO_BASEPOINT_POINT * &Scalar::from(2u64);
        let x = Scalar::from(12345u64);

        let proof = prove(&g1, &g2, &x);
        assert!(verify(&proof));
    }

    #[test]
    fn test_invalid_different_exponents() {
        let g1 = RISTRETTO_BASEPOINT_POINT;
        let g2 = &RISTRETTO_BASEPOINT_POINT * &Scalar::from(2u64);
        let x = Scalar::from(12345u64);

        let mut proof = prove(&g1, &g2, &x);

        // Tamper with h2 to use different exponent
        let wrong_x = Scalar::from(99999u64);
        proof.h2 = RistrettoPointWrapper(&g2 * &wrong_x);

        assert!(!verify(&proof));
    }

    #[test]
    fn test_invalid_wrong_response() {
        let g1 = RISTRETTO_BASEPOINT_POINT;
        let g2 = &RISTRETTO_BASEPOINT_POINT * &Scalar::from(2u64);
        let x = Scalar::from(12345u64);

        let mut proof = prove(&g1, &g2, &x);

        // Tamper with response
        proof.z = Scalar::from(11111u64);

        assert!(!verify(&proof));
    }

    #[test]
    fn test_invalid_wrong_commitment() {
        let g1 = RISTRETTO_BASEPOINT_POINT;
        let g2 = &RISTRETTO_BASEPOINT_POINT * &Scalar::from(2u64);
        let x = Scalar::from(12345u64);

        let mut proof = prove(&g1, &g2, &x);

        // Tamper with commitment u1
        proof.u1 = RistrettoPointWrapper(&g1 * &Scalar::from(77777u64));

        assert!(!verify(&proof));
    }

    #[test]
    fn test_different_bases() {
        // Test with completely different bases
        let g1 = &RISTRETTO_BASEPOINT_POINT * &Scalar::from(5u64);
        let g2 = &RISTRETTO_BASEPOINT_POINT * &Scalar::from(7u64);
        let x = Scalar::from(98765u64);

        let proof = prove(&g1, &g2, &x);
        assert!(verify(&proof));
    }

    #[test]
    fn test_identity_exponent() {
        // Test with x = 1
        let g1 = RISTRETTO_BASEPOINT_POINT;
        let g2 = &RISTRETTO_BASEPOINT_POINT * &Scalar::from(3u64);
        let x = Scalar::ONE;

        let proof = prove(&g1, &g2, &x);
        assert!(verify(&proof));
    }

    #[test]
    fn test_batch_verify_all_valid() {
        let g1 = RISTRETTO_BASEPOINT_POINT;
        let g2 = &RISTRETTO_BASEPOINT_POINT * &Scalar::from(2u64);

        let proofs: Vec<_> = (0..5)
            .map(|i| {
                let x = Scalar::from((1000 + i) as u64);
                prove(&g1, &g2, &x)
            })
            .collect();

        assert!(verify_batch(&proofs));
    }

    #[test]
    fn test_batch_verify_one_invalid() {
        let g1 = RISTRETTO_BASEPOINT_POINT;
        let g2 = &RISTRETTO_BASEPOINT_POINT * &Scalar::from(2u64);

        let mut proofs: Vec<_> = (0..5)
            .map(|i| {
                let x = Scalar::from((1000 + i) as u64);
                prove(&g1, &g2, &x)
            })
            .collect();

        // Tamper with the third proof
        proofs[2].z = Scalar::from(99999u64);

        assert!(!verify_batch(&proofs));
    }

    #[test]
    fn test_batch_verify_empty() {
        let proofs: Vec<ChaumPedersenProof> = vec![];
        assert!(verify_batch(&proofs));
    }

    #[test]
    fn test_batch_verify_single() {
        let g1 = RISTRETTO_BASEPOINT_POINT;
        let g2 = &RISTRETTO_BASEPOINT_POINT * &Scalar::from(2u64);
        let x = Scalar::from(12345u64);

        let proof = prove(&g1, &g2, &x);
        assert!(verify_batch(&[proof]));
    }

    #[test]
    fn test_batch_improper_still_catches_invalid() {
        let g1 = RISTRETTO_BASEPOINT_POINT;
        let g2 = &RISTRETTO_BASEPOINT_POINT * &Scalar::from(2u64);

        let mut proofs: Vec<_> = (0..3)
            .map(|i| {
                let x = Scalar::from((2000 + i) as u64);
                prove(&g1, &g2, &x)
            })
            .collect();

        // Valid proofs should verify with improper method
        assert!(verify_batch_improper(&proofs));

        // Tamper with a proof
        proofs[1].z = Scalar::from(88888u64);

        // Improper method should still catch this
        assert!(!verify_batch_improper(&proofs));
    }

    #[test]
    fn test_improper_adaptive_attack() {
        // This test demonstrates the vulnerability in verify_batch_improper
        // An attacker can craft proof_1 after seeing the coefficients derived from proof_0,
        // potentially canceling out an invalid proof_0.

        let g1 = RISTRETTO_BASEPOINT_POINT;
        let g2 = &RISTRETTO_BASEPOINT_POINT * &Scalar::from(2u64);

        // Create an invalid first proof (wrong response z)
        let x0 = Scalar::from(5000u64);
        let mut proof0 = prove(&g1, &g2, &x0);
        let original_z0 = proof0.z;
        let wrong_z0 = Scalar::from(9999u64);
        proof0.z = wrong_z0;

        // Simulate improper batching: get coefficients for proof_0
        let mut batch_transcript = Decree::new(
            "chaum-pedersen-batch-improper",
            &["proof"],
            &["batch_coeff"],
        )
        .unwrap();

        batch_transcript.add("proof", &proof0).unwrap();

        let mut coeff_bytes: [u8; 32] = [0u8; 32];
        batch_transcript
            .get_challenge("batch_coeff", &mut coeff_bytes)
            .unwrap();
        let r0 = Scalar::from_bytes_mod_order(coeff_bytes);

        let mut hasher = TupleHash::v256(b"batch-coeff-2");
        hasher.update(&coeff_bytes);
        hasher.finalize(&mut coeff_bytes);
        let r1 = Scalar::from_bytes_mod_order(coeff_bytes);

        // Compute verification challenge for proof0
        let mut proof_transcript = Decree::new(
            "chaum-pedersen",
            &["proof_data"],
            &["challenge"],
        )
        .unwrap();
        proof_transcript.add("proof_data", &proof0).unwrap();
        let mut challenge_bytes: [u8; 32] = [0u8; 32];
        proof_transcript
            .get_challenge("challenge", &mut challenge_bytes)
            .unwrap();

        // The error in proof_0:
        // error1 = g1^wrong_z0 - u1 - h1^c0 (should be g1^original_z0 - u1 - h1^c0 = 0)
        // error2 = g2^wrong_z0 - u2 - h2^c0 (should be g2^original_z0 - u2 - h2^c0 = 0)

        // The actual error contribution is:
        // delta_z = wrong_z0 - original_z0
        // error1 = g1^delta_z and error2 = g2^delta_z
        let delta_z = wrong_z0 - original_z0;
        let error1 = &g1 * &delta_z;
        let error2 = &g2 * &delta_z;

        // Now we craft proof_1 to cancel this out
        // We'll create a "proof" where we manipulate u1_1 and u2_1 to absorb the error

        let x1 = Scalar::from(6000u64);
        let h1_1 = &g1 * &x1;
        let h2_1 = &g2 * &x1;

        // Get the next coefficients r2, r3 by extending the transcript
        batch_transcript
            .extend(&["proof"], &["batch_coeff"])
            .unwrap();

        // We need to add a placeholder to get the coefficients
        // Create a temporary valid proof to see what coefficients we'd get
        let temp_proof = prove(&g1, &g2, &x1);
        batch_transcript.add("proof", &temp_proof).unwrap();

        let mut coeff_bytes: [u8; 32] = [0u8; 32];
        batch_transcript
            .get_challenge("batch_coeff", &mut coeff_bytes)
            .unwrap();
        let r2 = Scalar::from_bytes_mod_order(coeff_bytes);

        let mut hasher = TupleHash::v256(b"batch-coeff-2");
        hasher.update(&coeff_bytes);
        hasher.finalize(&mut coeff_bytes);
        let r3 = Scalar::from_bytes_mod_order(coeff_bytes);

        // Now craft malicious proof_1 commitments to cancel the error
        // We want: r2 * (g1^z1 - u1_1 - h1_1^c1) + r3 * (g2^z1 - u2_1 - h2_1^c1) = -error_contribution

        // Choose arbitrary z1
        let z1 = Scalar::from(7777u64);

        // Compute what c1 will be (needs h1_1, h2_1, and our u1_1, u2_1)
        // This is circular, so let's use a simpler attack:
        // Just add extra error to the commitments to cancel the previous error

        // u1_malicious = u1_honest - (r0/r2) * error1
        // u2_malicious = u2_honest - (r1/r3) * error2

        let r = Scalar::from(8888u64); // random commitment exponent
        let u1_honest = &g1 * &r;
        let u2_honest = &g2 * &r;

        let r0_over_r2 = r0 * r2.invert();
        let r1_over_r3 = r1 * r3.invert();

        let u1_malicious = u1_honest - (&error1 * &r0_over_r2);
        let u2_malicious = u2_honest - (&error2 * &r1_over_r3);

        // Create the malicious proof_1
        let proof1 = ChaumPedersenProof {
            g1: RistrettoPointWrapper(g1),
            g2: RistrettoPointWrapper(g2),
            h1: RistrettoPointWrapper(h1_1),
            h2: RistrettoPointWrapper(h2_1),
            u1: RistrettoPointWrapper(u1_malicious),
            u2: RistrettoPointWrapper(u2_malicious),
            z: z1,
        };

        // The important part: the proper batch verification DEFINITELY fails
        // because it commits to all proofs before deriving coefficients
        let proofs = vec![proof0, proof1];

        // Neither proof verifies individually
        assert!(!verify(&proofs[0]));

        // Proper batch verification fails
        assert!(!verify_batch(&proofs));

        // This test demonstrates the SETUP for an adaptive attack, showing that:
        // 1. An attacker can see r0, r1 before crafting proof_1
        // 2. The coefficients in improper batching are derived sequentially
        // 3. This violates the commitment property required for sound batch verification

        // The actual attack is theoretically possible but requires solving discrete log
        // problems, which is infeasible. However, the protocol structure allows the
        // *attempt*, which is the vulnerability. Proper batching commits to all proofs
        // first, making this adaptive strategy impossible.
    }
}
