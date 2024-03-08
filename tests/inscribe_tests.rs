#[cfg(test)]
mod tests {
    use bcs;
    use decree::error::Error;
    use decree::Inscribe;
    use decree::decree::FSInput;
    use tiny_keccak::TupleHash;
    use tiny_keccak::Hasher;
    const INSCRIBE_LENGTH: usize = 64;
    const ADDL_TEST_DATA: &str = "Additional data!";
    const MARK_TEST_DATA: &str = "Atypical mark!";

    #[derive(Inscribe)]
    #[inscribe_mark(atypical_mark)]
    struct Point {
        #[inscribe(serialize)]
        #[inscribe_name(input_2)]
        x: i32,
        #[inscribe(serialize)]
        #[inscribe_name(input_1)]
        y: i32,
    }

    impl Point {
        fn atypical_mark(&self) -> &'static str {
            MARK_TEST_DATA
        }
    }

    #[derive(Inscribe)]
    #[inscribe_addl(additional_data_method)]
    struct InscribeTest {
        a: Point,
        b: Point,
    }

    impl InscribeTest {
        fn additional_data_method(&self) -> Result<FSInput, Error> {
            Ok(ADDL_TEST_DATA.as_bytes().to_vec())
        }
    }

    #[test]
    /// Test to make sure that 
    fn test_derive_inscribe() {
        // First, build our structs
        let x: Point = Point { x: 8675309i32, y: 8675311i32 };
        let y: Point = Point { x: 8675323i32, y: 8675327i32 };
        let inscriber: InscribeTest = InscribeTest { a: x, b: y};

        // Get the inscription value directly:
        let inscript_auto = inscriber.get_inscription().unwrap();

        // Compute the inscription piece-by-piece
        // Get the inscription of the `a` member
        // (Note that `x` and `y` are out of order according to `inscribe_name`)
        let mut tuplehasher_a = TupleHash::v256(MARK_TEST_DATA.as_bytes());
        let a_x = bcs::to_bytes(&inscriber.a.x).unwrap();
        let a_y = bcs::to_bytes(&inscriber.a.y).unwrap();
        let a_addl: Vec<u8> = vec![];
        tuplehasher_a.update(a_y.as_slice());
        tuplehasher_a.update(a_x.as_slice());
        tuplehasher_a.update(a_addl.as_slice());
        let mut buffer_a: [u8; INSCRIBE_LENGTH] = [0u8; INSCRIBE_LENGTH];
        tuplehasher_a.finalize(&mut buffer_a);

        // Get the inscription of the `b` member
        // (Note that `x` and `y` are out of order according to `inscribe_name`)
        let mut tuplehasher_b = TupleHash::v256(MARK_TEST_DATA.as_bytes());
        let b_x = bcs::to_bytes(&inscriber.b.x).unwrap();
        let b_y = bcs::to_bytes(&inscriber.b.y).unwrap();
        let b_addl: Vec<u8> = vec![];
        tuplehasher_b.update(b_y.as_slice());
        tuplehasher_b.update(b_x.as_slice());
        tuplehasher_b.update(b_addl.as_slice());
        let mut buffer_b: [u8; INSCRIBE_LENGTH] = [0u8; INSCRIBE_LENGTH];
        tuplehasher_b.finalize(&mut buffer_b);

        // Put the `a` and `b` hashest together
        let mut tuplehasher_total = TupleHash::v256("InscribeTest".as_bytes());
        let total_addl: Vec<u8> = ADDL_TEST_DATA.as_bytes().to_vec();
        tuplehasher_total.update(&buffer_a);
        tuplehasher_total.update(&buffer_b);
        tuplehasher_total.update(total_addl.as_slice());
        let mut buffer_total: [u8; INSCRIBE_LENGTH] = [0u8; INSCRIBE_LENGTH];
        tuplehasher_total.finalize(&mut buffer_total);

        assert_eq!(inscript_auto, buffer_total.to_vec());
    }

    #[test]
    /// This is a Girault proof 
    fn test_girault() {
        use decree::decree::Decree;
        use num_bigint::{BigUint, RandBigInt};
        use rand;

        // Useful constants
        let zero = BigUint::parse_bytes(b"0", 16).unwrap();
        let one = BigUint::parse_bytes(b"1", 16).unwrap();

        // Create our transcript
        let mut transcript = Decree::new("girault",
            vec!["g", "N", "h", "u"].as_slice(),
            vec!["e"].as_slice()).unwrap();

        // x is our secret logarithm
        let x = BigUint::from(8675309u32);

        // p = NextPrime(SHA3-512('DECREE'))
        let p: BigUint = BigUint::parse_bytes(
            b"e955c307804136f22408b416ebc081ae\
              c8d940e1ebd790cbe128485b15a8064d\
              5015e2b4c0058d403670a8cfa00fe1ad\
              866312656e740e58b566fa4eddde2883", 16).unwrap();

        // q = NextPrime(SHA3-512('INSCRIBE'))
        let q: BigUint = BigUint::parse_bytes(
            b"d608e1552a96613570afb9e7291b2916\
              2ad18868e2f7aedeba2b321d13ab2b79\
              99a1e449e433c5947af5194471e84ce0\
              d34b30b761004c8efdad598771b37e13", 16).unwrap();

        // n is our modulus
        let n = &p * &q;
        transcript.add_serial("N", &n).unwrap();

        // g is our base
        let g = BigUint::from(2u32);
        transcript.add_serial("g", &g).unwrap();

        // We need `g^(-1)` to compute `g^(-x)`. Since `g` is 2, we can compute this easily.
        let g_inv = (&n + &one) / &g;

        // h is our target
        let h = g_inv.modpow(&x, &n);
        transcript.add_serial("h", &h).unwrap();

        // r is our secret randomizer; u is its corresponding public output
        let mut rng = rand::thread_rng();
        let r = rng.gen_biguint(1024);
        let u = g.modpow(&r, &n);
        transcript.add_serial("u", &u).unwrap();

        // Compute our challenge
        let mut prover_challenge_bytes: [u8; 128] = [0u8; 128];
        transcript.get_challenge("e", &mut prover_challenge_bytes).unwrap();

        // Compute our response
        let prover_challenge_int = BigUint::from_bytes_le(&prover_challenge_bytes);
        let z = r + (x * prover_challenge_int);

        // Final proof:
        let proof = (h, g, u, n, prover_challenge_bytes, z);


        // Now verify:
        let (h_verify, g_verify, u_verify, n_verify, challenge_verify, z_verify) = proof;
        assert!(u_verify != zero);
        assert!(z_verify != zero);
        assert!(h_verify != zero);
        assert!(g_verify != zero);
        assert!(h_verify != one);
        assert!(g_verify != one);
        assert!(z_verify != one);
        assert!(u_verify != one);

        let mut verifier_challenge_bytes: [u8; 128] = [0u8; 128];
        let mut transcript_verify = Decree::new("girault",
            vec!["g", "N", "h", "u"].as_slice(),
            vec!["e"].as_slice()).unwrap();
        transcript_verify.add_serial("N", &n_verify).unwrap();
        transcript_verify.add_serial("g", &g_verify).unwrap();
        transcript_verify.add_serial("h", &h_verify).unwrap();
        transcript_verify.add_serial("u", &u_verify).unwrap();
        transcript_verify.get_challenge("e", &mut verifier_challenge_bytes).unwrap();
        let verifier_challenge_int = BigUint::from_bytes_le(&prover_challenge_bytes);
        assert_eq!(verifier_challenge_bytes, challenge_verify);

        let check = (g_verify.modpow(&z_verify, &n_verify) * h_verify.modpow(&verifier_challenge_int, &n_verify)) % n_verify;

        assert_eq!(u_verify, check);
    }
}