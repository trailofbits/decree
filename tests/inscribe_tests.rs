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
        x: i32,
        #[inscribe(serialize)]
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
        let mut tuplehasher_a = TupleHash::v256(MARK_TEST_DATA.as_bytes());
        let a_x = bcs::to_bytes(&inscriber.a.x).unwrap();
        let a_y = bcs::to_bytes(&inscriber.a.y).unwrap();
        let a_addl: Vec<u8> = vec![];
        tuplehasher_a.update(a_x.as_slice());
        tuplehasher_a.update(a_y.as_slice());
        tuplehasher_a.update(a_addl.as_slice());
        let mut buffer_a: [u8; INSCRIBE_LENGTH] = [0u8; INSCRIBE_LENGTH];
        tuplehasher_a.finalize(&mut buffer_a);

        // Get the inscription of the `b` member
        let mut tuplehasher_b = TupleHash::v256(MARK_TEST_DATA.as_bytes());
        let b_x = bcs::to_bytes(&inscriber.b.x).unwrap();
        let b_y = bcs::to_bytes(&inscriber.b.y).unwrap();
        let b_addl: Vec<u8> = vec![];
        tuplehasher_b.update(b_x.as_slice());
        tuplehasher_b.update(b_y.as_slice());
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
}