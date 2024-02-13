use std::collections::HashMap;
use merlin::Transcript;
use bcs::to_bytes;
use bcs;
use serde::Serialize;
pub use crate::{Inscribe};
use crate::error::{Error, DecreeResult};

pub type InputLabel = &'static str;
pub type ChallengeLabel = &'static str;
pub type ErrMsg = &'static str;
pub type FSInput = Vec<u8>;

/// A `Decree` struct is used to formalize (and enforce) Fiat-Shamir transforms. It sits atop a
/// Merlin transcript, ensuring that required inputs are supplied before challenges are generated,
/// and that challenges are generated in order.
///
/// # Examples
/// ```
/// # use decree::decree::{Decree, InputLabel, ChallengeLabel};
/// # use decree::error::{Error, DecreeErrType, DecreeResult};
/// # fn main() -> DecreeResult<()> {
/// let inputs: [InputLabel; 2] = ["input1", "input2"];
/// let challenges: [ChallengeLabel; 2] = ["challenge1", "challenge2"];
/// let mut my_decree = Decree::new("testname", &inputs, &challenges)?;
/// my_decree.add_serial("input1", 10u32)?;
/// my_decree.add_serial("input2", 14u32)?;
/// let mut challenge_out1: [u8; 32] = [0u8; 32];
/// let mut challenge_out2: [u8; 32] = [0u8; 32];
/// my_decree.get_challenge("challenge1", &mut challenge_out1)?;
/// my_decree.get_challenge("challenge2", &mut challenge_out2)?;
/// # Ok(())
/// # }
/// ```
///
/// Schnorr proof:
/// ```
/// # use decree::decree::{Decree, InputLabel, ChallengeLabel};
/// # use decree::error::{Error, DecreeErrType, DecreeResult};
/// # use num_bigint::{BigInt, RandBigInt, Sign};
/// # use num_traits::Signed;
/// # use std::str::FromStr;
/// # fn main() -> DecreeResult<()> {
///     let inputs: [InputLabel; 4] = ["modulus", "base", "target", "u"];
///     let challenges: [ChallengeLabel; 1] = ["c_challenge"];
///     let mut transcript = Decree::new("schnorr proof", &inputs, &challenges)?;
///
///     // Proof parameters
///     let target = BigInt::from(8675309u32);
///     let base = BigInt::from(43u32);
///     let log = BigInt::from_str("18777797083714995725967614997933308615").unwrap();
///     let modulus = &BigInt::from(2u32).pow(127) - BigInt::from(1u32);
///
///     // Random exponent
///     let mut rng = rand::thread_rng();
///     let randomizer_exp = rng.gen_bigint(128).abs();
///     let randomizer = base.modpow(&randomizer_exp, &modulus);
///
///     // Add everything to the transcript-- note that order doesn't matter!
///     transcript.add_serial("modulus", &modulus);
///     transcript.add_serial("base", &base);
///     transcript.add_serial("target", &target);
///     transcript.add_serial("u", &randomizer);
///
///     // Generate challenge
///     let mut challenge_buffer: [u8; 16] = [0u8; 16];
///     transcript.get_challenge("c_challenge", &mut challenge_buffer)?;
///     let challenge_int = BigInt::from_bytes_le(Sign::Plus, &challenge_buffer);
///
///     // Final proof value
///     let z = (challenge_int * log) + randomizer;
/// #   Ok(())
/// # }
/// ```
///
/// Schnorr proof with `Inscribe` support:
/// ```
/// # use decree::decree::{Decree, InputLabel, ChallengeLabel};
/// # use decree::error::{Error, DecreeErrType, DecreeResult};
/// # use num_bigint::{BigInt, RandBigInt, Sign};
/// # use num_traits::Signed;
/// # use decree::Inscribe;
/// # use std::str::FromStr;
/// # use serde::Serialize;
///  #[derive(Inscribe, Clone)]
///  #[inscribe_addl(get_extra)]
///  pub struct BigIntTarget {
///     #[inscribe(serialize)]
///     target: BigInt,
///     #[inscribe(serialize)]
///     base: BigInt,
///     #[inscribe(serialize)]
///     modulus: BigInt,
///  }
///
///  impl BigIntTarget {
///     fn get_extra(&self) -> Result<Vec<u8>, Error> {
///         Ok("schnorr proof value".as_bytes().to_vec())
///     }
///  }
///
/// # fn main() -> DecreeResult<()> {
///     let inputs: [InputLabel; 4] = ["modulus", "base", "target", "u"];
///     let challenges: [ChallengeLabel; 1] = ["c_challenge"];
///     let mut transcript = Decree::new("schnorr proof", &inputs, &challenges)?;
///
///     // Proof parameters
///     let modulus = &BigInt::from(2u32).pow(127) - BigInt::from(1u32);
///     let base = BigInt::from(43u32);
///     let target = BigIntTarget{
///         target: BigInt::from(8675309u32),
///         base: base.clone(),
///         modulus: modulus.clone()};
///     let log = BigInt::from_str("18777797083714995725967614997933308615").unwrap();
///
///     // Random exponent
///     let mut rng = rand::thread_rng();
///     let randomizer_exp = rng.gen_bigint(128).abs();
///     let randomizer_int = base.modpow(&randomizer_exp, &modulus);
///
///     // Add everything to the transcript-- note that order doesn't matter!
///     transcript.add_serial("modulus", &modulus);
///     transcript.add_serial("base", &base);
///     transcript.add_serial("u", &randomizer_int);
///     transcript.add("target", target);
///
///     // Generate challenge
///     let mut challenge_buffer: [u8; 16] = [0u8; 16];
///     transcript.get_challenge("c_challenge", &mut challenge_buffer)?;
///     let challenge_int = BigInt::from_bytes_le(Sign::Plus, &challenge_buffer);
///
///     // Final proof value
///     let z = (challenge_int * log) + randomizer_int.clone();
/// #   Ok(())
/// # }
pub struct Decree {
    inputs: Vec<InputLabel>,
    challenges: Vec<ChallengeLabel>,
    values: HashMap<InputLabel, FSInput>,
    transcript: Transcript,
    committed: bool
}

// Checks that all elements in a Vector of status 
fn vector_is_distinct<T>(elts: &[T]) -> bool
where
    T: std::cmp::Eq,
    T: std::hash::Hash
{
    let mut uniq = std::collections::HashSet::new();
    elts.iter().all(move |x| uniq.insert(x))
}


impl Decree {
    /// Creates a new `Decree` struct. This will fail if one or both of the `input` or `challenge`
    /// slices is empty, or if an item is repeated in the `input` slice.
    ///
    /// # Examples
    /// A basic way to set up a Fiat-Shamir transcript with two inputs and a single challenge.
    /// ```no_run
    /// # use decree::decree::Decree;
    /// # use decree::decree::{InputLabel, ChallengeLabel};
    /// # use decree::error::{Error, DecreeErrType, DecreeResult};
    /// # fn main() -> DecreeResult<()> {
    /// let inputs: [InputLabel; 2] = ["input1", "input2"];
    /// let challenges: [ChallengeLabel; 1] = ["challenge1"];
    /// let mut decree = Decree::new("testname", &inputs, &challenges)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Panics
    /// If `inputs` or `challenges` is empty
    ///
    /// If `inputs` contains repeated entries
    ///
    /// # Tests
    ///
    /// Test the "happy path"
    /// ```
    /// # use decree::decree::Decree;
    /// # use decree::decree::{InputLabel, ChallengeLabel};
    /// # use decree::error::{Error, DecreeErrType, DecreeResult};
    /// # fn main() -> DecreeResult<()> {
    /// let inputs: [InputLabel; 2] = ["input1", "input2"];
    /// let challenges: [ChallengeLabel; 2] = ["challenge1", "challenge2"];
    /// let mut decree = Decree::new("testname", &inputs, &challenges)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Test empty label set.
    /// ```should_panic
    /// # use decree::decree::Decree;
    /// # use decree::decree::{InputLabel, ChallengeLabel};
    /// # use decree::error::{Error, DecreeErrType, DecreeResult};
    /// # fn main() -> DecreeResult<()> {
    /// let inputs: [InputLabel; 0] = [];
    /// let challenges: [ChallengeLabel; 2] = ["challenge1", "challenge2"];
    /// let mut decree = Decree::new("testname", &inputs, &challenges)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Test empty challenge set.
    /// ```should_panic
    /// # use decree::decree::Decree;
    /// # use decree::decree::{InputLabel, ChallengeLabel};
    /// # use decree::error::{Error, DecreeErrType, DecreeResult};
    /// # fn main() -> DecreeResult<()> {
    /// let inputs: [InputLabel; 2] = ["input1", "input2"];
    /// let challenges: [ChallengeLabel; 0] = [];
    /// let mut decree = Decree::new("testname", &inputs, &challenges)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Test repeated labels
    /// ```should_panic
    /// # use decree::decree::Decree;
    /// # use decree::decree::{InputLabel, ChallengeLabel};
    /// # use decree::error::{Error, DecreeErrType, DecreeResult};
    /// # fn main() -> DecreeResult<()> {
    /// let inputs: [InputLabel; 2] = ["repeated_input", "repeated_input"];
    /// let challenges: [ChallengeLabel; 2] = ["challenge1", "challenge2"];
    /// let mut decree = Decree::new("testname", &inputs, &challenges)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(
        name: &'static str,
        inputs: &[InputLabel],
        challenges: &[ChallengeLabel]) -> DecreeResult<Decree> {

        // Make sure we have at least one input and one output
        if inputs.is_empty() {
            return Err(Error::new_init_fail("Must specify at least one input"));
        }
        if challenges.is_empty() {
            return Err(Error::new_init_fail("Must specify at least one challenge"));
        }


        // Make sure our inputs are unique (should challenges be forced to be unique?)
        let mut input_labels = inputs.to_vec();
        if !vector_is_distinct(&input_labels) {
            return Err(Error::new_init_fail("Inputs must be distinct"));
        }

        // We need  to sort the input labels to ensure that we have a consistent transcript.
        input_labels.sort();

        // Initialize the Merlin trascript
        let transcript = Transcript::new(name.as_bytes());

        Ok(Decree{
            inputs: input_labels,
            challenges: challenges.to_vec(),
            values: HashMap::new(),
            transcript,
            committed: false
        })
    }


    /// The `extend` method is used to move from one phase of a protocol to the next while
    /// maintaining Fiat-Shamir state. Calling `extend` should leave a `Decree` struct ready to
    /// accept new inputs and generate new challenges, but without resetting the Merlin transcript.
    ///
    /// If you're used to working with Merlin transcripts directly, you can think of this as a step
    /// that fits in between generating your latest challenge and adding your next input.
    ///
    /// Aside from not needing a `name` input as in the `new` method, the inputs must meet the same
    /// requirements as the `new` method.
    ///
    /// # Tests
    /// 
    /// Test the "happy path"
    /// 
    /// ```
    /// # use decree::decree::Decree;
    /// # use decree::decree::{InputLabel, ChallengeLabel};
    /// # use decree::error::{Error, DecreeErrType, DecreeResult};
    /// # fn main() -> DecreeResult<()> {
    /// # let mut challenge_out: [u8; 32] = [0u8; 32];
    /// let inputs: [InputLabel; 2] = ["input1", "input2"];
    /// let challenges: [ChallengeLabel; 2] = ["challenge1", "challenge2"];
    /// let mut my_decree = Decree::new("testname", &inputs, &challenges)?;
    /// my_decree.add_serial("input1", "input_data_1")?;
    /// my_decree.add_serial("input2", "input_data_2")?;
    /// my_decree.get_challenge("challenge1", &mut challenge_out)?;
    /// my_decree.get_challenge("challenge2", &mut challenge_out)?;
    /// my_decree.extend(&inputs, &challenges)?;
    /// my_decree.add_serial("input1", "input_data_3")?;
    /// my_decree.add_serial("input2", "input_data_4")?;
    /// my_decree.get_challenge("challenge1", &mut challenge_out)?;
    /// my_decree.get_challenge("challenge2", &mut challenge_out)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn extend(
            &mut self,
            inputs: &[InputLabel],
            challenges: &[ChallengeLabel]) -> DecreeResult<()> {
        // If we have pending challenges, or aren't in a committed state,
        // bail.
        if !self.challenges.is_empty() || !self.committed {
            return Err(Error::new_extend_fail("Cannot extend Decree until all challenges generated"));
        }
        // Make sure we have at least one input and one output
        if inputs.is_empty() {
            return Err(Error::new_extend_fail("Must specify at least one input"));
        }
        if challenges.is_empty() {
            return Err(Error::new_extend_fail("Must specify at least one challenge"));
        }

        // Make sure our inputs are unique (should challenges be forced to be unique?)
        let mut input_labels = inputs.to_vec();
        if !vector_is_distinct(&input_labels) {
            return Err(Error::new_init_fail("Inputs must be distinct"));
        }

        // We need  to sort the input labels to ensure that we have a
        // consistent transcript.
        input_labels.sort();

        // Set up all the new values, leaving the transcript in place
        self.inputs = input_labels;
        self.challenges = challenges.to_vec();
        self.values = HashMap::new();
        self.committed = false;

        Ok(())
    }


    fn can_commit(&self) -> bool {
        // If we already committed the current values, don't do it again
        if self.committed {
            return false;
        }

        // Bail if any specified input lacks an associated value
        for label in self.inputs.iter() {
            if !self.values.contains_key(label) {
                return false;
            }
        }

        // Otherwise, we have all our inputs and we can commit
        true
    }


    // The `commit` method actually writes the Fiat-Shamir values into the transcript. It should
    // only be called when every element of the `inputs` vector has a matching entry in the`values`
    // hash map.
    fn commit(&mut self) -> DecreeResult<()> {
        // We iterate over the input label vector because the HashMap
        // item iterator does not provide the elements in any guaranteed
        // order.
        for input_label in self.inputs.iter() {
            let value = match self.values.get(input_label) {
                Some(a) => a,
                None => { return Err(Error::new_general("Error in label processing")); }
            };
            self.transcript.append_message(input_label.as_bytes(), value.as_slice());
        }

        // Set the committed flag
        self.committed = true;

        Ok(())
    }

    fn add_input(
            &mut self,
            label: InputLabel,
            input: FSInput) -> DecreeResult<()> {
        // If we're already committed, we can't add new values
        if self.committed {
            return Err(Error::new_general("Cannot add values after commitment"));
        }

        // Invalid inputs should result in an error
        if !self.inputs.contains(&label) {
            return Err(Error::new_invalid_label("Invalid label"));
        }

        // Re-definition of an input should result in an error
        if self.values.contains_key(label) {
            return Err(Error::new_invalid_label("Label already used"));
        }

        // Add the input to the map
        self.values.insert(
            label,
            input.to_vec()
        );

        // If this is the last input, go ahead and commit the values
        if self.can_commit() {
            self.commit()?;
        }
        Ok(())
    }

    /// The `add_serial` method associates the BCS serialization of a value with the given input
    /// label. This should be used when a Fiat-Shamir input supports the `Serialize` trait, but
    // not the `Inscribe` trait.
    ///
    /// # Panics
    ///
    /// If `label` is not a valid label specified in the most recent `new` or `extend` call.
    ///
    /// If `label` has already been used in a call to `add_serial`, or `add`
    ///
    /// If all inputs already have associated inputs.
    ///
    /// If `label` is the last value to be processed, and an error occurs during commitment.
    ///
    /// # Tests
    /// 
    /// Test the "happy path"
    /// 
    /// ```
    /// # use decree::decree::Decree;
    /// # use decree::decree::{InputLabel, ChallengeLabel};
    /// # use decree::error::{Error, DecreeErrType, DecreeResult};
    /// # use serde::Serialize;
    /// #[derive(Serialize)]
    /// pub struct Point {
    ///     x: i32,
    ///     y: i32,
    /// }
    /// # fn main() -> DecreeResult<()> {
    /// let input_data = "input_data_1";
    /// let inputs: [InputLabel; 2] = ["input1", "input2"];
    /// let challenges: [ChallengeLabel; 2] = ["challenge1", "challenge2"];
    /// let mut my_decree = Decree::new("testname", &inputs, &challenges)?;
    /// my_decree.add_serial("input1", Point{ x: 1i32, y: 2i32 })?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_serial<T: Serialize>(
            &mut self,
            label: InputLabel,
            input: T) -> DecreeResult<()> {
        let bytevec = match to_bytes::<T>(&input) {
            Ok(a) => a,
            Err(_) => { return Err(Error::new_general("Could not serialize")); }
        };
        self.add_input(label, bytevec)
    }


    /// The `add` method associates the inscription of an object with the given input
    /// label. This should always be used when a Fiat-Shamir input supports the `Inscribe`
    /// trait.
    ///
    /// # Panics
    ///
    /// If `label` is not a valid label specified in the most recent `new` or `extend` call.
    ///
    /// If `label` has already been used in a call to `add_serial` or `add`
    ///
    /// If all inputs already have associated inputs.
    ///
    /// If `label` is the last value to be processed, and an error occurs during commitment.
    ///
    /// # Tests
    /// 
    /// Test the "happy path"
    /// 
    /// ```
    /// # use decree::decree::{Decree, InputLabel, ChallengeLabel};
    /// # use decree::error::{Error, DecreeErrType, DecreeResult};
    /// # use decree::Inscribe;
    /// # use decree::inscribe::{INSCRIBE_LENGTH, InscribeBuffer};
    /// #[derive(Inscribe)]
    /// pub struct Point {
    ///     #[inscribe(serialize)]
    ///     x: i32,
    ///     #[inscribe(serialize)]
    ///     y: i32,
    /// }
    /// # fn main() -> DecreeResult<()> {
    /// let input_data = "input_data_1";
    /// let inputs: [InputLabel; 2] = ["input1", "input2"];
    /// let challenges: [ChallengeLabel; 2] = ["challenge1", "challenge2"];
    /// let mut my_decree = Decree::new("testname", &inputs, &challenges)?;
    /// my_decree.add("input1", Point{ x: 1i32, y: 2i32 })?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn add<T: Inscribe>(
            &mut self,
            label: InputLabel,
            input: T) -> DecreeResult<()> {
        //let mut buf: InscribeBuffer = [0u8; INSCRIBE_LENGTH];
        //input.get_inscription(&mut buf);
        //let inscription_vec = buf.to_vec();
        let inscription = input.get_inscription()?;
        self.add_input(label, inscription)
    }


    /// The `get_challenge` method extracts a challenge value from the underlying Merlin
    /// transcript. The `challenge` argument specifies which challenge to generate. As part of the
    /// Fiat-Shamir enforcement system, the challenges _must_ be generated with labels given in
    /// the same order they were provided in the most recent call to `new` or `extend`.
    ///
    /// Challenges may not be generated PRIOR to all inputs being provided. This is to prevent
    /// implementations from accidentally leaving out security-critical values.
    /// 
    /// # Panics
    /// If the challenge label `challenge` is not specified during that last call to `new` or
    /// `extend`.
    ///
    /// If the challenge label `challenge` does not match the next expected challenge
    ///
    /// If no challenges remain to be generated
    ///
    /// If no challenges can be generated because of incomplete inputs
    /// 
    /// # Examples
    ///
    /// The following code should succeed
    /// ```
    /// # use decree::decree::{Decree, InputLabel, ChallengeLabel};
    /// # use decree::error::{Error, DecreeErrType, DecreeResult};
    /// # use decree::Inscribe;
    /// # use decree::inscribe::{INSCRIBE_LENGTH, InscribeBuffer};
    /// #[derive(Inscribe)]
    /// pub struct Point {
    ///     #[inscribe(serialize)]
    ///     x: i32,
    ///     #[inscribe(serialize)]
    ///     y: i32,
    /// }
    /// # fn main() -> DecreeResult<()> {
    /// let input_data = "input_data_1";
    /// let inputs: [InputLabel; 2] = ["input1", "input2"];
    /// let challenges: [ChallengeLabel; 2] = ["challenge1", "challenge2"];
    /// let mut my_decree = Decree::new("testname", &inputs, &challenges)?;
    /// my_decree.add("input1", Point{ x: 1i32, y: 2i32 })?;
    /// let mut challenge_out: [u8; 64] = [0u8; 64];
    /// my_decree.get_challenge("challenge1", &mut challenge_out);
    /// my_decree.get_challenge("challenge2", &mut challenge_out);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Tests
    ///
    /// The following code will not work, because the challenges are requested out of order
    ///
    /// ```should_panic
    /// # use decree::decree::{Decree, InputLabel, ChallengeLabel};
    /// # use decree::error::{Error, DecreeErrType, DecreeResult};
    /// # use decree::Inscribe;
    /// # use decree::inscribe::{INSCRIBE_LENGTH, InscribeBuffer};
    /// #[derive(Inscribe)]
    /// pub struct Point {
    ///     #[inscribe(serialize)]
    ///     x: i32,
    ///     #[inscribe(serialize)]
    ///     y: i32,
    /// }
    /// # fn main() -> DecreeResult<()> {
    /// let input_data = "input_data_1";
    /// let inputs: [InputLabel; 2] = ["input1", "input2"];
    /// let challenges: [ChallengeLabel; 2] = ["challenge1", "challenge2"];
    /// let mut my_decree = Decree::new("testname", &inputs, &challenges)?;
    /// my_decree.add("input1", Point{ x: 1i32, y: 2i32 })?;
    /// my_decree.add("input2", Point{ x: 1i32, y: 2i32 })?;
    /// let mut challenge_out: [u8; 64] = [0u8; 64];
    /// my_decree.get_challenge("challenge2", &mut challenge_out)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// The following code will not work, because the challenge is not specified
    ///
    /// ```should_panic
    /// # use decree::decree::{Decree, InputLabel, ChallengeLabel};
    /// # use decree::error::{Error, DecreeErrType, DecreeResult};
    /// # use decree::Inscribe;
    /// # use decree::inscribe::{INSCRIBE_LENGTH, InscribeBuffer};
    /// #[derive(Inscribe)]
    /// pub struct Point {
    ///     #[inscribe(serialize)]
    ///     x: i32,
    ///     #[inscribe(serialize)]
    ///     y: i32,
    /// }
    /// # fn main() -> DecreeResult<()> {
    /// let input_data = "input_data_1";
    /// let inputs: [InputLabel; 2] = ["input1", "input2"];
    /// let challenges: [ChallengeLabel; 2] = ["challenge1", "challenge2"];
    /// let mut my_decree = Decree::new("testname", &inputs, &challenges)?;
    /// my_decree.add("input1", Point{ x: 1i32, y: 2i32 })?;
    /// my_decree.add("input2", Point{ x: 1i32, y: 2i32 })?;
    /// let mut challenge_out: [u8; 64] = [0u8; 64];
    /// my_decree.get_challenge("invalid_challenge", &mut challenge_out)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// The following code will not work, because a challenge is requested AFTER all specified
    //// challenges are generated.
    ///
    /// ```should_panic
    /// # use decree::decree::{Decree, InputLabel, ChallengeLabel};
    /// # use decree::error::{Error, DecreeErrType, DecreeResult};
    /// # use decree::Inscribe;
    /// # use decree::inscribe::{INSCRIBE_LENGTH, InscribeBuffer};
    /// #[derive(Inscribe)]
    /// pub struct Point {
    ///     #[inscribe(serialize)]
    ///     x: i32,
    ///     #[inscribe(serialize)]
    ///     y: i32,
    /// }
    /// # fn main() -> DecreeResult<()> {
    /// let input_data = "input_data_1";
    /// let inputs: [InputLabel; 2] = ["input1", "input2"];
    /// let challenges: [ChallengeLabel; 2] = ["challenge1", "challenge2"];
    /// let mut my_decree = Decree::new("testname", &inputs, &challenges)?;
    /// my_decree.add("input1", Point{ x: 1i32, y: 2i32 })?;
    /// my_decree.add("input2", Point{ x: 1i32, y: 2i32 })?;
    /// let mut challenge_out: [u8; 64] = [0u8; 64];
    /// my_decree.get_challenge("challenge1", &mut challenge_out)?;
    /// my_decree.get_challenge("challenge2", &mut challenge_out)?;
    /// my_decree.get_challenge("challenge_extra", &mut challenge_out)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// The following code will not work, because a challenge is requested when specified inputs
    //// are missing.
    ///
    /// ```should_panic
    /// # use decree::decree::{Decree, InputLabel, ChallengeLabel};
    /// # use decree::error::{Error, DecreeErrType, DecreeResult};
    /// # use decree::Inscribe;
    /// # use decree::inscribe::{INSCRIBE_LENGTH, InscribeBuffer};
    /// #[derive(Inscribe)]
    /// pub struct Point {
    ///     #[inscribe(serialize)]
    ///     x: i32,
    ///     #[inscribe(serialize)]
    ///     y: i32,
    /// }
    /// # fn main() -> DecreeResult<()> {
    /// let input_data = "input_data_1";
    /// let inputs: [InputLabel; 2] = ["input1", "input2"];
    /// let challenges: [ChallengeLabel; 2] = ["challenge1", "challenge2"];
    /// let mut my_decree = Decree::new("testname", &inputs, &challenges)?;
    /// my_decree.add("input1", Point{ x: 1i32, y: 2i32 })?;
    /// let mut challenge_out: [u8; 64] = [0u8; 64];
    /// my_decree.get_challenge("challenge1", &mut challenge_out)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_challenge(
            &mut self,
            challenge: ChallengeLabel,
            dest: &mut [u8]
            ) -> DecreeResult<()> {
        if !self.committed {
            return Err(Error::new_general("Missing transcript parameters"));
        }
        if self.challenges.is_empty() {
            return Err(Error::new_invalid_challenge("No remaining challenges"));
        }
        if !self.challenges.contains(&challenge) {
            return Err(Error::new_invalid_challenge("Requested challenge not in spec"));
        }
        if self.challenges[0] != challenge {
            return Err(Error::new_invalid_challenge("Challenge order incorrect"));
        }

        self.transcript.challenge_bytes(challenge.as_bytes(), dest);

        self.challenges.remove(0);

        Ok(())
    }
}