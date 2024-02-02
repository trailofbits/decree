use std::collections::HashMap;
use merlin::Transcript;
use bcs::to_bytes;
use bcs;
use serde::Serialize;
use crate::{Inscribe};
use crate::inscribe::{INSCRIBE_LENGTH, InscribeBuffer};

pub type InputLabel = &'static str;
pub type ChallengeLabel = &'static str;
pub type ErrMsg = &'static str;
pub type DecreeResult = Result<(), ErrMsg>;
pub type FSInput = Vec<u8>;

// The Decree struct itself only tracks a few things:
//  - Expected inputs
//  - Expected challenges
//  - Received inputs
//  - The Merlin transcript
//  - Commitment status
pub struct Decree {
    inputs: Vec<InputLabel>,
    challenges: Vec<ChallengeLabel>,
    values: HashMap<InputLabel, FSInput>,
    transcript: Transcript,
    committed: bool
}

impl Decree {
    pub fn new(
        name: &'static str,
        inputs: &[InputLabel],
        challenges: &[ChallengeLabel]) -> Result<Decree, ErrMsg> {

        // Make sure we have at least one input and one output
        if inputs.len() == 0 {
            return Err("Must specify at least one input");
        }
        if challenges.len() == 0 {
            return Err("Must specify at least one challenge");
        }

        // We need  to sort the input labels to ensure that we have a
        // consistent transcript.
        let mut input_labels = inputs.to_vec();
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


    // The `extend` method is used to move from one phase of a protocol to the next while
    // maintaining Fiat-Shamir state. Calling `extend` should leave a `Decree` struct ready to
    // accept new inputs and generate new challenges, but without resetting the Merlin transcript.

    // If you're used to working with Merlin transcripts directly, you can think of this as a step
    // that fits in between generating your latest challenge and adding your next input.
    pub fn extend(
            &mut self,
            inputs: &[InputLabel],
            challenges: &[ChallengeLabel]) -> DecreeResult {
        // If we have pending challenges, or aren't in a committed state,
        // bail.
        if self.challenges.len() != 0 || !self.committed {
            return Err("Cannot extend Decree until all challenges generated");
        }
        // Make sure we have at least one input and one output
        if inputs.len() == 0 {
            return Err("Must specify at least one input");
        }
        if challenges.len() == 0 {
            return Err("Must specify at least one challenge");
        }

        // We need  to sort the input labels to ensure that we have a
        // consistent transcript.
        let mut input_labels = inputs.to_vec();
        input_labels.sort();

        // Set up all the new values, leaving the transcript in place
        self.inputs = input_labels;
        self.challenges = challenges.to_vec();
        self.values = HashMap::new();
        self.committed = false;

        Ok(())
    }


    fn check_ready_commit(&self) -> bool {
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
    fn commit(&mut self) -> Option<()>{
        // We iterate over the input label vector because the HashMap
        // item iterator does not provide the elements in any guaranteed
        // order.
        for input_label in self.inputs.iter() {
            let value = match self.values.get(input_label) {
                Some(a) => a,
                None => { return None; }
            };
            self.transcript.append_message(input_label.as_bytes(), value.as_slice());
        }

        // Set the committed flag
        self.committed = true;

        Some(())
    }


    fn add_input(
            &mut self,
            label: InputLabel,
            input: FSInput) -> DecreeResult {
        // If we're already committed, we can't add new values
        if self.committed {
            return Err("Cannot add values after commitment")
        }

        // Invalid inputs should result in an error
        if !self.inputs.contains(&label) {
            return Err("Invalid label");
        }

        // Re-definition of an input should result in an error
        if self.values.contains_key(label) {
            return Err("Label already used");
        }

        // Add the input to the map
        self.values.insert(
            label,
            input.to_vec()
        );

        // If this is the last input, go ahead and commit the values
        if self.check_ready_commit() {
            match self.commit() {
                Some(_) => {},
                None => { return Err("Commit failure"); }
            }
        }
        Ok(())
    }


    pub fn add_bytes(
            &mut self,
            label: InputLabel,
            input: &[u8]) -> DecreeResult {
        let input_vec = input.to_vec();
        self.add_input(label, input_vec)
    }


    pub fn add_serial<T: Serialize>(
            &mut self,
            label: InputLabel,
            input: T) -> DecreeResult {
        let bytevec = match to_bytes::<T>(&input) {
            Ok(a) => a,
            Err(_) => { return Err("Could not serialize"); }
        };
        self.add_input(label, bytevec)
    }


    pub fn add_inscribe<T: Inscribe>(
            &mut self,
            label: InputLabel,
            input: T) -> DecreeResult {
        let mut buf: InscribeBuffer = [0u8; INSCRIBE_LENGTH];
        input.get_inscription(&mut buf);
        let inscription_vec = buf.to_vec();
        self.add_input(label, inscription_vec)
    }


    pub fn get_challenge(
            &mut self,
            challenge: ChallengeLabel,
            dest: &mut [u8]
            ) -> DecreeResult {
        if !self.committed {
            return Err("Missing transcript parameters");
        }
        if self.challenges.is_empty() {
            return Err("No remaining challenges");
        }
        if !self.challenges.contains(&challenge) {
            return Err("Requested challenge not in spec");
        }
        if self.challenges[0] != challenge {
            return Err("Challenge order incorrect");
        }

        self.transcript.challenge_bytes(challenge.as_bytes(), dest);

        self.challenges.remove(0);

        Ok(())
    }
}