# Decree Fiat-Shamir Library

The Decree library provides a set of tools that help developers prevent and identify [weak
Fiat-Shamir problems](https://eprint.iacr.org/2023/691) in their zero-knowledge (ZK) and
multi-party computation (MPC) software.

## The `Inscribe` trait

The `Inscribe` trait allows developers to include useful contextual information for Fiat-Shamir
transcripts.  In the case of an elliptic curve point, for example, this might include the curve
parameters (or, in the case of curves with well-known parameters, such as `secp256k1` or
`ed25519`, simply the name of the curve). For an integer in a finite field, the field order might
be included.

In more complex systems like Groth16 or Bulletproofs, it's possible that _multiple_ parameters
could be included as contextual information.

The trait is derivable, allowing for recursive inclusion of contextual information: if a struct
member supports `Inscribe`, then it will be included with _its_ contextual information as well.
Struct members that do _not_ support the `Inscribe` trait can be tagged for inclusion using
the `bcs` library, which serializes values in a way that is canonical and deterministic: given the
same data type with the same value, then regardless of the platform or operating system, the
serialized result will be the same.

Structs that use `#[derive(Inscribe)]` can specify `#[inscribe_addl(<function>)]`, where
`function` can return any contextual information not included in the struct, whether explicitly
or implicitly via `Inscribe` members. This is where implementers can include things like domain
parameters, protocol versions (if such information is important), related values, etc.

Member values and contextual information in `#[derive(Inscribe)]` structs are combined using
TupleHash, which is derived from the SHA-3 hash function. This prevents issues with domain
separation and canonicalization.

Structs with the `Inscribe` trait also provide a name or "mark". By default, the mark is just the
name of the name of the struct; developers can override this by defining the `get_mark` method.
Since many cryptographic libraries include distinct structures with the same name (think of
structs named `PublicKey` or `Proof`), it's a good idea to do so.

## `Decree` transcripts

### Overview

A Decree transcript sits atop a [Merlin transcript](https://github.com/zkcrypto/merlin), adding
a protocol specification and enforcement mechanism. At each stage of a protocol, developers
are required to specify the inputs and challenges for each step of a Fiat-Shamir transcript. If a
specified input is provided more than once, an `Error` is returned. If an input that is not
included in the specification is not provided, an `Error` is returned.

If a challenge is requested before all specified inputs have been provided, an `Error` is returned.
If a challenge is requested out of the specified order, an `Error` is returned. If a challenge that
is not not included in the specification is requested, an `Error` is returned.

After challenges have been successfully generated, the Decree transcript can be "continued" by
specifying a new set of inputs and challenges. The underlying Merlin transcript is kept in place,
ensuring that transcript state is carried over to the new stage in the protocol.

Additionally, inputs at each stage are added to the Merlin transcript in a fixed order, regardless
of the order in which they are added to the Decree transcript. If two programs provide the same
inputs and request the same challenges, then the challenges will always match, even if they add
the inputs in different orders.

In other words: a Decree transcript requires developers to specify the contents of their
Fiat-Shamir transcripts in distinct stages, then _holds developers to that spec_, even as it
makes room for implementation flexibility.

Decree transcripts ensure that:

  - Transcript formats are specified at a single point per stage, not across entire functions
  - Critical transcript inputs aren't skipped
  - Transcript inputs are not multiply-specified
  - Changes to the order of inputs don't result in incompatibility problems
  - Challenges are generated in a specified order


### Supported types

Once a `Decree` struct has been initialized or extended, inputs can be added using the `add` and
`add_serial` methods.

The `add` method is meant for inputs that support the `Inscribe` trait, described above. Where
supported, this is the preferred method for adding data to a Decree transcript, as types that
implement `Inscribe` are less likely to have colliding transcript inputs across multiple
parameterizations.

The `add_serial` method can be used for any input that supports the `Serialize` trait. This
method uses the `bcs` (binary canonical serialization) library to serialize the input to a unique,
platform-independent binary representation, which is then used as the direct input to the Merlin
transcript. This ensures that serialized values don't change from platform to platform, as long
as the data structures remain the same.

Because `Serialize` is implemented for `&[u8]`, it is possible to serialize values "by hand" and
feed the resulting slice to the `add_serial` method. It is worth noting, however, that the
`bcs` library is still used to serialize the `&[u8]` input, so the result will not be the same
as directly feeding the slice into the underlying Merlin transcript.

### Example: Schnorr Proof

Consider the following example from the doctests, a Schnorr proof that Alice knows the base-`43`
discrete logarithm of `8675309` modulo a shared modulus of `0x1fffffffffffffff` (2^127 - 1).

```rs
    let inputs: [InputLabel; 4] = ["modulus", "base", "target", "u"];
    let challenges: [ChallengeLabel; 1] = ["c_challenge"];
    let mut transcript = Decree::new("schnorr proof", &inputs, &challenges)?;

    // Proof parameters
    let target = BigInt::from(8675309u32);
    let base = BigInt::from(43u32);
    let log = BigInt::parse_bytes(b"18777797083714995725967614997933308615", 10).unwrap();
    let modulus = &BigInt::from(2u32).pow(127) - BigInt::from(1u32);

    // Random exponent
    let mut rng = rand::thread_rng();
    let randomizer_exp = rng.gen_bigint(256) % (&modulus - BigInt::from(1u32));
    let randomizer = base.modpow(&randomizer_exp, &modulus);

    // Add everything to the transcript-- note that order of addition doesn't matter!
    transcript.add_serial("u", &randomizer);
    transcript.add_serial("target", &target);
    transcript.add_serial("base", &base);
    transcript.add_serial("modulus", &modulus);

    let mut challenge_out: [u8; 32] = [0u8; 32];
    transcript.get_challenge("c_challenge", &mut challenge_out);
```

(Note: this code should not be _used_ for a variety of reasons; it is for illustrative purposes
only.)

We could extend this by adding an `Inscribe` implementation for the `target` and `base` values to
indicate the associated modulus:

```rs
#[derive(Inscribe)]
pub struct BigIntTarget {
   #[inscribe(serialize)]
   target: BigInt,
   #[inscribe(serialize)]
   base: BigInt,
   #[inscribe(serialize)]
   modulus: BigInt,
}

impl BigIntTarget {
   fn get_extra(&self) -> Result<Vec<u8>, Error> {
       Ok("schnorr proof value".as_bytes().to_vec())
   }
}

 [...]

   let inputs: [InputLabel; 3] = ["modulus", "target", "u"];
   let challenges: [ChallengeLabel; 1] = ["c_challenge"];
   let mut transcript = Decree::new("schnorr proof", &inputs, &challenges)?;

   // Proof parameters
   let modulus = &BigInt::from(2u32).pow(127) - BigInt::from(1u32);
   let base = BigInt::from(43u32);
   let target = BigIntTarget{
       target: BigInt::from(8675309u32),
       base: base.clone(),
       modulus: modulus.clone()};
   let log = BigInt::from_str("18777797083714995725967614997933308615").unwrap();

   // Random exponent
   let mut rng = rand::thread_rng();
   let randomizer_exp = rng.gen_bigint(128).abs();
   let randomizer_int = base.modpow(&randomizer_exp, &modulus);

   // Add everything to the transcript-- note that order doesn't matter!
   transcript.add_serial("modulus", &modulus);
   transcript.add_serial("u", &randomizer_int);
   transcript.add("target", target);

   // Generate challenge
   let mut challenge_buffer: [u8; 16] = [0u8; 16];
   transcript.get_challenge("c_challenge", &mut challenge_buffer)?;
   let challenge_int = BigInt::from_bytes_le(Sign::Plus, &challenge_buffer);

   // Final proof value
   let z = (challenge_int * log) + randomizer_int.clone();

[...]

```

(Note: again, this code should not be used for a variety of reasons; it is for illustrative
purposes only.)

In this case, we've "forgotten" to add the `base` input to the transcript, which would normally be
[a major Fiat-Shamir vulnerability](). But we're still okay, because the `target` parameter supports
the `Inscribe` trait, and `base` is included in the transcript calculation.  If somebody tries to
cheat by replacing `base` with a maliciously-crafted value, the verifier will see a different
challenge value than would be generated for a different `base` value.

Also worth noting: this approach includes `modulus` twice. Once explicitly via an `add_serial`
call, and once in the call to the `get_inscription` method of `target` that gets made by `add`.
This is okay; the implicit inclusion in `target` does not preclude inclusion elsewhere.
