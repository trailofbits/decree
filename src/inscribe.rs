pub const INSCRIBE_LENGTH: usize = 64;
pub type InscribeBuffer = [u8; INSCRIBE_LENGTH];

/// The `Inscribe` trait is a derivable trait for structs that makes it easy to incorporate
/// contextual data into Fiat-Shamir transcripts. There are two main methods that the trait
/// requires:
///
/// `fn get_mark(&self) -> &'static str`
///
/// and
///
/// `fn get_inscription(&self, buf: &mut InscribeBuffer)`
///
/// For derived structs, the `get_inscription` method will do the following:
///     - Initialize a TupleHash with the results of `get_mark`
///     - For each member of the struct, do one of three things:
///         + Call the `get_inscription` routine and add the results to the TupleHash
///         + Use the `bcs` library to serialize the member and add the results to the TupleHash
///         + Skip the item entirely
///
/// By default, struct members are assumed to implement the `Inscribe` trait, but this can be
/// overridden using `inscribe` attributes:
///
/// Examples:
///
/// This following code should fail to compile, as the default behavior is to call
/// `get_inscription` on `x` and `y`, even though the `i32` type doesn't implement the `Inscribe`
/// trait.
///
/// ```compile_fail
/// # use decree::Inscribe;
/// # use decree::inscribe::InscribeBuffer;
/// #[derive(Inscribe)]
/// pub struct Point {
///     x: i32,
///     y: i32,
/// }
/// ```
///
/// On the other hand, if we annotate both `x` and `y` with `inscribe(serialize)`, the code will
/// compile just fine, with both values being serialized using the `bcs` library.
///
/// ```
/// # use decree::Inscribe;
/// # use decree::inscribe::InscribeBuffer;
/// #[derive(Inscribe)]
/// pub struct Point {
///     #[inscribe(serialize)]
///     x: i32,
///     #[inscribe(serialize)]
///     y: i32,
/// }
/// ```
///
/// # Tests
///
/// ```
/// # use decree::Inscribe;
/// # use decree::inscribe::InscribeBuffer;
/// #[derive(Inscribe)]
/// pub struct Point {
///     #[inscribe(serialize)]
///     x: i32,
///     #[inscribe(serialize)]
///     y: i32,
/// }
///
/// #[derive(Inscribe)]
/// pub struct Proof {
///     basis: Point,
///     result: Point,
///     #[inscribe(serialize)]
///     challenge: Vec<u8>,
/// }
/// ```
///
pub trait Inscribe {
    fn get_mark(&self) -> &'static str;
    fn get_inscription(&self, buf: &mut InscribeBuffer);
}