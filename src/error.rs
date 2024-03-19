use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DecreeErrType {
    InitFail,
    InvalidLabel,
    InvalidChallenge,
    ExtendFail,
    General,
}

#[derive(Debug)]
pub struct Error {
    err_type: DecreeErrType,
    err_string: &'static str,
}

impl Error {
    pub fn get_type(&self) -> DecreeErrType {
        self.err_type
    }

    pub fn get_str(&self) -> &'static str {
        self.err_string
    }

    /// ```
    ///     use decree::error::{DecreeErrType, Error};
    ///     let l_err = Error::new(DecreeErrType::InitFail, "Duplicate labels");
    ///     println!("{}", l_err);
    /// ```
    pub fn new(e_type: DecreeErrType, msg: &'static str) -> Error {
        Error {
            err_type : e_type,
            err_string : msg,
        }
    }

    /// ```
    ///     use decree::error::{DecreeErrType, Error};
    ///     let l_err = Error::new_invalid_label("Label reused");
    ///     assert_eq!(l_err.get_type(), DecreeErrType::InvalidLabel);
    ///     println!("{}", l_err);
    /// ```
    pub fn new_invalid_label(msg: &'static str) -> Error {
        Self::new(DecreeErrType::InvalidLabel, msg)
    }

    /// ```
    ///     use decree::error::{DecreeErrType, Error};
    ///     let l_err = Error::new_invalid_challenge("Out of order challenge");
    ///     assert_eq!(l_err.get_type(), DecreeErrType::InvalidChallenge);
    ///     println!("{}", l_err);
    /// ```
    pub fn new_invalid_challenge(msg: &'static str) -> Error {
        Self::new(DecreeErrType::InvalidChallenge, msg)
    }

    /// ```
    ///     use decree::error::{DecreeErrType, Error};
    ///     let l_err = Error::new_init_fail("Failed initialization");
    ///     assert_eq!(l_err.get_type(), DecreeErrType::InitFail);
    ///     println!("{}", l_err);
    /// ```
    pub fn new_init_fail(msg: &'static str) -> Error {
        Self::new(DecreeErrType::InitFail, msg)
    }

    /// ```
    ///     use decree::error::{DecreeErrType, Error};
    ///     let l_err = Error::new_extend_fail("Failed extension");
    ///     assert_eq!(l_err.get_type(), DecreeErrType::ExtendFail);
    ///     println!("{}", l_err);
    /// ```
    pub fn new_extend_fail(msg: &'static str) -> Error {
        Self::new(DecreeErrType::ExtendFail, msg)
    }

    /// ```
    ///     use decree::error::{DecreeErrType, Error};
    ///     let l_err = Error::new_general("Failed serialization");
    ///     assert_eq!(l_err.get_type(), DecreeErrType::General);
    ///     println!("{}", l_err);
    /// ```
    pub fn new_general(msg: &'static str) -> Error {
        Self::new(DecreeErrType::General, msg)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.err_type {
            DecreeErrType::InitFail => {write!(f, "Initialization failure")?; },
            DecreeErrType::InvalidLabel => {write!(f, "Invalid label")?; },
            DecreeErrType::InvalidChallenge => {write!(f, "Invalid challenge")?; },
            DecreeErrType::ExtendFail => {write!(f, "Extend failure")?; },
            DecreeErrType::General => {write!(f, "General failure")?; },
        }
        write!(f, ": {}", self.get_str())
    }
}

pub type DecreeResult<T> = Result<T, Error>;