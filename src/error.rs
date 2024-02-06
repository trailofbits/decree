use std::fmt;

#[derive(Debug)]
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
    pub fn new(e_type: DecreeErrType, msg: &'static str) -> Error {
        Error {
            err_type : e_type,
            err_string : msg,
        }
    }

    pub fn new_invalid_label(msg: &'static str) -> Error {
        Self::new(DecreeErrType::InvalidLabel, msg)
    }

    pub fn new_invalid_challenge(msg: &'static str) -> Error {
        Self::new(DecreeErrType::InvalidChallenge, msg)
    }

    pub fn new_init_fail(msg: &'static str) -> Error {
        Self::new(DecreeErrType::InitFail, msg)
    }

    pub fn new_extend_fail(msg: &'static str) -> Error {
        Self::new(DecreeErrType::ExtendFail, msg)
    }

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
        write!(f, ": {}", self.err_string)
    }
}

pub type DecreeResult<T> = Result<T, Error>;