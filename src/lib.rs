#![cfg_attr(not(doctest), doc = include_str!("../README.md"))]
pub mod inscribe;
pub use inscribe_derive::Inscribe;
pub use inscribe::Inscribe;
pub mod decree;
pub use decree::Decree;
pub mod error;
