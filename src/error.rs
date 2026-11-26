//! Error type shared across RPF.
//!
//! A single flat error type keeps the dependency-free promise (no `anyhow`)
//! while still carrying context. Errors are built with [`Error::new`] and
//! annotated with [`Error::context`] as they bubble up.

use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Error {
    msg: String,
}

impl Error {
    pub fn new(msg: impl Into<String>) -> Self {
        Error { msg: msg.into() }
    }

    /// Prefix the message with additional context, e.g. the file being read.
    pub fn context(self, ctx: impl fmt::Display) -> Self {
        Error {
            msg: format!("{}: {}", ctx, self.msg),
        }
    }

    pub fn message(&self) -> &str {
        &self.msg
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::new(e.to_string())
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(e: std::num::ParseIntError) -> Self {
        Error::new(e.to_string())
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(e: std::str::Utf8Error) -> Self {
        Error::new(e.to_string())
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(e: std::string::FromUtf8Error) -> Self {
        Error::new(e.to_string())
    }
}

/// Convenience macro that builds an [`Error`] with `format!` syntax.
#[macro_export]
macro_rules! bail {
    ($($arg:tt)*) => {
        return Err($crate::Error::new(format!($($arg)*)))
    };
}

/// Fail with a formatted message unless the condition holds.
#[macro_export]
macro_rules! ensure {
    ($cond:expr, $($arg:tt)*) => {
        if !$cond {
            $crate::bail!($($arg)*);
        }
    };
}
