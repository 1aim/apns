use std::fmt;
use std::time::SystemTime;
use std::sync::Arc;
use std::str::{self, FromStr};
use std::ascii::AsciiExt;

use json;

use error::{Error, ErrorKind, Result};

#[derive(Clone, Debug)]
pub enum Priority {
	High,
	Low,
}

#[derive(Clone, Debug)]
pub struct DeviceToken([u8; 32]);

impl fmt::UpperHex for DeviceToken {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		for byte in self.0.iter() {
			write!(f, "{:X}", byte)?;
		}
		Ok(())
	}
}

impl FromStr for DeviceToken {
	type Err = Error;

	fn from_str(s: &str) -> Result<Self> {
		let mut bytes = [0u8; 32];

		if !s.is_ascii() || s.len() != 64 {
			return Err(ErrorKind::InvalidToken.into());
		}

		for (b, ch) in bytes.iter_mut().zip(s.as_bytes().chunks(2)) {
			*b = u8::from_str_radix(unsafe { str::from_utf8_unchecked(ch) }, 16)?;
		}

		Ok(DeviceToken(bytes))
	}
}

pub struct Request {
	pub(crate) recipient: DeviceToken,
	pub(crate) payload: Arc<json::Value>,
	pub(crate) priority: Option<Priority>,
	pub(crate) expiration: Option<SystemTime>,
}

impl Request {
	pub fn new(
		recipient: DeviceToken,
		payload: Arc<json::Value>,
		priority: Option<Priority>,
		expiration: Option<SystemTime>,
	) -> Self {
		Request {
			recipient,
			payload,
			priority,
			expiration,
		}
	}
}
