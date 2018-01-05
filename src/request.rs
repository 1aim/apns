use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::sync::Arc;
use std::str::{self, FromStr};
use std::ascii::AsciiExt;

use json;
use httpbis::solicit::header::HeaderPart;

use error::{Error, ErrorKind, Result};

/// The priority at which the notification should be sent
#[derive(Clone, Debug)]
pub enum Priority {
	/// High priority notification
	High,
	/// Low priority notification
	Low,
}

pub struct Expiration(SystemTime);

impl Into<HeaderPart> for Priority {
	fn into(self) -> HeaderPart {
		match self {
			Priority::High => "10",
			Priority::Low => "5",
		}.into()
	}
}

impl Into<HeaderPart> for Expiration {
	fn into(self) -> HeaderPart {
		format!(
			"{}",
			self.0
				.duration_since(UNIX_EPOCH)
				.unwrap_or(Duration::new(0, 0))
				.as_secs()
		).into()
	}
}

impl Into<Expiration> for SystemTime {
	fn into(self) -> Expiration {
		Expiration(self)
	}
}

/// A device token identifying the target of a notification
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

/// A request to the apns server, corresponding to a notification
pub struct Request {
	pub(crate) recipient: DeviceToken,
	pub(crate) payload: Arc<json::Value>,
	pub(crate) priority: Option<Priority>,
	pub(crate) expiration: Option<Expiration>,
}

impl Request {
	/// Construct a new notification request to be sent to the server
	pub fn new<P: Into<Arc<json::Value>>, E: Into<Expiration>>(
		recipient: DeviceToken,
		payload: P,
		priority: Option<Priority>,
		expiration: Option<E>,
	) -> Self {
		Request {
			recipient,
			payload: payload.into(),
			priority,
			expiration: expiration.map(|e| e.into()),
		}
	}
}
