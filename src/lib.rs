#[macro_use]
extern crate error_chain;
extern crate futures;
extern crate httpbis;
extern crate openssl;
#[allow(unused)]
#[macro_use]
extern crate serde_json as json;
extern crate tls_api;
extern crate tls_api_openssl;

use std::env;
use futures::Future;

mod auth;
use auth::{ApnsConnector, AUTH};
pub use auth::Auth;

mod error;
use error::Result;
pub use error::Error;

mod request;
pub use request::{DeviceToken, Priority, Request};

const PROD_SERVER: &str = "api.push.apple.com";
const DEV_SERVER: &str = "api.development.push.apple.com";

pub type ApnsFuture = Box<futures::Future<Item = (), Error = Error>>;

pub struct Client {
	client: httpbis::Client,
	server: &'static str,
}

impl Client {
	pub fn new(auth: &Auth) -> Result<Self> {
		AUTH.with(|a| *a.borrow_mut() = Some(auth.clone()));
		let client =
			httpbis::Client::new_tls::<ApnsConnector>(PROD_SERVER, 443, Default::default())?;
		Ok(Client {
			client,
			server: PROD_SERVER,
		})
	}

	pub fn sandbox(auth: &Auth) -> Result<Self> {
		AUTH.with(|a| *a.borrow_mut() = Some(auth.clone()));
		let client =
			httpbis::Client::new_tls::<ApnsConnector>(DEV_SERVER, 443, Default::default())?;
		Ok(Client {
			client,
			server: DEV_SERVER,
		})
	}

	pub fn send(&self, request: Request) -> ApnsFuture {
		let Request {
			recipient,
			payload,
			priority,
			expiration,
		} = request;

		Box::new(
			self.client
				.start_post(
					&format!("/3/device/{:X}", recipient),
					self.server,
					payload.to_string().into(),
				)
				.collect()
				.map(|_| ())
				.map_err(Into::into),
		)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::str::FromStr;

	#[test]
	fn it_works() {
		let auth = Auth::new(
			env::var("APNS_CERT_FILE").unwrap(),
			env::var("APNS_PRIVATE_KEY_FILE").unwrap(),
			env::var("APNS_CA_FILE").unwrap(),
		).unwrap();

		let token = DeviceToken::from_str(&env::var("APNS_DEVICE_TOKEN").unwrap()).unwrap();
		let payload = json!({
			"action": "warning",
			"title": "wonk",
			"description": "tjusning"
		});

		let request = Request::new(token, payload, None, None);
		let client = Client::sandbox(&auth).unwrap();

		client.send(request).wait().unwrap();
	}
}
