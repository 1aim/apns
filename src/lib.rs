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

use httpbis::Client;
use futures::Future;

mod auth;
mod error;

use auth::{ApnsConnector, Auth, AUTH};
use error::Result;

const DEV_SERVER: &str = "api.development.push.apple.com";

pub struct ApnsClient {
	client: Client,
}

impl ApnsClient {
	pub fn new(auth: Auth) -> Result<Self> {
		AUTH.with(|a| *a.borrow_mut() = Some(auth));
		let client = Client::new_tls::<ApnsConnector>(DEV_SERVER, 443, Default::default())?;
		Ok(ApnsClient { client })
	}

	pub fn send(&self, token: &str, body: &json::Value) {
		let resp = self.client
			.start_post(
				&format!("/3/device/{}", token),
				DEV_SERVER,
				body.to_string().into(),
			)
			.collect()
			.wait()
			.expect("execute request");
		println!("{}", resp.dump());
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn it_works() {
		let auth = Auth::new(
			env::var("APNS_CERT_FILE").unwrap(),
			env::var("APNS_PRIVATE_KEY_FILE").unwrap(),
			env::var("APNS_CA_FILE").unwrap(),
		).unwrap();

		let client = ApnsClient::new(auth).unwrap();

		let body = json!({
			"action": "warning",
			"title": "wonk",
			"description": "tjusning"
		});

		let token = "47CA3E85B27221F470E149AAAFF036EAFA52537DE3C76464E518C72C6DCED8C0";

		client.send(token, &body);
	}
}
