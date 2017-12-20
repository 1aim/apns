#[macro_use]
extern crate error_chain;
extern crate futures;
extern crate httpbis;
extern crate openssl;
extern crate tls_api;
extern crate tls_api_openssl;

use futures::Future;
use httpbis::Client;

use std::fs::File;
use std::env;

mod auth;
mod error;

use auth::ApnsConnector;
use error::Result;

const DEV_SERVER: &str = "api.development.push.apple.com";

pub struct ApnsClient {
	client: Client,
}

impl ApnsClient {
	pub fn new() -> Result<Self> {
		// Make sure all neccesary envirovent variables are pointing at files that are present
  // this is neccesary to use the ApnsConnector wrapper, since it cannot carry any
  // parameters with it.
		let _ = File::open(env::var("APNS_CERT_FILE")?)?;
		let _ = File::open(env::var("APNS_PRIVATE_KEY_FILE")?)?;
		let _ = File::open(env::var("APNS_CA_FILE")?)?;

		let client = Client::new_tls::<ApnsConnector>(DEV_SERVER, 443, Default::default())?;

		Ok(ApnsClient { client })
	}

	pub fn test(&self) {
		let resp = self.client
			.start_get("/", DEV_SERVER)
			.collect()
			.wait()
			.expect("execute request");
		print!("{}", resp.dump());
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn it_works() {
		let client = ApnsClient::new().unwrap();

		client.test();
	}
}
