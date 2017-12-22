use std::io;
use env;
use httpbis;
use openssl;
use tls_api;

error_chain! {
	errors {}

	foreign_links {
		Io(io::Error);
		Env(env::VarError);
		Http2(httpbis::Error);
		OpenSsl(openssl::error::ErrorStack);
		Tls(tls_api::Error);
	}
}
