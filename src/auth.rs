// use std::path::{Path, PathBuf};
// use std::fs::File;
use std::{env, fmt, io};

use openssl::x509::X509_FILETYPE_PEM;

use tls_api;
use tls_api_openssl::{TlsConnector, TlsConnectorBuilder};

/// Wrapper types for doing apns authentification
pub struct ApnsConnectorBuilder(pub TlsConnectorBuilder);
pub struct ApnsConnector(pub TlsConnector);

impl tls_api::TlsConnectorBuilder for ApnsConnectorBuilder {
	type Connector = ApnsConnector;
	type Underlying = TlsConnectorBuilder;

	fn underlying_mut(&mut self) -> &mut TlsConnectorBuilder {
		&mut self.0
	}

	fn supports_alpn() -> bool {
		false
	}

	fn set_alpn_protocols(&mut self, protos: &[&[u8]]) -> tls_api::Result<()> {
		self.0.set_alpn_protocols(protos)
	}

	fn add_root_certificate(&mut self, cert: tls_api::Certificate) -> tls_api::Result<&mut Self> {
		self.0.add_root_certificate(cert)?;
		Ok(self)
	}

	fn build(self) -> tls_api::Result<ApnsConnector> {
		let ApnsConnectorBuilder(mut inner) = self;
		{
			let underlying = inner.underlying_mut();
			// FIXME: assure the unwraps are sound before constructing a client

			let cert = env::var("APNS_CERT_FILE").unwrap();
			let key = env::var("APNS_PRIVATE_KEY_FILE").unwrap();
			let ca = env::var("APNS_CA_FILE").unwrap();

			underlying.set_ca_file(&ca).unwrap();
			underlying
				.set_certificate_file(&cert, X509_FILETYPE_PEM)
				.unwrap();
			underlying
				.set_private_key_file(&key, X509_FILETYPE_PEM)
				.unwrap();
		}
		Ok(ApnsConnector(inner.build()?))
	}
}

impl tls_api::TlsConnector for ApnsConnector {
	type Builder = ApnsConnectorBuilder;

	fn builder() -> tls_api::Result<ApnsConnectorBuilder> {
		Ok(ApnsConnectorBuilder(TlsConnector::builder()?))
	}

	fn connect<S>(
		&self,
		domain: &str,
		stream: S,
	) -> Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>>
	where
		S: io::Read + io::Write + fmt::Debug + Send + Sync + 'static,
	{
		self.0.connect(domain, stream)
	}

	fn danger_connect_without_providing_domain_for_certificate_verification_and_server_name_indication<
		S,
	>(
		&self,
		stream: S,
	) -> Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>>
	where
		S: io::Read + io::Write + fmt::Debug + Send + Sync + 'static,
	{
		self.0.danger_connect_without_providing_domain_for_certificate_verification_and_server_name_indication(stream)
	}
}
