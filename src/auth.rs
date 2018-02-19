use std::path::{Path, PathBuf};
use std::fs::File;
use std::{fmt, io, result};

use openssl::x509::X509_FILETYPE_PEM;
use openssl::ssl;
use std::cell::RefCell;

use tls_api;
use tls_api_openssl::{TlsConnector, TlsConnectorBuilder};

use error::Result;

// Since httpbis does not support runtime tls configuration,
// we use a thread local to pass in the configuration to the builder.
thread_local! {
	pub static AUTH: RefCell<Option<Auth>> = RefCell::new(None);
}

/// Authorization information for the tls connection to the apns server
#[derive(Clone, Debug)]
pub struct Auth {
	cert: PathBuf,
	key: PathBuf,
	ca: PathBuf,
}

impl Auth {
	/// Construct a new `Auth` value given the paths to a certificate, a key and
	/// a certificate authority.
	///
	/// # `cert`
	/// Expects a `.pem` file holding the certificate.
	///
	/// # `key`
	/// Expects a `.key` file, for the connection private key.
	///
	/// # `ca`
	/// Expects a `.pem` file, the certificate authority.
	pub fn new<Cert, Key, Ca>(cert: Cert, key: Key, ca: Ca) -> Result<Self>
	where
		Cert: AsRef<Path>,
		Key: AsRef<Path>,
		Ca: AsRef<Path>,
	{
		let cert = cert.as_ref();
		let key = key.as_ref();
		let ca = ca.as_ref();

		let _ = File::open(cert)?;
		let _ = File::open(key)?;
		let _ = File::open(ca)?;

		Ok(Auth {
			cert: cert.to_path_buf(),
			key: key.to_path_buf(),
			ca: ca.to_path_buf(),
		})
	}

	fn build(&self, b: &mut ssl::SslConnectorBuilder) -> tls_api::Result<()> {
		b.set_ca_file(&self.ca).map_err(tls_api::Error::new)?;
		b.set_certificate_file(&self.cert, X509_FILETYPE_PEM)
			.map_err(tls_api::Error::new)?;;
		b.set_private_key_file(&self.key, X509_FILETYPE_PEM)
			.map_err(tls_api::Error::new)?;;

		Ok(())
	}
}

/// Wrapper types for doing apns authentification
pub struct ApnsConnectorBuilder {
	builder: TlsConnectorBuilder,
	auth: Auth,
}

pub struct ApnsConnector(TlsConnector);

impl tls_api::TlsConnectorBuilder for ApnsConnectorBuilder {
	type Connector = ApnsConnector;
	type Underlying = TlsConnectorBuilder;

	fn underlying_mut(&mut self) -> &mut TlsConnectorBuilder {
		&mut self.builder
	}

	fn supports_alpn() -> bool {
		false
	}

	fn set_alpn_protocols(&mut self, protos: &[&[u8]]) -> tls_api::Result<()> {
		self.builder.set_alpn_protocols(protos)
	}

	fn add_root_certificate(&mut self, cert: tls_api::Certificate) -> tls_api::Result<&mut Self> {
		self.builder.add_root_certificate(cert)?;
		Ok(self)
	}

	fn build(self) -> tls_api::Result<ApnsConnector> {
		let ApnsConnectorBuilder {
			builder: mut inner,
			auth,
		} = self;

		auth.build(inner.underlying_mut())?;

		Ok(ApnsConnector(inner.build()?))
	}
}

impl tls_api::TlsConnector for ApnsConnector {
	type Builder = ApnsConnectorBuilder;

	fn builder() -> tls_api::Result<ApnsConnectorBuilder> {
		let mut auth = None;
		AUTH.with(|a| auth = a.borrow().clone());

		Ok(ApnsConnectorBuilder {
			builder: TlsConnector::builder()?,
			auth: auth.unwrap(),
		})
	}

	fn connect<S>(
		&self,
		domain: &str,
		stream: S,
	) -> result::Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>>
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
	) -> result::Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>>
	where
		S: io::Read + io::Write + fmt::Debug + Send + Sync + 'static,
	{
		self.0.danger_connect_without_providing_domain_for_certificate_verification_and_server_name_indication(stream)
	}
}
